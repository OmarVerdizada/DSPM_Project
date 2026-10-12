"""Optional, hardened OCR text extraction (RapidOCR / ONNX Runtime).

OCR lets the classifiers find sensitive data (PANs, PII, secrets) inside images
and scanned pages. Because it processes UNTRUSTED image bytes and is expensive,
it is deliberately:

  * OPTIONAL - the ``rapidocr-onnxruntime`` extra need not be installed. When it
    is absent, OCR is silently skipped and never breaks a scan (mirrors the
    ML/spaCy optional pattern). Install with ``requirements-ocr.txt``.
  * GATED behind ``DSPM_OCR_ENABLED`` (default off): it costs ~2 s/image on CPU
    and adds a ~150 MB dependency, so it is opt-in per deployment.
  * HARDENED against hostile images - the whole point of this module:
      - a file-size cap and a decompression-bomb PIXEL cap enforced from the
        HEADER (no full decode of a bomb);
      - the image is decoded by Pillow (with its bomb guard) and DOWNSCALED to a
        bounded dimension before OCR, so a huge image cannot exhaust CPU/RAM and
        the untrusted bytes are never handed to opencv's decoders directly;
      - a hard per-image wall-clock budget (a watchdog thread abandons a slow
        inference - ONNX Runtime releases the GIL, so this actually returns);
      - fail-CLOSED: any error, timeout, or cap returns "" - OCR can never hang,
        OOM, or crash a scan.
  * A plain-text entry point feeding the existing classifier pipeline, so SC-1
    masking and every downstream control apply to OCR'd text unchanged.

Config (all env-overridable): DSPM_OCR_ENABLED, DSPM_OCR_MAX_FILE_BYTES,
DSPM_OCR_MAX_PIXELS, DSPM_OCR_MAX_DIMENSION, DSPM_OCR_TIMEOUT_SECONDS,
DSPM_OCR_MIN_CONFIDENCE, DSPM_OCR_MAX_CHARS, DSPM_OCR_INTRA_OP_THREADS.
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path

from scripts.logger import get_logger

logger = get_logger(__name__)

OCR_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _max_file_bytes() -> int:
    return _int_env("DSPM_OCR_MAX_FILE_BYTES", 25 * 1024 * 1024)  # 25 MB


def _max_pixels() -> int:
    return _int_env("DSPM_OCR_MAX_PIXELS", 40_000_000)  # 40 MP - reject bombs above this


def _max_dimension() -> int:
    return _int_env("DSPM_OCR_MAX_DIMENSION", 2600)  # downscale longest side before OCR


def _timeout_seconds() -> float:
    return _float_env("DSPM_OCR_TIMEOUT_SECONDS", 20.0)


def _min_confidence() -> float:
    return _float_env("DSPM_OCR_MIN_CONFIDENCE", 0.3)


def _max_chars() -> int:
    return _int_env("DSPM_OCR_MAX_CHARS", 120_000)


def ocr_enabled() -> bool:
    return os.getenv("DSPM_OCR_ENABLED", "0") == "1"


_engine = None
_engine_lock = threading.Lock()
# One RapidOCR inference already uses the configured ONNX intra-op CPU threads.
# Concurrent calls benchmarked worse and the shared engine is not documented as
# re-entrant, so P-B serializes inference while allowing collection/analysis
# around it to remain parallel. A timed-out daemon retains this gate until its
# bounded inference actually exits.
_ocr_inference_gate = threading.Semaphore(1)
_unavailable_logged = False


def _get_engine():
    """Lazily create ONE RapidOCR engine and reuse it (model load + first-run
    warmup are costly; a fresh engine per image would be catastrophic). Returns
    None when the optional dependency is absent or init fails."""
    global _engine, _unavailable_logged
    if _engine is not None:
        return _engine
    with _engine_lock:
        if _engine is not None:
            return _engine
        try:
            from rapidocr_onnxruntime import RapidOCR
        except Exception:
            if not _unavailable_logged:
                logger.warning(
                    "OCR is enabled (DSPM_OCR_ENABLED=1) but rapidocr-onnxruntime is not "
                    "installed - OCR is disabled. Install requirements-ocr.txt to enable it."
                )
                _unavailable_logged = True
            return None
        try:
            threads = _int_env("DSPM_OCR_INTRA_OP_THREADS", 0)
            _engine = RapidOCR(intra_op_num_threads=threads) if threads > 0 else RapidOCR()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not initialise the OCR engine: %s", exc)
            return None
    return _engine


def ocr_available() -> bool:
    """True only when OCR is enabled AND the engine can be created."""
    return ocr_enabled() and _get_engine() is not None


# ---------------------------------------------------------------------------
# Result cache — the accuracy-neutral speedup.
#
# OCR inference (~2 s/image, all cores) dominates scan time and is the ONLY heavy
# step; decode/hash are milliseconds and concurrency measurably HURTS (a single
# inference already saturates the cores). Identical image bytes always produce the
# identical OCR result, so re-running OCR on an unchanged image is pure waste. A
# process-wide LRU keyed by the file's content hash removes:
#   * re-OCR of unchanged images across repeat scans (the server is long-running),
#   * double-OCR of one physical file surfaced via two overlapping SMB shares
#     (both are read before the record-level dedup runs).
# It changes NOTHING about accuracy — a cache hit returns the exact same text OCR
# would produce. Bounded by DSPM_OCR_CACHE_MAX entries (0 disables the cache).
# ---------------------------------------------------------------------------
_ocr_cache: "OrderedDict[str, str]" = OrderedDict()
_ocr_cache_lock = threading.Lock()


def _ocr_cache_max() -> int:
    return _int_env("DSPM_OCR_CACHE_MAX", 1024)


def _file_sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 16), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _cache_get(key: str | None) -> str | None:
    if key is None:
        return None
    with _ocr_cache_lock:
        text = _ocr_cache.get(key)
        if text is not None:
            _ocr_cache.move_to_end(key)  # mark most-recently-used
        return text


def _cache_put(key: str | None, text: str) -> None:
    if key is None:
        return
    cap = _ocr_cache_max()
    if cap <= 0:
        return
    with _ocr_cache_lock:
        _ocr_cache[key] = text
        _ocr_cache.move_to_end(key)
        while len(_ocr_cache) > cap:
            _ocr_cache.popitem(last=False)  # evict least-recently-used


def warmup() -> bool:
    """Load and warm the engine so the FIRST real image does not pay the one-time
    ONNX graph-optimisation cost (~4-6 s cold vs ~2 s warm). Safe to call from a
    background thread at server startup; returns True if the engine is ready."""
    if not ocr_enabled():
        return False
    engine = _get_engine()
    if engine is None:
        return False
    try:
        import numpy as np

        _run_ocr_with_budget(engine, np.zeros((32, 96, 3), dtype="uint8"))
        return True
    except Exception:  # pragma: no cover - defensive
        return False


def is_ocr_scannable(extension: str) -> bool:
    return ocr_enabled() and str(extension or "").lower() in OCR_IMAGE_EXTENSIONS


def dependency_installed() -> bool:
    """True if the rapidocr extra is importable, WITHOUT loading the model
    (cheap enough for a startup / health check)."""
    import importlib.util

    try:
        return importlib.util.find_spec("rapidocr_onnxruntime") is not None
    except Exception:
        return False


def ocr_status() -> dict:
    """Machine-readable OCR posture for /api/health and diagnostics."""
    enabled = ocr_enabled()
    installed = dependency_installed()
    if enabled and installed:
        state = "enabled"
    elif enabled and not installed:
        state = "enabled_but_dependency_missing"
    elif installed:
        state = "disabled_dependency_present"
    else:
        state = "disabled"
    return {
        "enabled": enabled,
        "dependency_installed": installed,
        "state": state,
        "image_extensions": sorted(OCR_IMAGE_EXTENSIONS),
        "inference_workers": 1,
        "parallelism": "serialized_inference",
    }


def ocr_status_line() -> str:
    """One-line human summary for the startup log - the answer to 'is OCR on?'."""
    return {
        "enabled": "OCR: ENABLED (RapidOCR available) - images/scanned docs will be text-extracted.",
        "enabled_but_dependency_missing": (
            "OCR: enabled (DSPM_OCR_ENABLED=1) but rapidocr-onnxruntime is NOT installed - "
            "OCR will be SKIPPED. Install it: pip install -r requirements-ocr.txt"
        ),
        "disabled_dependency_present": (
            "OCR: OFF. The dependency is installed; set DSPM_OCR_ENABLED=1 to turn it on."
        ),
        "disabled": (
            "OCR: OFF (optional). To enable: pip install -r requirements-ocr.txt "
            "and set DSPM_OCR_ENABLED=1."
        ),
    }[ocr_status()["state"]]


def _load_bounded_image(path: Path):
    """Open an image with strict file-size / pixel caps and downscale it, without
    fully decoding a pathological (decompression-bomb) image. Returns a numpy RGB
    array or None. Pillow decodes (with its own bomb guard); the untrusted bytes
    are never passed to opencv's decoders directly."""
    from PIL import Image

    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= 0 or size > _max_file_bytes():
        return None
    try:
        with Image.open(path) as image:
            # Bomb guard: reject on the header's declared pixel count BEFORE any
            # decode. This is authoritative (both Pillow and we derive pixels from
            # width*height, so a small file that "decodes huge" is caught here).
            # We deliberately do NOT touch the process-global Image.MAX_IMAGE_PIXELS
            # (that would leak to other scans/threads); Pillow's own default guard
            # remains a backstop and any DecompressionBombError is caught below.
            width, height = image.size  # header only - no full decode yet
            if width <= 0 or height <= 0 or (width * height) > _max_pixels():
                return None
            image = image.convert("RGB")  # forces the guarded decode
            longest = max(width, height)
            if longest > _max_dimension():
                scale = _max_dimension() / longest
                image = image.resize((max(1, int(width * scale)), max(1, int(height * scale))))
            import numpy as np

            return np.array(image)
    except Exception:
        return None


def _run_ocr_with_budget(engine, image):
    """Run OCR in a watchdog thread and abandon it if it exceeds the per-image
    budget. ONNX Runtime releases the GIL during inference, so join(timeout)
    actually fires; the abandoned (daemon) thread finishes its bounded work in
    the background. Returns the OCR result list or None."""
    box: dict = {}

    def work() -> None:
        try:
            with _ocr_inference_gate:
                output = engine(image)
                box["result"] = output[0] if isinstance(output, tuple) else output
        except Exception as exc:  # pragma: no cover - defensive
            box["error"] = exc

    worker = threading.Thread(target=work, name="dspm-ocr", daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(_timeout_seconds())
    if worker.is_alive():
        logger.debug("OCR exceeded the %ss budget and was abandoned", _timeout_seconds())
        return None
    if "error" in box:
        logger.debug("OCR failed: %s", box["error"])
        return None
    _ = time.monotonic() - started
    return box.get("result")


def max_image_bytes() -> int:
    """The largest image OCR reads (DSPM_OCR_MAX_FILE_BYTES)."""
    return _max_file_bytes()


def extract_text_from_image(path: Path | str, max_chars: int | None = None, digest: str | None = None) -> str:
    """Extract text from an image via OCR. Fail-CLOSED: returns "" when OCR is
    disabled/unavailable, the image is rejected by a cap, the budget is exceeded,
    or anything goes wrong. Never raises.

    ``digest`` is the image's SHA-256 when the caller has read it already (W2.2): the
    cache key then costs no second read. An image over the size cap is refused before
    it is hashed - it used to be read whole for a cache key, then rejected."""
    if not ocr_enabled():
        return ""
    engine = _get_engine()
    if engine is None:
        return ""
    path = Path(path)
    limit = _max_chars() if max_chars is None else max_chars
    try:
        if path.stat().st_size > _max_file_bytes():
            return ""
    except OSError:
        return ""

    # Cache lookup by content hash: an unchanged image returns its prior result
    # WITHOUT re-running OCR (same bytes -> same text, so accuracy is identical).
    if digest is None or _ocr_cache_max() <= 0:
        digest = _file_sha256(path) if _ocr_cache_max() > 0 else None
    cached = _cache_get(digest)
    if cached is not None:
        return cached[:limit] if limit else cached

    image = _load_bounded_image(path)
    if image is None:
        return ""
    result = _run_ocr_with_budget(engine, image)
    if result is None:
        # Timeout / error: may be transient, so do NOT cache "" (a later scan retries).
        return ""
    lines: list[str] = []
    threshold = _min_confidence()
    for item in result:
        try:
            _box, text, confidence = item
        except (TypeError, ValueError):
            continue
        try:
            confident = float(confidence) >= threshold
        except (TypeError, ValueError):
            confident = True
        if confident and str(text).strip():
            lines.append(str(text))
    text = "\n".join(lines)
    # OCR completed (result is a list): cache even an empty result - a genuinely
    # text-less image should not be re-OCR'd next scan.
    _cache_put(digest, text)
    return text[:limit] if limit else text
