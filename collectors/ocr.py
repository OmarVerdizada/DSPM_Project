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

import os
import threading
import time
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


def extract_text_from_image(path: Path | str, max_chars: int | None = None) -> str:
    """Extract text from an image via OCR. Fail-CLOSED: returns "" when OCR is
    disabled/unavailable, the image is rejected by a cap, the budget is exceeded,
    or anything goes wrong. Never raises."""
    if not ocr_enabled():
        return ""
    engine = _get_engine()
    if engine is None:
        return ""
    path = Path(path)
    image = _load_bounded_image(path)
    if image is None:
        return ""
    result = _run_ocr_with_budget(engine, image)
    lines: list[str] = []
    threshold = _min_confidence()
    for item in result or []:
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
    limit = _max_chars() if max_chars is None else max_chars
    return text[:limit] if limit else text
