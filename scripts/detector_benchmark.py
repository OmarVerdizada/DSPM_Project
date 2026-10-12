"""Track P-D detector-throughput benchmark (parity-gated).

The generic catalog runs one regex pass per rule. The P-D necessary-substring
prefilter skips any rule whose mandatory literal is absent from the content -
recall-exact (a skipped rule would have produced zero matches). This measures the
per-call cost of `classify_content` with the prefilter ON vs OFF and asserts the
findings are byte-identical.

    python scripts/detector_benchmark.py [--iterations 40] [--path enterprise_test_data]

Local prose is the clearest case (few anchors present -> most rules skipped). The
gain shrinks toward 1x on secret-dense content where most anchors ARE present.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from classification.regex_classifier import classify_content  # noqa: E402


def _bench(text: str, iterations: int) -> tuple[float, float, bool]:
    on = classify_content(text)
    off = classify_content(text, _prefilter=False)
    parity = on == off

    def timed(prefilter: bool) -> float:
        t0 = time.perf_counter()
        for _ in range(iterations):
            classify_content(text, _prefilter=prefilter)
        return (time.perf_counter() - t0) / iterations * 1000.0

    return timed(True), timed(False), parity


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=40)
    ap.add_argument("--path", default="", help="Optional corpus; else a synthetic prose blob.")
    args = ap.parse_args()

    cases: list[tuple[str, str]] = []
    if args.path:
        root = Path(args.path).expanduser().resolve()
        if not root.exists():
            raise SystemExit(f"path not found: {root}")
        blob = []
        for p in root.rglob("*"):
            if p.is_file():
                try:
                    blob.append(p.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass
        cases.append((f"corpus:{root.name}", "\n".join(blob)))
    else:
        cases.append(("prose-no-secrets", "the quick brown fox jumps over the lazy dog by the river. " * 3000))
        cases.append(("secret-dense", "password: hunter2 email a@b.com AKIAIOSFODNN7EXAMPLE confidential\n" * 1500))

    print(f"{'case':22} {'on(ms)':>9} {'off(ms)':>9} {'speedup':>8}  parity")
    ok = True
    for name, text in cases:
        on_ms, off_ms, parity = _bench(text, args.iterations)
        ok = ok and parity
        speedup = off_ms / on_ms if on_ms else 1.0
        print(f"{name:22} {on_ms:>9.2f} {off_ms:>9.2f} {speedup:>7.2f}x  {'OK' if parity else 'MISMATCH!'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
