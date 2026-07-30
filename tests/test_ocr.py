"""OCR extraction: opt-in gating, fail-closed hardening against hostile images,
and no-regression when disabled.

The engine is mocked (a fake callable) so these tests are fast and run whether or
not rapidocr-onnxruntime is installed. The image-bomb / size / corrupt caps run
against the REAL Pillow-based loader (which never reaches the engine)."""

from __future__ import annotations

import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from PIL import Image, ImageDraw

import collectors.file_scanner as fs
import collectors.ocr as ocr


def _write_png(path: Path, text: str = "Card: 4111 1111 1111 1111", size=(420, 90)) -> Path:
    image = Image.new("RGB", size, "white")
    ImageDraw.Draw(image).text((10, 10), text, fill="black")
    image.save(path)
    return path


class _FakeEngine:
    """Stands in for RapidOCR: returns (result, elapse) like the real callable."""

    def __init__(self, result, delay: float = 0.0):
        self.result = result
        self.delay = delay
        self.calls = 0

    def __call__(self, _image):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        return self.result, 0.01


def _enabled():
    return mock.patch.dict(os.environ, {"DSPM_OCR_ENABLED": "1"})


class OcrDisabledTests(unittest.TestCase):
    """Default (OFF) posture: images behave exactly as before OCR existed."""

    def setUp(self) -> None:
        os.environ.pop("DSPM_OCR_ENABLED", None)

    def test_disabled_by_default(self) -> None:
        self.assertFalse(ocr.ocr_enabled())
        self.assertFalse(ocr.is_ocr_scannable(".png"))

    def test_extract_returns_empty_when_disabled(self) -> None:
        with TemporaryDirectory() as d:
            png = _write_png(Path(d) / "x.png")
            # Even if an engine somehow existed, disabled short-circuits first.
            with mock.patch.object(ocr, "_get_engine", return_value=_FakeEngine([])):
                self.assertEqual(ocr.extract_text_from_image(png), "")

    def test_image_stays_metadata_only_when_disabled(self) -> None:
        self.assertEqual(fs.scan_mode_for_extension(".png"), "metadata_only")
        with TemporaryDirectory() as d:
            png = _write_png(Path(d) / "x.png")
            self.assertEqual(fs.read_text_preview(png), "")


class OcrEnabledGatingTests(unittest.TestCase):
    def test_enabled_marks_images_scannable(self) -> None:
        with _enabled():
            self.assertTrue(ocr.ocr_enabled())
            self.assertTrue(ocr.is_ocr_scannable(".PNG"))  # case-insensitive
            self.assertFalse(ocr.is_ocr_scannable(".txt"))
            self.assertEqual(fs.scan_mode_for_extension(".png"), "image_ocr")

    def test_absent_dependency_fails_closed(self) -> None:
        with _enabled(), mock.patch.object(ocr, "_get_engine", return_value=None):
            with TemporaryDirectory() as d:
                png = _write_png(Path(d) / "x.png")
                self.assertEqual(ocr.extract_text_from_image(png), "")
                self.assertFalse(ocr.ocr_available())


class OcrExtractionTests(unittest.TestCase):
    def test_extracts_and_feeds_preview(self) -> None:
        result = [[[[0, 0]], "Card: 4111 1111 1111 1111", 0.9], [[[0, 0]], "Name: Jane", 0.88]]
        with _enabled(), mock.patch.object(ocr, "_get_engine", return_value=_FakeEngine(result)):
            with TemporaryDirectory() as d:
                png = _write_png(Path(d) / "x.png")
                text = fs.read_text_preview(png)  # exercises the wired scanner path
        self.assertIn("4111 1111 1111 1111", text)
        self.assertIn("Name: Jane", text)

    def test_low_confidence_lines_dropped(self) -> None:
        result = [[[[0, 0]], "GOOD LINE", 0.9], [[[0, 0]], "noise", 0.05]]
        with _enabled(), mock.patch.object(ocr, "_get_engine", return_value=_FakeEngine(result)):
            with TemporaryDirectory() as d:
                png = _write_png(Path(d) / "x.png")
                text = ocr.extract_text_from_image(png)
        self.assertIn("GOOD LINE", text)
        self.assertNotIn("noise", text)

    def test_output_is_length_bounded(self) -> None:
        result = [[[[0, 0]], "A" * 5000, 0.9]]
        with _enabled(), mock.patch.object(ocr, "_get_engine", return_value=_FakeEngine(result)):
            with TemporaryDirectory() as d:
                png = _write_png(Path(d) / "x.png")
                text = ocr.extract_text_from_image(png, max_chars=100)
        self.assertEqual(len(text), 100)

    def test_slow_inference_abandoned_at_budget(self) -> None:
        result = [[[[0, 0]], "TOO LATE", 0.9]]
        slow = _FakeEngine(result, delay=2.0)
        with _enabled(), \
             mock.patch.dict(os.environ, {"DSPM_OCR_TIMEOUT_SECONDS": "0.2"}), \
             mock.patch.object(ocr, "_get_engine", return_value=slow):
            with TemporaryDirectory() as d:
                png = _write_png(Path(d) / "x.png")
                started = time.monotonic()
                text = ocr.extract_text_from_image(png)
                elapsed = time.monotonic() - started
        self.assertEqual(text, "")            # abandoned, fail-closed
        self.assertLess(elapsed, 1.5)         # returned control at the budget


class OcrHardeningTests(unittest.TestCase):
    """Hostile-image caps run against the REAL Pillow loader (engine never reached)."""

    def test_pixel_bomb_rejected_from_header(self) -> None:
        engine = _FakeEngine([[[[0, 0]], "SHOULD NOT RUN", 0.9]])
        with _enabled(), \
             mock.patch.dict(os.environ, {"DSPM_OCR_MAX_PIXELS": "100"}), \
             mock.patch.object(ocr, "_get_engine", return_value=engine):
            with TemporaryDirectory() as d:
                png = _write_png(Path(d) / "big.png", size=(400, 400))  # 160k px > 100
                self.assertEqual(ocr.extract_text_from_image(png), "")
        self.assertEqual(engine.calls, 0)  # never decoded/ran the bomb

    def test_oversized_file_rejected(self) -> None:
        engine = _FakeEngine([[[[0, 0]], "X", 0.9]])
        with _enabled(), \
             mock.patch.dict(os.environ, {"DSPM_OCR_MAX_FILE_BYTES": "10"}), \
             mock.patch.object(ocr, "_get_engine", return_value=engine):
            with TemporaryDirectory() as d:
                png = _write_png(Path(d) / "x.png")  # > 10 bytes
                self.assertEqual(ocr.extract_text_from_image(png), "")
        self.assertEqual(engine.calls, 0)

    def test_corrupt_image_fails_closed(self) -> None:
        engine = _FakeEngine([[[[0, 0]], "X", 0.9]])
        with _enabled(), mock.patch.object(ocr, "_get_engine", return_value=engine):
            with TemporaryDirectory() as d:
                bad = Path(d) / "x.png"
                bad.write_bytes(b"this is not a PNG")
                self.assertEqual(ocr.extract_text_from_image(bad), "")
        self.assertEqual(engine.calls, 0)

    def test_missing_file_fails_closed(self) -> None:
        with _enabled(), mock.patch.object(ocr, "_get_engine", return_value=_FakeEngine([])):
            self.assertEqual(ocr.extract_text_from_image(Path("does_not_exist.png")), "")


class SmbImageOcrTests(unittest.TestCase):
    """The SMB content path downloads image bytes to a temp file and OCRs them."""

    def _scanner_with_bytes(self, data: bytes):
        from collectors.smb_scanner import SMBConfig, SMBScanner

        class _FakeConn:
            def retrieveFileFromOffset(self, _share, _path, buffer, offset=0, max_length=0):
                buffer.write(data)
                return (len(data), len(data))

        scanner = SMBScanner(SMBConfig(server="x", read_content=True))
        scanner.connection = _FakeConn()
        return scanner

    def _png_bytes(self) -> bytes:
        from io import BytesIO

        buf = BytesIO()
        img = Image.new("RGB", (420, 90), "white")
        ImageDraw.Draw(img).text((10, 10), "Card: 4111 1111 1111 1111", fill="black")
        img.save(buf, format="PNG")
        return buf.getvalue()

    def test_smb_image_is_ocred_when_enabled(self) -> None:
        result = [[[[0, 0]], "Card: 4111 1111 1111 1111", 0.9]]
        scanner = self._scanner_with_bytes(self._png_bytes())
        with _enabled(), mock.patch.object(ocr, "_get_engine", return_value=_FakeEngine(result)):
            text = scanner._read_file_preview("Finance", "/photo.png", ".png")
        self.assertIn("4111 1111 1111 1111", text)

    def test_smb_image_ignored_when_disabled(self) -> None:
        os.environ.pop("DSPM_OCR_ENABLED", None)
        scanner = self._scanner_with_bytes(self._png_bytes())
        with mock.patch.object(ocr, "_get_engine", return_value=_FakeEngine([["x", "Y", 0.9]])):
            self.assertEqual(scanner._read_file_preview("Finance", "/photo.png", ".png"), "")


class OcrStatusTests(unittest.TestCase):
    def test_status_reflects_flag(self) -> None:
        os.environ.pop("DSPM_OCR_ENABLED", None)
        self.assertFalse(ocr.ocr_status()["enabled"])
        with _enabled():
            self.assertTrue(ocr.ocr_status()["enabled"])
            self.assertIn("ENABLED", ocr.ocr_status_line())


if __name__ == "__main__":
    unittest.main()
