"""C11: service logs rotate within a fixed bound, survive a restart, and hold no secret.

Gate line: "logs survive service restart" and "No secret may appear in: logs". The bound
is (backups + 1) files of at most the configured size; a restart appends; the configured
secret values, bearer and signed tokens, `password=`-shaped pairs and database-URL
passwords are replaced before any handler writes - tracebacks included.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from backend import logging_setup

SECRET = "vault-key-" + "Q" * 30


class _Case(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        root = logging.getLogger()
        saved = (list(root.handlers), root.level)

        def restore() -> None:
            for handler in list(root.handlers):
                root.removeHandler(handler)
                handler.close()
            for handler in saved[0]:
                root.addHandler(handler)
            root.setLevel(saved[1])
            shutil.rmtree(self.tmp, ignore_errors=True)

        self.addCleanup(restore)
        # For the whole test, as for a service's whole life: the filter reads the
        # configured secrets when each line is written.
        patcher = mock.patch.dict(os.environ, {"DSPM_LOG_DIR": str(self.tmp), "DSPM_VAULT_KEY": SECRET})
        patcher.start()
        self.addCleanup(patcher.stop)

    def configure(self, **env: str) -> Path:
        with mock.patch.dict(os.environ, env):
            path = logging_setup.configure("backend")
        self.assertIsNotNone(path)
        return path

    def flush(self) -> None:
        for handler in logging.getLogger().handlers:
            handler.flush()


class RotationTest(_Case):

    def test_the_logs_never_exceed_their_bound(self) -> None:
        path = self.configure(DSPM_LOG_MAX_MB="1", DSPM_LOG_BACKUPS="3")
        log = logging.getLogger("sentro.c11.rotation")
        line = "x" * 1000
        for index in range(6000):  # ~6 MB through a 1 MB x (3 + 1) bound
            log.warning("%05d %s", index, line)
        self.flush()
        files = sorted(self.tmp.glob("backend.log*"))
        self.assertEqual([item.name for item in files], ["backend.log", "backend.log.1", "backend.log.2", "backend.log.3"])
        for item in files:
            self.assertLessEqual(item.stat().st_size, 1024 * 1024)
        self.assertIn("05999", path.read_text(encoding="utf-8"), "the newest line is in the live file")

    def test_a_restart_appends_to_the_log(self) -> None:
        path = self.configure()
        logging.getLogger("sentro.c11").warning("before the restart")
        self.flush()
        path = self.configure()  # what the next service start does
        logging.getLogger("sentro.c11").warning("after the restart")
        self.flush()
        text = path.read_text(encoding="utf-8")
        self.assertIn("before the restart", text)
        self.assertIn("after the restart", text)
        self.assertLess(text.index("before the restart"), text.index("after the restart"))

    def test_uvicorn_lines_reach_the_same_file(self) -> None:
        path = self.configure()
        logging.getLogger("uvicorn.access").info('127.0.0.1:5000 - "GET /api/health HTTP/1.1" 200')
        self.flush()
        self.assertIn("GET /api/health", path.read_text(encoding="utf-8"))


class RedactionTest(_Case):

    def test_configured_secrets_tokens_and_passwords_never_reach_the_file(self) -> None:
        path = self.configure()
        log = logging.getLogger("sentro.c11.redaction")
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXZhbHVl"
        log.warning("vault key is %s", SECRET)
        log.warning("Authorization: Bearer abcdefghijklmnop123")
        log.warning("token %s issued", jwt)
        log.warning("connect postgresql://sentro_app:Hunter2-db@db01:5432/sentro")
        log.warning("retry with password=Sparrow-771 and api_key: k-123456")
        try:
            raise RuntimeError(f"could not decrypt with {SECRET}")
        except RuntimeError:
            log.exception("decrypt failed")
        self.flush()
        text = path.read_text(encoding="utf-8")
        for secret in (SECRET, "abcdefghijklmnop123", jwt, "Hunter2-db", "Sparrow-771", "k-123456"):
            self.assertNotIn(secret, text)
        self.assertIn("RuntimeError", text, "the traceback is kept, without the secret")
        self.assertGreaterEqual(text.count(logging_setup.REDACTED), 7)
        self.assertIn("postgresql://sentro_app:[redacted]@db01", text, "the rest of the URL still helps")

    def test_ordinary_lines_are_untouched(self) -> None:
        path = self.configure()
        logging.getLogger("sentro.c11").info("Scan 42 finished: 1,204 files, 17 findings")
        self.flush()
        self.assertIn("Scan 42 finished: 1,204 files, 17 findings", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
