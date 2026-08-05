"""ARCH-002: DSPM_COPILOT_ENABLED=0 lets the core deploy without the Copilot.

Run in a subprocess so each import sees a clean flag value (the app object and
its routes are built at import time) without disturbing the in-process app.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent


class CopilotFeatureFlagTests(unittest.TestCase):
    def _routes(self, flag_value: str) -> str:
        env = dict(os.environ, DSPM_COPILOT_ENABLED=flag_value, PYTHONPATH=str(_REPO))
        code = "from backend.app import app; print('\\n'.join(sorted({getattr(r, 'path', '') for r in app.routes})))"
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, env=env, cwd=str(_REPO), timeout=180,
        )
        if result.returncode != 0:
            self.fail(result.stderr[-2000:])
        return result.stdout

    def test_enabled_by_default_mounts_copilot(self) -> None:
        routes = self._routes("1")
        self.assertIn("copilot", routes.lower())
        self.assertIn("/api/health", routes)

    def test_disabled_removes_copilot_but_keeps_core(self) -> None:
        routes = self._routes("0")
        self.assertNotIn("copilot", routes.lower())
        self.assertIn("/api/health", routes)  # core platform still fully mounted
        self.assertIn("/api/scan", routes)


if __name__ == "__main__":
    unittest.main()
