"""Phase 0.2 / H1 recurrence guard tests.

Assert that scripts/check_no_cmdline_secrets.py (the CI gate) passes on the real
tree and would FAIL the build if a credential were re-introduced onto a command
line - the acceptance criterion for roadmap item 0.2.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "scripts" / "check_no_cmdline_secrets.py"


def _load_guard():
    spec = importlib.util.spec_from_file_location("cmdline_secret_guard", GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CmdlineSecretGuardTests(unittest.TestCase):
    guard = _load_guard()

    def test_real_tree_passes(self) -> None:
        result = subprocess.run([sys.executable, str(GUARD)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"guard should pass on the real tree:\n{result.stderr}")

    def test_rule1_flags_credential_on_subprocess_argv(self) -> None:
        src = 'import subprocess\nsubprocess.run(["schtasks", "/RP", self.config.password])\n'
        self.assertTrue(self.guard.check_source(Path("x.py"), src, False))

    def test_rule2_flags_powershell_reading_payload_password(self) -> None:
        src = 's = "ConvertTo-SecureString ([string]$payload.password) -AsPlainText -Force"\n'
        self.assertTrue(self.guard.check_source(Path("x.py"), src, False))

    def test_rule3_flags_credential_dict_in_collectors(self) -> None:
        src = 'p = {"host": "h", "password": self.config.password}\n'
        self.assertTrue(self.guard.check_source(Path("x.py"), src, True))

    def test_env_channel_is_allowed(self) -> None:
        # The correct pattern - secret via env=, command carries only the encoded blob.
        src = (
            "import subprocess, os\n"
            'subprocess.run(["powershell", "-EncodedCommand", encoded], '
            'env={**os.environ, "DSPM_ACTIVATION_PW": self.config.password})\n'
        )
        self.assertEqual(self.guard.check_source(Path("x.py"), src, True), [])


if __name__ == "__main__":
    unittest.main()
