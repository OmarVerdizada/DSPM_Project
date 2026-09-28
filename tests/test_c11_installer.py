"""C11: the installer's decisions, without touching Windows services.

The real install, upgrade, downgrade refusal and uninstall ran on this host against an
isolated prefix (roadmap C11 status); these pin what that run depends on: which way an
upgrade goes and when it is refused, that secret files are generated in the product's own
formats and never overwritten, that no secret reaches the configuration file or a service
definition, and that data removal needs the prefix typed back.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging" / "windows"
_spec = importlib.util.spec_from_file_location("sentro_installer", PACKAGING / "sentro_installer.py")
installer = importlib.util.module_from_spec(_spec)
sys.modules["sentro_installer"] = installer
_spec.loader.exec_module(installer)


def _manifest(commit: str, when: int, revision: int) -> dict:
    return {"commit": commit, "commit_time": when, "schema_revision": revision, "label": f"r{revision}-{commit[:6]}"}


class TheUpgradeDecisionTest(unittest.TestCase):
    INSTALLED = {"commit": "aaaaaa", "commit_time": 2000, "release": "r26-aaaaaa", "data_root": r"C:\Data"}

    def test_a_newer_build_upgrades(self) -> None:
        self.assertEqual(installer.decide_upgrade(self.INSTALLED, _manifest("bbbbbb", 3000, 27), 26, None), "upgrade")

    def test_the_same_build_is_refused(self) -> None:
        with self.assertRaises(installer.InstallError):
            installer.decide_upgrade(self.INSTALLED, _manifest("aaaaaa", 2000, 26), 26, None)

    def test_an_older_build_at_an_older_schema_is_refused_and_says_how_to_go_back(self) -> None:
        with self.assertRaises(installer.InstallError) as refused:
            installer.decide_upgrade(self.INSTALLED, _manifest("cccccc", 1000, 25), 26, None)
        message = str(refused.exception)
        self.assertIn("revision 25", message)
        self.assertIn("-RestoreBackup", message)

    def test_an_older_build_at_the_same_schema_downgrades(self) -> None:
        self.assertEqual(installer.decide_upgrade(self.INSTALLED, _manifest("dddddd", 1000, 26), 26, None), "downgrade")

    def test_going_back_needs_a_backup_at_the_package_schema(self) -> None:
        with self.assertRaises(installer.InstallError):
            installer.decide_upgrade(self.INSTALLED, _manifest("cccccc", 1000, 25), 26, {"schema_revision": 26})
        self.assertEqual(installer.decide_upgrade(self.INSTALLED, _manifest("cccccc", 1000, 25), 26,
                                                  {"schema_revision": 25}), "restore-downgrade")

    def test_a_newer_build_expecting_an_older_schema_is_refused_too(self) -> None:
        # Ordering by time never overrides the schema: the database decides what can run on it.
        with self.assertRaises(installer.InstallError):
            installer.decide_upgrade(self.INSTALLED, _manifest("eeeeee", 9000, 24), 26, None)


class _LayoutCase(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.layout = installer.Layout(self.tmp / "install", self.tmp / "data", "SentroT")


class TheSecretsTest(_LayoutCase):

    def test_keys_are_in_the_products_formats_and_never_overwritten(self) -> None:
        from cryptography.fernet import Fernet

        created = installer.init_secrets(self.layout, None)
        self.assertEqual(sorted(created), sorted(filename for filename, _ in installer.SECRET_FILES.values()))
        for filename in ("vault_key", "artifact_key", "backup_key"):
            Fernet((self.layout.secrets / filename).read_text(encoding="utf-8").strip().encode())
        self.assertGreaterEqual(len((self.layout.secrets / "secret_key").read_text(encoding="utf-8").strip()), 32)
        before = {path.name: path.read_bytes() for path in self.layout.secrets.iterdir()}
        self.assertEqual(installer.init_secrets(self.layout, None), [], "a reinstall creates nothing")
        self.assertEqual({path.name: path.read_bytes() for path in self.layout.secrets.iterdir()}, before)

    def test_the_first_administrator_password_meets_the_password_policy(self) -> None:
        from backend import security

        for _ in range(50):
            security.validate_password_strength(installer.admin_password(), username="admin")  # raises if refused

    def test_the_database_url_file_is_copied_and_checked(self) -> None:
        source = self.tmp / "url.txt"
        source.write_text("mysql://nope\n", encoding="utf-8")
        with self.assertRaises(installer.InstallError):
            installer.init_secrets(self.layout, source)
        source.write_text("postgresql://sentro_app:pw-77@db01/sentro?sslmode=verify-full\n", encoding="utf-8")
        installer.init_secrets(self.layout, source)
        self.assertEqual((self.layout.secrets / "db_url").read_text(encoding="utf-8").strip(),
                         "postgresql://sentro_app:pw-77@db01/sentro?sslmode=verify-full")


class TheConfigurationItWritesTest(_LayoutCase):

    def test_production_configuration_is_valid_and_holds_no_secret(self) -> None:
        from backend import config

        installer.init_secrets(self.layout, None)
        (self.layout.secrets / "db_url").write_text("postgresql://sentro_app:pw-77@127.0.0.1/sentro\n", encoding="utf-8")
        text = installer.render_config(self.layout, "production", 8000, "sentro.corp.example")
        for path in self.layout.secrets.iterdir():
            self.assertNotIn(path.read_text(encoding="utf-8").strip(), text)
        self.layout.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.layout.config_file.write_text(text, encoding="utf-8")
        effective = config.resolve({}, self.layout.config_file)
        self.assertEqual(effective.errors, [])
        self.assertTrue(effective.production)
        self.assertEqual(effective.get("DSPM_TRUSTED_HOSTS"), "sentro.corp.example")

    def test_evaluation_configuration_uses_sqlite_and_the_dev_admin_password_file(self) -> None:
        from backend import config

        installer.init_secrets(self.layout, None)
        text = installer.render_config(self.layout, "evaluation", 8000)
        self.layout.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.layout.config_file.write_text(text, encoding="utf-8")
        effective = config.resolve({}, self.layout.config_file)
        self.assertEqual(effective.errors, [])
        self.assertFalse(effective.production)
        self.assertTrue(effective.get("DSPM_DB_PATH").endswith("dspm.sqlite"))
        # a local install otherwise prints a generated one-time password to its log
        self.assertEqual(effective.values["DSPM_DEV_ADMIN_PASSWORD"].source, "secret file")

    def test_production_needs_a_public_host_and_a_database(self) -> None:
        package = self.tmp / "package"
        package.mkdir()
        (package / "manifest.json").write_text('{"label": "x", "commit": "c", "commit_time": 1}', encoding="utf-8")

        class NoServices(installer.Runner):
            def run(self, args, **kwargs):
                return subprocess.CompletedProcess(args, 1, "", "")

        with self.assertRaises(installer.InstallError) as refused:
            installer.install(package, self.layout, port=8000, mode="production", db_url_file=None,
                              runner=NoServices())
        self.assertIn("-PublicHostName", str(refused.exception))
        with self.assertRaises(installer.InstallError) as refused:
            installer.install(package, self.layout, port=8000, mode="production", db_url_file=None,
                              public_host="sentro.corp.example", runner=NoServices())
        self.assertIn("PostgreSQL", str(refused.exception))


class AFolderSomeoneElseCreatedTest(_LayoutCase):
    """A standard user may create folders under ProgramData; one who pre-created the data
    root would own it after the install and could open its secrets (M3 exit review)."""

    def _runner(self, owner: str, installing: str = "S-1-5-21-10-20-30-500"):
        issued: list[list[str]] = []

        class Answers(installer.Runner):
            def run(self, args, **kwargs):
                issued.append([str(arg) for arg in args])
                if str(args[0]) == "powershell":
                    return subprocess.CompletedProcess(args, 0, f"{owner}\n{installing}\n", "")
                return subprocess.CompletedProcess(args, 0, "", "")

        return Answers(), issued

    def test_a_data_root_owned_by_a_user_is_refused(self) -> None:
        self.layout.data_root.mkdir(parents=True)
        runner, _issued = self._runner("S-1-5-21-10-20-30-1001")
        with self.assertRaises(installer.InstallError) as refused:
            installer.refuse_foreign_folders(self.layout, runner)
        self.assertIn("owned by S-1-5-21-10-20-30-1001", str(refused.exception))

    def test_administrators_system_or_the_installing_account_may_own_it(self) -> None:
        self.layout.data_root.mkdir(parents=True)
        for owner in ("S-1-5-32-544", "S-1-5-18", "S-1-5-21-10-20-30-500"):
            runner, _issued = self._runner(owner)
            installer.refuse_foreign_folders(self.layout, runner)

    def test_nothing_is_asked_about_folders_that_do_not_exist(self) -> None:
        runner, issued = self._runner("S-1-5-21-10-20-30-1001")
        installer.refuse_foreign_folders(self.layout, runner)
        self.assertEqual(issued, [])

    def test_the_lock_down_makes_administrators_the_owner_of_everything_first(self) -> None:
        runner, issued = self._runner("S-1-5-32-544")
        installer.lock_down(self.layout, runner)
        self.assertEqual(issued[0][:4], ["icacls", str(self.layout.data_root), "/setowner", "*S-1-5-32-544"])
        self.assertIn("/T", issued[0])

    @unittest.skipUnless(sys.platform == "win32", "Windows ACLs")
    def test_the_owner_query_reads_a_real_folder(self) -> None:
        owner, installing = installer.folder_owner(self.tmp, installer.Runner())
        self.assertTrue(owner.startswith("S-1-") and installing.startswith("S-1-"), (owner, installing))


class TheServiceDefinitionTest(_LayoutCase):

    def test_it_names_paths_and_a_port_only(self) -> None:
        xml = installer.service_xml(self.layout, "SentroTBackend", "backend", "serve --host 127.0.0.1 --port 8000")
        self.assertIn("<startmode>Automatic</startmode>", xml)
        self.assertIn('<env name="DSPM_CONFIG_FILE"', xml)
        self.assertEqual(xml.count("<env "), 1, "the configuration file's path is the only environment")
        self.assertIn('<onfailure action="restart"', xml)
        self.assertIn('<log mode="roll-by-size">', xml)
        for word in ("PASSWORD", "KEY=", "postgresql://", "SECRET"):
            self.assertNotIn(word, xml.upper() if word.isupper() else xml)

    def test_each_service_runs_as_its_own_virtual_account(self) -> None:
        self.assertEqual(self.layout.service_account("SentroTBackend"), "NT SERVICE\\SentroTBackend")


class ARefusedUpgradeTest(_LayoutCase):
    """The installer places the new release before it can read the database's revision, so
    a refusal must not delete a release that was there before - the one kept for rollback."""

    def _upgrade(self, keep_existing: bool) -> Path:
        import json
        from unittest import mock

        package = self.tmp / "package"
        package.mkdir()
        (package / "manifest.json").write_text(json.dumps(_manifest("older1", 1000, 25)), encoding="utf-8")
        self.layout.data_root.mkdir(parents=True)
        installer.write_state(self.layout, {**TheUpgradeDecisionTest.INSTALLED, "port": 8000, "history": []})
        running = self.layout.releases / "r26-aaaaaa"
        running.mkdir(parents=True)
        release = self.layout.releases / "r25-older1"
        if keep_existing:
            release.mkdir()
            (release / "kept.txt").write_text("the rollback copy", encoding="utf-8")

        def place(package_dir, layout, runner):
            release.mkdir(exist_ok=True)
            return release

        with (mock.patch.object(installer, "current_release", return_value=running),
              mock.patch.object(installer, "place_release", side_effect=place),
              mock.patch.object(installer, "product"),
              mock.patch.object(installer, "product_json", return_value={"applied_revision": 26})):
            with self.assertRaises(installer.InstallError):
                installer.upgrade(package, self.layout, runner=installer.Runner())
        return release

    def test_a_release_that_was_already_there_survives_the_refusal(self) -> None:
        self.assertTrue(self._upgrade(keep_existing=True).exists())

    def test_a_release_placed_only_for_this_run_is_removed(self) -> None:
        self.assertFalse(self._upgrade(keep_existing=False).exists())


class TheUninstallTest(_LayoutCase):

    def test_removing_data_needs_the_prefix_typed_back(self) -> None:
        self.layout.data_root.mkdir(parents=True)
        with self.assertRaises(installer.InstallError):
            installer.uninstall(self.layout, remove_data=True, confirm="yes")
        self.assertTrue(self.layout.data_root.exists())

    def test_by_default_the_data_stays(self) -> None:
        class Missing(installer.Runner):
            def run(self, args, **kwargs):
                return subprocess.CompletedProcess(args, 1060, "", "")  # no such service

        (self.layout.data_root / "secrets").mkdir(parents=True)
        (self.layout.data_root / "secrets" / "vault_key").write_text("k", encoding="utf-8")
        installer.write_state(self.layout, {"release": "r26-x", "history": []})
        installer.uninstall(self.layout, runner=Missing())
        self.assertTrue((self.layout.data_root / "secrets" / "vault_key").exists())
        self.assertIsNone(installer.read_state(self.layout)["release"])
        self.assertEqual(installer.read_state(self.layout)["history"][-1]["action"], "uninstall")


class ThePowerShellEntryPointsTest(unittest.TestCase):

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell")
    def test_every_script_parses(self) -> None:
        for name in ("SentroPackage.psm1", "install.ps1", "upgrade.ps1", "uninstall.ps1"):
            script = (f"$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
                      f"'{PACKAGING / name}', [ref]$null, [ref]$e); $e.Count")
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                 capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(out, "0", name)

    def test_nothing_from_the_package_runs_before_it_is_verified(self) -> None:
        module = (PACKAGING / "SentroPackage.psm1").read_text(encoding="utf-8")
        self.assertNotIn(". $digestPath", module, "the digest file is read as text, never dot-sourced")
        for name in ("install.ps1", "upgrade.ps1", "uninstall.ps1"):
            text = (PACKAGING / name).read_text(encoding="utf-8")
            self.assertLess(text.index("Test-SentroPackage"), text.index("Expand-SentroRuntime"), name)
            self.assertLess(text.index("Expand-SentroRuntime"), text.index("Invoke-SentroInstaller"), name)

    def test_an_unsigned_package_needs_the_operator_to_say_so(self) -> None:
        module = (PACKAGING / "SentroPackage.psm1").read_text(encoding="utf-8")
        self.assertIn("HELD FOR CODE-SIGNING CERTIFICATE", module)
        self.assertIn("elseif (-not $AllowUnsigned)", module)


class ThePinsTest(unittest.TestCase):

    def test_every_third_party_file_is_pinned_by_digest(self) -> None:
        import json

        pins = json.loads((PACKAGING / "pins.json").read_text(encoding="utf-8"))
        for name in ("python", "winsw", "pip"):
            self.assertRegex(pins[name]["sha256"], r"^[0-9a-f]{64}$", name)
        self.assertEqual(pins["winsw"]["license"], "MIT")
        self.assertEqual(pins["python"]["authenticode_signer"], "Python Software Foundation")


if __name__ == "__main__":
    unittest.main()
