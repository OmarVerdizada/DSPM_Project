"""D10: a signed offline licence, and signed update packages - a publisher key the install
pinned, not one the package brings - with downgrade protection.

Gate line: "Altered/expired licence and update packages are refused; offline recovery
path documented."

The keys here are made for the test. A production publisher key is made and kept offline
by the publisher (scripts/sentro_sign.py keygen); its public half is what an install pins.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from backend import licensing, security, signing, store
from backend.app import app

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "packaging" / "windows"))

import sentro_installer as installer  # noqa: E402
import sentro_sign  # noqa: E402

PASSWORD = "Kestrel-lantern-4471"
NOW = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


def raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class KeysCase(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.publisher, self.stranger, self.licence_only = (Ed25519PrivateKey.generate() for _ in range(3))
        self.trust_path = self.tmp / "trust" / "publishers.json"
        signing.add_to_trust(self.trust_path, raw(self.publisher), ["package", "licence"], "test publisher", "now")
        signing.add_to_trust(self.trust_path, raw(self.licence_only), ["licence"], "licences only", "now")
        patcher = mock.patch.dict(os.environ, {"DSPM_TRUST_FILE": str(self.trust_path)})
        patcher.start()
        self.addCleanup(patcher.stop)

    @property
    def trust(self) -> dict:
        return signing.load_trust(self.trust_path)


class TheVerifierTest(unittest.TestCase):
    """The installer verifies with plain Python; it must agree with a real implementation."""

    RFC8032 = (
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    )

    def test_the_rfc_8032_vectors(self) -> None:
        for public, message, signature in self.RFC8032:
            self.assertTrue(signing.verify_ed25519(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)))

    def test_it_agrees_with_cryptography_and_refuses_every_tampering(self) -> None:
        for index in range(20):
            key = Ed25519PrivateKey.generate()
            message = os.urandom(index * 13)
            signature = key.sign(message)
            self.assertTrue(signing.verify_ed25519(raw(key), message, signature))
            flipped = bytearray(signature)
            flipped[(index * 7) % 64] ^= 1 << (index % 8)
            self.assertFalse(signing.verify_ed25519(raw(key), message, bytes(flipped)))
            self.assertFalse(signing.verify_ed25519(raw(key), message + b"!", signature))
            self.assertFalse(signing.verify_ed25519(raw(Ed25519PrivateKey.generate()), message, signature))

    def test_a_malleable_s_and_wrong_lengths_are_refused(self) -> None:
        key = Ed25519PrivateKey.generate()
        signature = key.sign(b"m")
        s = int.from_bytes(signature[32:], "little") + signing._L
        self.assertFalse(signing.verify_ed25519(raw(key), b"m", signature[:32] + s.to_bytes(32, "little")))
        self.assertFalse(signing.verify_ed25519(raw(key)[:31], b"m", signature))
        self.assertFalse(signing.verify_ed25519(raw(key), b"m", signature[:63]))


class PackageCase(KeysCase):

    def make_package(self, name: str = "pkg", *, commit_time: int = 3000, schema: int = 33, sign_with=None) -> Path:
        package = self.tmp / name
        (package / "app" / "backend").mkdir(parents=True)
        shutil.copyfile(ROOT / "backend" / "signing.py", package / "app" / "backend" / "signing.py")
        (package / "app" / "main.py").write_text("print('sentro')\n", encoding="utf-8")
        (package / "manifest.json").write_text(json.dumps({"label": f"r{schema}-{name}", "commit": f"c-{name}",
                                                           "commit_time": commit_time, "schema_revision": schema}),
                                               encoding="utf-8")
        self.write_sums(package)
        if sign_with is not None:
            sentro_sign.sign_package(sign_with, package)
        return package

    @staticmethod
    def write_sums(package: Path) -> None:
        lines = []
        for path in sorted(package.rglob("*")):
            relative = path.relative_to(package).as_posix()
            if path.is_file() and relative not in signing.UNLISTED:
                lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
        (package / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


class ThePackageSignatureTest(PackageCase):

    def test_a_package_signed_by_the_pinned_publisher_is_verified(self) -> None:
        result = signing.verify_package(self.make_package(sign_with=self.publisher), self.trust)
        self.assertEqual((result["signed_by"], result["files"]), (signing.key_id(raw(self.publisher)), 3))

    def test_a_package_re_signed_by_someone_else_is_refused_whatever_key_it_carries(self) -> None:
        # The defect D10 closes: the package named its own signer. A key the package brings
        # (publisher.json) is never trusted because it is there.
        package = self.make_package(sign_with=self.stranger)
        with self.assertRaisesRegex(signing.TrustError, "does not trust"):
            signing.verify_package(package, self.trust)

    def test_an_altered_or_added_file_is_refused(self) -> None:
        package = self.make_package(sign_with=self.publisher)
        (package / "app" / "main.py").write_text("print('altered')\n", encoding="utf-8")
        with self.assertRaisesRegex(signing.TrustError, "does not match SHA256SUMS"):
            signing.verify_package(package, self.trust)
        other = self.make_package("pkg2", sign_with=self.publisher)
        (other / "app" / "extra.py").write_text("x = 1\n", encoding="utf-8")
        with self.assertRaisesRegex(signing.TrustError, "not in SHA256SUMS"):
            signing.verify_package(other, self.trust)

    def test_checksums_rewritten_after_signing_are_refused(self) -> None:
        package = self.make_package(sign_with=self.publisher)
        (package / "app" / "main.py").write_text("print('altered')\n", encoding="utf-8")
        self.write_sums(package)  # the attacker keeps SHA256SUMS consistent
        with self.assertRaisesRegex(signing.TrustError, "changed after signing"):
            signing.verify_package(package, self.trust)

    def test_a_manifest_changed_after_signing_is_refused(self) -> None:
        package = self.make_package(sign_with=self.publisher)
        manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
        manifest["commit_time"] = 9999  # pass off an old build as new
        (package / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.write_sums(package)
        with self.assertRaisesRegex(signing.TrustError, "changed after signing"):
            signing.verify_package(package, self.trust)

    def test_a_forged_signature_is_refused(self) -> None:
        package = self.make_package(sign_with=self.publisher)
        envelope = json.loads((package / "SIGNATURE.json").read_text(encoding="utf-8"))
        forged = bytearray(base64.b64decode(envelope["signature"]))
        forged[5] ^= 0x10
        envelope["signature"] = base64.b64encode(bytes(forged)).decode()
        (package / "SIGNATURE.json").write_text(json.dumps(envelope), encoding="utf-8")
        with self.assertRaisesRegex(signing.TrustError, "does not match"):
            signing.verify_package(package, self.trust)

    def test_a_key_trusted_for_licences_cannot_sign_packages(self) -> None:
        with self.assertRaisesRegex(signing.TrustError, "not to sign a package"):
            signing.verify_package(self.make_package(sign_with=self.licence_only), self.trust)

    def test_an_unsigned_package_needs_the_operator_to_accept_it(self) -> None:
        package = self.make_package()
        with self.assertRaisesRegex(signing.TrustError, "not signed"):
            signing.verify_package(package, self.trust)
        self.assertEqual(signing.verify_package(package, self.trust, allow_unsigned=True)["signed_by"], "")

    def test_an_older_signed_package_is_a_downgrade_and_refused_unless_asked_for(self) -> None:
        package = self.make_package(commit_time=1000, sign_with=self.publisher)
        installed = {"commit_time": 2000, "release": "r33-newer"}
        with self.assertRaisesRegex(signing.TrustError, "downgrade"):
            signing.verify_package(package, self.trust, installed=installed)
        self.assertTrue(signing.verify_package(package, self.trust, installed=installed, allow_downgrade=True)["downgrade"])


class TheInstallerTest(PackageCase):

    def layout(self) -> installer.Layout:
        return installer.Layout(self.tmp / "install", self.tmp / "data", "Sentro")

    def test_the_installed_releases_verifier_and_trust_decide_not_the_packages(self) -> None:
        layout = self.layout()
        layout.trust_file.parent.mkdir(parents=True)
        shutil.copyfile(self.trust_path, layout.trust_file)
        release = self.tmp / "install" / "releases" / "r32-old"
        (release / "app" / "backend").mkdir(parents=True)
        shutil.copyfile(ROOT / "backend" / "signing.py", release / "app" / "backend" / "signing.py")
        package = self.make_package(sign_with=self.stranger)
        # The hostile package ships a verifier that accepts anything, and trusts its own key.
        (package / "app" / "backend" / "signing.py").write_text(
            "UNLISTED = ()\nclass TrustError(ValueError):\n    pass\n"
            "def load_trust(path):\n    return {}\n"
            "def verify_package(*a, **k):\n    return {'label': 'x', 'files': 0, 'signed_by': 'me'}\n", encoding="utf-8")
        self.write_sums(package)
        sentro_sign.sign_package(self.stranger, package)
        with self.assertRaisesRegex(installer.InstallError, "does not trust"):
            installer.verify_package(package, layout, installed={"commit_time": 1}, verifier=release)

    def test_an_upgrade_checks_the_package_before_placing_anything(self) -> None:
        layout = self.layout()
        layout.trust_file.parent.mkdir(parents=True)
        shutil.copyfile(self.trust_path, layout.trust_file)
        installer.write_state(layout, {"commit": "old", "commit_time": 1000, "release": "r32-old", "port": 8000,
                                       "history": []})
        running = layout.releases / "r32-old"
        (running / "app" / "backend").mkdir(parents=True)
        shutil.copyfile(ROOT / "backend" / "signing.py", running / "app" / "backend" / "signing.py")
        package = self.make_package(commit_time=3000, sign_with=self.stranger)
        placed = []
        with (mock.patch.object(installer, "current_release", return_value=running),
              mock.patch.object(installer, "place_release", side_effect=lambda *args: placed.append(args))):
            with self.assertRaisesRegex(installer.InstallError, "does not trust"):
                installer.upgrade(package, layout, runner=installer.Runner())
        self.assertEqual(placed, [], "nothing from the package was placed")

    def test_an_install_refuses_an_untrusted_package_before_placing_it(self) -> None:
        layout = self.layout()
        package = self.make_package(sign_with=self.stranger)
        placed = []
        with (mock.patch.object(installer.Services, "exists", return_value=False),
              mock.patch.object(installer, "refuse_foreign_folders"), mock.patch.object(installer, "lock_down"),
              mock.patch.object(installer, "place_release", side_effect=lambda *args: placed.append(args))):
            with self.assertRaisesRegex(installer.InstallError, "does not trust"):
                installer.install(package, layout, port=8000, mode="evaluation", db_url_file=None)
        self.assertEqual(placed, [])

    def test_install_pins_the_key_the_operator_gives_and_nothing_else(self) -> None:
        layout = self.layout()
        package = self.make_package(sign_with=self.publisher)
        with self.assertRaisesRegex(installer.InstallError, "does not trust"):
            installer.verify_package(package, layout)  # nothing pinned yet
        key_file = self.tmp / "publisher.pub"
        key_file.write_text(json.dumps(sentro_sign.publisher_document(raw(self.publisher))), encoding="utf-8")
        pinned = installer.pin_publisher(package, layout, publisher_key_file=key_file)
        self.assertEqual(pinned, signing.key_id(raw(self.publisher)))
        self.assertEqual(installer.verify_package(package, layout)["signed_by"], pinned)

    def test_trusting_the_packages_own_key_is_the_operators_explicit_choice(self) -> None:
        layout = self.layout()
        package = self.make_package(sign_with=self.stranger)
        self.assertEqual(installer.pin_publisher(package, layout), "", "no flag, no pin")
        self.assertFalse(layout.trust_file.exists())
        installer.pin_publisher(package, layout, trust_package_publisher=True)
        self.assertIn(signing.key_id(raw(self.stranger)), signing.load_trust(layout.trust_file))

    def test_an_older_build_is_refused_unless_going_back_was_asked_for(self) -> None:
        installed = {"commit": "aaaaaa", "commit_time": 2000, "release": "r33-aaaaaa"}
        older = {"commit": "dddddd", "commit_time": 1000, "schema_revision": 33, "label": "r33-dddddd"}
        with self.assertRaisesRegex(installer.InstallError, "AllowDowngrade"):
            installer.decide_upgrade(installed, older, 33, None)
        self.assertEqual(installer.decide_upgrade(installed, older, 33, None, allow_downgrade=True), "downgrade")

    def test_an_install_from_before_d10_is_given_its_trust_setting_once(self) -> None:
        layout = self.layout()
        layout.config_file.parent.mkdir(parents=True)
        layout.config_file.write_text("[settings]\nDSPM_ENV = \"production\"\n", encoding="utf-8")
        self.assertTrue(installer.ensure_trust_setting(layout))
        self.assertFalse(installer.ensure_trust_setting(layout))
        self.assertEqual(layout.config_file.read_text(encoding="utf-8").count("DSPM_TRUST_FILE"), 1)
        self.assertIn("DSPM_TRUST_FILE", installer.render_config(layout, "production", 8000, "sentro.test"))

    def test_the_powershell_check_leaves_the_signature_to_the_installer(self) -> None:
        module = (ROOT / "packaging" / "windows" / "SentroPackage.psm1").read_text(encoding="utf-8")
        self.assertIn("'SIGNATURE.json', 'publisher.json'", module)
        self.assertIn("HELD FOR CODE-SIGNING CERTIFICATE", module)
        install = (ROOT / "packaging" / "windows" / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("--publisher-key-file", install)
        upgrade = (ROOT / "packaging" / "windows" / "upgrade.ps1").read_text(encoding="utf-8")
        self.assertIn("--allow-downgrade", upgrade)


class LicenceCase(KeysCase):

    def setUp(self) -> None:
        super().setUp()
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "d10.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        if store.get_tenant("default") is None:
            store.create_tenant("default", "Default")
        store.create_tenant("t-d10", "t-d10")
        if store.get_user("admin") is None:
            store.create_user("admin", security.hash_password(PASSWORD), "admin", "default")
        store.create_user("d10-admin", security.hash_password(PASSWORD), "admin", "t-d10")
        self.client = TestClient(app)

    def as_(self, user: str = "admin", tenant: str = "default", *, mfa: bool = True) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, 'admin', tenant, mfa_verified=mfa)}"}

    def licence(self, key=None, *, expires: datetime | None = None, not_before: datetime | None = None,
                customer: str = "Contoso") -> dict:
        document = sentro_sign.licence_document(
            customer, (expires or datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            features=["scan"], not_before=not_before.isoformat() if not_before else None)
        return sentro_sign.sign_licence(key or self.publisher, document)

    def put(self, envelope, **headers):
        return self.client.put("/api/licence", headers=headers or self.as_(), json={"licence": json.dumps(envelope)})


class TheLicenceTest(LicenceCase):

    def test_a_signed_licence_in_force_is_installed(self) -> None:
        response = self.put(self.licence())
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["licence"]["state"], "valid")
        self.assertIn("licence.installed", [row["action"] for row in store.read_audit_log("default", 50)])

    def test_an_altered_licence_is_refused_and_the_installed_one_stays(self) -> None:
        self.put(self.licence())
        altered = self.licence(customer="Contoso")
        altered["licence"]["expires_at"] = "2099-01-01T00:00:00+00:00"  # a longer licence than was sold
        refused = self.put(altered)
        self.assertEqual(refused.status_code, 400)
        self.assertIn("altered", refused.json()["detail"])
        self.assertEqual(licensing.installed()["licence"]["customer"], "Contoso")
        self.assertNotEqual(licensing.installed()["licence"]["expires_at"], "2099-01-01T00:00:00+00:00")
        self.assertIn("licence.refused", [row["action"] for row in store.read_audit_log("default", 50)])

    def test_expired_not_yet_valid_and_untrusted_licences_are_refused(self) -> None:
        now = datetime.now(timezone.utc)
        for envelope, reason in (
                (self.licence(expires=now - timedelta(days=1)), "expired"),
                (self.licence(not_before=now + timedelta(days=3)), "not valid before"),
                (self.licence(self.stranger), "does not trust")):
            with self.subTest(reason=reason):
                refused = self.put(envelope)
                self.assertEqual(refused.status_code, 400)
                self.assertIn(reason, refused.json()["detail"])
        self.assertIsNone(licensing.installed())

    def test_a_key_trusted_only_for_packages_cannot_sign_licences(self) -> None:
        package_only = Ed25519PrivateKey.generate()
        signing.add_to_trust(self.trust_path, raw(package_only), ["package"], "packages only", "now")
        self.assertIn("not to sign a licence", self.put(self.licence(package_only)).json()["detail"])

    def test_only_the_platform_administrator_with_a_second_factor_installs_one(self) -> None:
        envelope = self.licence()
        self.assertEqual(self.put(envelope, **self.as_("d10-admin", "t-d10")).status_code, 403)
        self.assertEqual(self.put(envelope, **self.as_(mfa=False)).status_code, 403)
        self.assertEqual(self.client.get("/api/licence", headers=self.as_("d10-admin", "t-d10")).status_code, 403)

    def test_an_expired_licence_has_a_grace_period_then_stops_new_scans_only(self) -> None:
        expires = NOW + timedelta(days=30)
        envelope = self.licence(expires=expires, not_before=NOW - timedelta(days=1))
        with mock.patch.dict(os.environ, {"DSPM_LICENCE_REQUIRED": "1", "DSPM_LICENCE_GRACE_DAYS": "14"}):
            self.assertEqual(licensing.status(envelope, now=NOW)["state"], "valid")
            grace = licensing.status(envelope, now=expires + timedelta(days=3))
            self.assertEqual((grace["state"], grace["scans_allowed"]), ("grace", True))
            over = licensing.status(envelope, now=expires + timedelta(days=15))
            self.assertEqual((over["state"], over["scans_allowed"]), ("expired", False))
            altered = json.loads(json.dumps(envelope))
            altered["licence"]["customer"] = "Someone else"
            self.assertEqual(licensing.status(altered, now=NOW)["state"], "invalid", "an altered licence has no grace")
            self.assertEqual(licensing.status(altered, now=expires + timedelta(days=3))["state"], "invalid",
                             "nor once it would have expired")

    def test_with_a_licence_required_a_scan_without_one_is_refused_and_says_how_to_recover(self) -> None:
        from fastapi import HTTPException

        # Past the licence check nothing may start: a scan that got that far answers 418.
        started = HTTPException(status_code=418, detail="the scan started")
        with (mock.patch.dict(os.environ, {"DSPM_LICENCE_REQUIRED": "1"}),
              mock.patch("backend.app._prepare_local_scan_data", side_effect=started),
              mock.patch("backend.app._validate_scan_target", side_effect=started)):
            refused = self.client.post("/api/scan", headers=self.as_(), json={"local_path": "tmp", "async_scan": False})
            self.assertEqual(refused.status_code, 402)
            self.assertIn("main.py licence install", refused.json()["detail"])
            endpoint = self.client.post("/api/endpoint/scan", headers=self.as_(),
                                        json={"host": "203.0.113.5", "async_scan": False})
            self.assertEqual(endpoint.status_code, 402, endpoint.text[:200])
            self.assertEqual(self.client.get("/api/findings", headers=self.as_()).status_code, 200, "reading goes on")
            self.put(self.licence())
            self.assertEqual(licensing.scans_allowed(), (True, ""))

    def test_a_due_schedule_without_a_licence_is_recorded_not_started(self) -> None:
        from backend import scan_scheduler

        schedule = store.create_scan_schedule("t-d10", name="nightly", request={"local_path": "tmp"},
                                              created_by="d10-admin")
        started = []
        with mock.patch.dict(os.environ, {"DSPM_LICENCE_REQUIRED": "1"}):
            self.assertEqual(scan_scheduler.run_due_schedules(started.append,
                                                              now=datetime.now(timezone.utc) + timedelta(minutes=1)), [])
        self.assertEqual(started, [])
        [after] = [item for item in store.list_scan_schedules("t-d10") if item["schedule_id"] == schedule["schedule_id"]]
        self.assertIn("licence", json.dumps(after).lower())

    def test_the_offline_recovery_path_needs_only_the_host(self) -> None:
        good, bad = self.tmp / "renewal.licence", self.tmp / "altered.licence"
        good.write_text(json.dumps(self.licence()), encoding="utf-8")
        altered = self.licence()
        altered["licence"]["customer"] = "Someone else"
        bad.write_text(json.dumps(altered), encoding="utf-8")
        env = {**os.environ, "DSPM_DB_PATH": str(store.DB_PATH), "DSPM_TRUST_FILE": str(self.trust_path)}
        env.pop("DSPM_DB_URL", None)
        refused = subprocess.run([sys.executable, "main.py", "licence", "install", str(bad)], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=120)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("REFUSED", refused.stdout)
        installed = subprocess.run([sys.executable, "main.py", "licence", "install", str(good)], cwd=ROOT, env=env,
                                   capture_output=True, text=True, timeout=120)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.assertEqual(licensing.status(licensing.installed())["state"], "valid")
        status = subprocess.run([sys.executable, "main.py", "licence", "status", "--json"], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(json.loads(status.stdout)["customer"], "Contoso")

    def test_the_documented_recovery_path_exists(self) -> None:
        text = (ROOT / "docs" / "DEPLOYMENT_WINDOWS.md").read_text(encoding="utf-8")
        for words in ("main.py licence install", "-PublisherKeyFile", "-AllowDowngrade", "package verify --package"):
            self.assertIn(words, text)


if __name__ == "__main__":
    unittest.main()
