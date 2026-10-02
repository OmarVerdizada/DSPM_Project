"""C13: a privileged, audited reveal of ONE value, read again from its source.

Gate line: "Unauthorized user denied; authorized reveal displays only the requested value
and records actor, target and reason; changed file fails safely." Plus the product
owner's lines: explicit permission, saved credential, stable file identity, re-read and
re-detect, a mandatory reason, typed-password scans unrevealable, the audit never holds
the value, and the console keeps it nowhere but the dialog.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

from backend import evidence_reveal, security, store
from backend.app import app

CARD = "4111 1111 1111 1111"
OTHER_CARD = "5500 0000 0000 0004"
IBAN = "AZ21NABZ00000000137010001944"
CONTENT = (f"Payroll export\nPrimary card {CARD} for travel.\nBackup card {OTHER_CARD}.\n"
           f"Salary account {IBAN}.\n")
REASON = "Card holder dispute INC-4471: confirm which card was on file"


class _ScannedCase(unittest.TestCase):
    """A workspace that scanned one local file through the real route."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        original = store.DB_PATH
        store.DB_PATH = self.tmp / "reveal.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        for tenant in ("t-rev", "t-other"):
            store.create_tenant(tenant, tenant)
        store.save_custom_role("t-rev", "revealer", "Revealer", "", ["inventory.view", "evidence.view", "evidence.reveal"],
                               actor="test")
        store.save_custom_role("t-other", "revealer", "Revealer", "", ["inventory.view", "evidence.view", "evidence.reveal"],
                               actor="test")
        for name, role, tenant in (("boss", "admin", "t-rev"), ("rita", "revealer", "t-rev"), ("ana", "analyst", "t-rev"),
                                   ("otto", "revealer", "t-other")):
            store.create_user(name, security.hash_password("Reveal-test-pass-9"), role, tenant)
        for name in ("rita", "otto", "boss"):
            store.clear_login_failures(f"reveal:{name}")
        self.client = TestClient(app)
        # A scan's local_path is project-local by design; tmp/ is ignored by git.
        root = Path(__file__).resolve().parents[1]
        relative = Path("tmp") / f"c13-estate-{os.getpid()}-{id(self)}"
        self.folder = root / relative
        self.folder.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.file = self.folder / "payroll.txt"
        self.file.write_text(CONTENT, encoding="utf-8")
        with mock.patch("backend.app.partitioned_scans_enabled", return_value=False):
            scanned = self.client.post("/api/scan", headers=self.as_("boss", "admin", "t-rev"), json={
                "local_path": relative.as_posix(), "async_scan": False, "save_report": True, "compact_result": False,
                "incremental_enabled": False})
        self.assertEqual(scanned.status_code, 200, scanned.text[:400])
        admin = self.as_("boss", "admin", "t-rev")
        findings = self.client.get("/api/findings?limit=100", headers=admin).json()["items"]
        cards = [item for item in findings if "card" in str(item.get("type"))]
        self.assertTrue(cards, [item.get("type") for item in findings])
        # The list is a summary; the detail carries each value's fingerprint, as the console reads it.
        self.finding = self.client.get(f"/api/findings/{cards[0]['finding_id']}", headers=admin).json()["finding"]
        self.assertTrue(self.finding.get("secure_value_fingerprints"), sorted(self.finding))
        self.fingerprints = list(self.finding["secure_value_fingerprints"])

    def as_(self, user: str, role: str, tenant: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(user, role, tenant)}"}

    def reveal(self, fingerprint: str | None = None, reason: str = REASON, user=("rita", "revealer", "t-rev"), **kw):
        return self.client.post(f"/api/findings/{self.finding['finding_id']}/reveal", headers=self.as_(*user, **kw),
                                json={"fingerprint": fingerprint or self.fingerprints[0], "reason": reason})

    def audit_rows(self, tenant: str = "t-rev") -> list[dict]:
        return [row for row in store.read_audit_log(tenant, 200) if row["action"].startswith("evidence.reveal")]


class AnAuthorisedRevealTest(_ScannedCase):

    def test_it_returns_only_the_requested_value(self) -> None:
        response = self.reveal()
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(set(body), {"finding_id", "type", "fingerprint", "value", "masked"})
        self.assertIn(body["value"].replace(" ", ""), {CARD.replace(" ", ""), OTHER_CARD.replace(" ", "")})
        others = {CARD.replace(" ", ""), OTHER_CARD.replace(" ", "")} - {body["value"].replace(" ", "")}
        text = response.text.replace(" ", "")
        for other in [*others, IBAN]:
            self.assertNotIn(other, text, "only the one value asked for")

    def test_each_fingerprint_reveals_its_own_value(self) -> None:
        values = {self.reveal(fingerprint).json()["value"].replace(" ", "") for fingerprint in self.fingerprints}
        self.assertEqual(len(values), len(set(self.fingerprints)))

    def test_it_is_audited_with_actor_target_and_reason_and_never_the_value(self) -> None:
        self.reveal()
        row = self.audit_rows()[-1]
        self.assertEqual((row["action"], row["actor"]), ("evidence.revealed", "rita"))
        detail = row["detail"]
        self.assertEqual(detail["reason"], REASON)
        self.assertEqual(detail["target"], str(self.file))
        self.assertEqual(detail["source"], "local")
        self.assertEqual(detail["result"], "revealed")
        everything = json.dumps(store.read_audit_log("t-rev", 500)).replace(" ", "")
        for value in (CARD, OTHER_CARD, IBAN):
            self.assertNotIn(value.replace(" ", ""), everything)

    def test_the_value_is_read_again_not_stored(self) -> None:
        # Nothing the scan kept holds the raw value; the reveal can only have come from the file.
        with store._connect() as conn:
            dumped = json.dumps([dict(row) for table in ("findings", "finding_index", "assets", "scan_reports")
                                 for row in conn.execute(f"SELECT * FROM {table}").fetchall()], default=str)
        self.assertNotIn(CARD.replace(" ", ""), dumped.replace(" ", ""))
        self.assertEqual(self.reveal().status_code, 200)


class TheRefusalsTest(_ScannedCase):

    def test_a_reason_is_mandatory(self) -> None:
        response = self.reveal(reason="because")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["code"], "reason_required")
        self.assertEqual(self.audit_rows()[-1]["detail"]["result"], "reason_required")

    def test_a_changed_file_reveals_nothing(self) -> None:
        self.file.write_text(CONTENT + "appended after the scan\n", encoding="utf-8")
        response = self.reveal()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["detail"]["code"], "file_changed")
        self.assertNotIn(CARD.replace(" ", ""), response.text.replace(" ", ""))
        self.assertEqual(self.audit_rows()[-1]["action"], "evidence.reveal_refused")

    def test_a_deleted_file_reveals_nothing(self) -> None:
        self.file.unlink()
        self.assertEqual(self.reveal().json()["detail"]["code"], "source_missing")

    def test_a_fingerprint_from_elsewhere_is_refused(self) -> None:
        response = self.reveal(fingerprint="[redacted:000000000000]")
        self.assertEqual((response.status_code, response.json()["detail"]["code"]), (400, "unknown_occurrence"))

    def test_evidence_view_alone_is_not_enough(self) -> None:
        self.assertEqual(self.reveal(user=("ana", "analyst", "t-rev")).status_code, 403)

    def test_another_workspace_cannot_reveal_it(self) -> None:
        response = self.reveal(user=("otto", "revealer", "t-other"))
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(CARD.replace(" ", ""), response.text.replace(" ", ""))

    def test_reveals_are_limited_per_account(self) -> None:
        from backend import app as app_module

        throttle = app_module.RouteThrottle("reveal", 2, 3600)
        with mock.patch.object(app_module, "REVEAL_THROTTLE", throttle):
            codes = [self.reveal().status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
        self.assertEqual(self.audit_rows()[-1]["detail"]["result"], "throttled", "a throttled attempt is on the record")

    def test_an_api_key_cannot_hold_it(self) -> None:
        created = self.client.post("/api/api-keys", headers=self.as_("boss", "admin", "t-rev"),
                                   json={"label": "bot", "role": "revealer"})
        self.assertEqual(created.status_code, 400, created.text)


class TheSourcesTest(_ScannedCase):

    def test_the_scan_recorded_how_it_read_the_file(self) -> None:
        source = store.get_scan_source("t-rev", self.finding["scan_id"])
        self.assertEqual((source["source_kind"], source["credential_kind"], source["credential_ref"]), ("local", "none", ""))

    def test_a_typed_password_is_recorded_as_typed_and_never_kept(self) -> None:
        from backend import app as app_module

        payload = app_module.ScanRequest(server="files.corp.example", username="svc", password="Typed-pass-2291")
        app_module._record_scan_source("t-rev", "scan-typed", payload)
        source = store.get_scan_source("t-rev", "scan-typed")
        self.assertEqual((source["source_kind"], source["credential_kind"], source["credential_ref"]), ("smb", "typed", ""))
        with store._connect() as conn:
            self.assertNotIn("Typed-pass-2291", json.dumps([dict(r) for r in conn.execute("SELECT * FROM scan_sources")]))

    def test_a_typed_password_scan_is_unrevealable(self) -> None:
        asset = {"source": "smb", "share": "Finance", "path": "/payroll.txt", "sha256": "ab" * 32, "size": 10}
        with self.assertRaises(evidence_reveal.RevealRefused) as refused:
            evidence_reveal.reread("t-rev", asset, {"credential_kind": "typed", "credential_ref": "", "server": "fs1"})
        self.assertEqual(refused.exception.code, "typed_credential")
        with self.assertRaises(evidence_reveal.RevealRefused) as unknown:
            evidence_reveal.reread("t-rev", asset, None)
        self.assertEqual(unknown.exception.code, "no_scan_record")

    def test_an_smb_file_is_read_again_with_the_saved_credential(self) -> None:
        import hashlib

        from backend.vault import CredentialVault

        ref = CredentialVault().store("t-rev", "svc-read", "Saved-pass-2292", "CORP")
        raw = CONTENT.encode("utf-8")
        asset = {"source": "smb", "share": "Finance", "path": "/payroll.txt", "reuse_key": "smb://fs1/Finance/payroll.txt",
                 "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        seen = {"live_size": len(raw)}

        class Share:
            def getAttributes(self, share, path):
                return type("Attributes", (), {"file_size": seen["live_size"]})()

            def close(self):
                seen["closed"] = True

        class Scanner:
            def __init__(self, config):
                seen["config"] = config
                self.connection = Share()

            def connect(self):
                return True

            def _acquire_file_data(self, share, path, extension, size):
                seen["read"] = (share, path)
                return type("Data", (), {"content": CONTENT, "sha256": hashlib.sha256(raw).hexdigest()})()

        with mock.patch("collectors.smb_scanner.SMBScanner", Scanner):
            text = evidence_reveal.reread("t-rev", asset, {"credential_kind": "saved", "credential_ref": ref, "server": "fs1"})
        self.assertIn(CARD, text)
        self.assertEqual((seen["config"].server, seen["config"].username, seen["config"].password),
                         ("fs1", "svc-read", "Saved-pass-2292"))
        self.assertEqual(seen["config"].tenant_id, "t-rev", "the workspace's scan targets decide the connection (C5)")
        self.assertEqual(seen["read"], ("Finance", "/payroll.txt"))
        changed = dict(asset, sha256="00" * 32)
        with mock.patch("collectors.smb_scanner.SMBScanner", Scanner):
            with self.assertRaises(evidence_reveal.RevealRefused) as refused:
                evidence_reveal.reread("t-rev", changed, {"credential_kind": "saved", "credential_ref": ref, "server": "fs1"})
        self.assertEqual(refused.exception.code, "file_changed")
        # a file that GREW since the scan: the share's live size says so before anything is
        # read (hashing only the recorded number of bytes would have called it unchanged)
        seen.pop("read", None)
        seen["live_size"] = len(raw) + 40
        with mock.patch("collectors.smb_scanner.SMBScanner", Scanner):
            with self.assertRaises(evidence_reveal.RevealRefused) as grown:
                evidence_reveal.reread("t-rev", asset, {"credential_kind": "saved", "credential_ref": ref, "server": "fs1"})
        self.assertEqual(grown.exception.code, "file_changed")
        self.assertNotIn("read", seen)

    def test_a_file_the_scan_kept_no_digest_for_is_not_revealed(self) -> None:
        # Without the scan's digest a changed file could not be told from the one scanned.
        asset = {"source": "local", "path": str(self.file), "size": len(CONTENT.encode("utf-8"))}
        with self.assertRaises(evidence_reveal.RevealRefused) as refused:
            evidence_reveal.reread("t-rev", asset, {"credential_kind": "none"})
        self.assertEqual(refused.exception.code, "no_identity")

    def test_endpoint_scans_are_not_revealable(self) -> None:
        with self.assertRaises(evidence_reveal.RevealRefused) as refused:
            evidence_reveal.reread("t-rev", {"source": "endpoint-winrm"}, {"credential_kind": "saved"})
        self.assertEqual(refused.exception.code, "unsupported_source")


class TheConsoleTest(unittest.TestCase):
    """The value lives in the dialog and nowhere else: not a URL, not browser storage."""

    def test_the_reveal_script_keeps_the_value_nowhere_else(self) -> None:
        script = Path(__file__).resolve().parents[1].joinpath("frontend", "app.js").read_text(encoding="utf-8")
        block = script[script.index("// C13: reveal"):script.index("// C13: end of reveal")]
        for forbidden in ("localStorage", "sessionStorage", "history.", "location.", "document.cookie", "console.log"):
            self.assertNotIn(forbidden, block)
        self.assertIn("revealValue.textContent = \"\"", block, "closing the dialog clears the value")
        self.assertIn("REVEAL_SHOW_SECONDS", block, "and it clears itself after a while")


class ExitReviewRevealTest(_ScannedCase):
    """M3 exit review: every attempt is on the record, with where it would have read."""

    def test_a_refusal_names_the_file_it_would_have_read(self) -> None:
        self.file.write_text(CONTENT + "changed\n", encoding="utf-8")
        self.assertEqual(self.reveal().status_code, 409)
        detail = self.audit_rows()[-1]["detail"]
        self.assertEqual((detail["result"], detail["source"], detail["target"]), ("file_changed", "local", str(self.file)))

    def test_an_unexpected_failure_is_audited_and_reveals_nothing(self) -> None:
        with mock.patch.object(evidence_reveal, "reread", side_effect=RuntimeError("connection reset by peer")):
            response = self.reveal()
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["detail"]["code"], "reveal_failed")
        self.assertNotIn("connection reset", response.text, "no raw exception text")
        row = self.audit_rows()[-1]
        self.assertEqual((row["action"], row["detail"]["result"], row["detail"]["error"]),
                         ("evidence.reveal_refused", "error", "RuntimeError"))

    def test_the_throttle_counts_and_checks_in_one_step(self) -> None:
        from concurrent.futures import ThreadPoolExecutor

        from backend import app as app_module

        throttle = app_module.RouteThrottle("reveal-race", 3, 3600)
        store.clear_login_failures("reveal-race:rita")
        with ThreadPoolExecutor(max_workers=12) as pool:
            allowed = list(pool.map(lambda _i: throttle.take("rita"), range(12)))
        self.assertEqual(sum(allowed), 3, "parallel requests cannot all pass before any is counted")

    def test_sentros_own_data_is_never_a_source(self) -> None:
        private = self.folder / "install-data"
        private.mkdir()
        kept = private / "server.log"
        kept.write_text(CONTENT, encoding="utf-8")
        with mock.patch.dict(os.environ, {"DSPM_DATA_DIR": str(private)}):
            with self.assertRaises(evidence_reveal.RevealRefused) as refused:
                evidence_reveal.reread("t-rev", {"source": "local", "path": str(kept), "sha256": "ab" * 32, "size": 1},
                                       {"credential_kind": "none"})
            self.assertEqual(refused.exception.code, "product_file")

    def test_a_local_scan_does_not_read_sentros_own_data(self) -> None:
        from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

        private = self.folder / "install-data"
        private.mkdir()
        (private / "server.log").write_text(f"another workspace logged {OTHER_CARD}\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"DSPM_DATA_DIR": str(private)}):
            report = DSPMDiscoveryEngine(ScanConfig(tenant_id="t-rev", local_path=str(self.folder),
                                                    walk_local_path=True, incremental_enabled=False)).run().to_dict()
        paths = [str(item.get("path") or "") for item in report.get("files") or []]
        self.assertTrue(any(path.endswith("payroll.txt") for path in paths), paths)
        self.assertFalse(any("install-data" in path for path in paths), paths)


class ExitReviewConsoleTest(unittest.TestCase):

    def test_a_late_answer_is_never_written_into_the_page(self) -> None:
        script = Path(__file__).resolve().parents[1].joinpath("frontend", "app.js").read_text(encoding="utf-8")
        block = script[script.index("// C13: reveal"):script.index("// C13: end of reveal")]
        answered = block.index("parts.value.textContent = data.value")
        self.assertIn("if (!stillAsked()) return;", block[:answered], "a closed or reopened dialog drops the answer")
        self.assertIn("clearRevealedValue();", block[block.index("if (!stillAsked()) return;"):answered],
                      "the previous countdown is stopped before a new one starts")
        self.assertIn("if (stillAsked()) parts.error.textContent", block)


if __name__ == "__main__":
    unittest.main()
