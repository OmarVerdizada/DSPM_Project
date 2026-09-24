"""B6: the console writes the rule, and dismissing a false positive can write it for you.

The gate is one sentence - a rule from a FALSE_POSITIVE prevents recreation next scan -
and this is the half an analyst touches: the dismissal that offers to write the rule, the
scope that answers "and what else?", and the ordinary shape of a tenant-owned list a
viewer may read and an analyst may change.

What the endpoint refuses is the interesting part. A rule is a decision that hides
findings, so it is never inferred: no scope wider than the one asked for, no rule from a
finding that carries several values, and no rule at all unless the dismissal asked for
one.
"""

from __future__ import annotations

import unittest
from unittest import mock
from uuid import uuid4

from fastapi.testclient import TestClient

from backend import app as app_module, store
from backend.app import app
from backend.security import create_token, hash_password


def _headers(tenant: str = "default", role: str = "admin", subject: str = "admin") -> dict:
    return {"Authorization": f"Bearer {create_token(subject, role, tenant)}"}


def _finding(**overrides) -> dict:
    finding = {
        "id": "fnd-1",
        "type": "credit_card",
        "scan_id": "20260917010203",
        "secure_value_fingerprints": ["fp-1"],
        "file": {"name": "customers.csv", "path": r"C:\Data\Reports\customers.csv", "source": "local"},
    }
    finding.update(overrides)
    return finding


class TheRuleEndpointsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        self.made: list[tuple[str, str]] = []

    def tearDown(self) -> None:
        for tenant, rule_id in self.made:
            store.delete_suppression_rule(tenant, rule_id)

    def _create(self, tenant: str = "default", subject: str = "admin", **overrides) -> dict:
        payload = {"finding_type": "credit_card", "path_pattern": r"C:\Data\TestData\*", "reason": "synthetic data"}
        payload.update(overrides)
        response = self.client.post("/api/suppression-rules", json=payload,
                                    headers=_headers(tenant, subject=subject))
        self.assertEqual(response.status_code, 200, response.text)
        rule = response.json()["rule"]
        self.made.append((tenant, rule["rule_id"]))
        return rule

    def test_a_rule_is_written_listed_changed_and_removed(self) -> None:
        rule = self._create()
        self.assertEqual(rule["finding_type"], "credit_card")
        self.assertEqual(rule["created_by"], "admin")
        self.assertTrue(rule["active"])

        listed = self.client.get("/api/suppression-rules", headers=_headers()).json()["rules"]
        self.assertIn(rule["rule_id"], [item["rule_id"] for item in listed])

        changed = self.client.patch(f"/api/suppression-rules/{rule['rule_id']}",
                                    json={"active": False, "reason": "reviewed, keeping it off"},
                                    headers=_headers())
        self.assertEqual(changed.status_code, 200, changed.text)
        self.assertFalse(changed.json()["rule"]["active"])

        removed = self.client.delete(f"/api/suppression-rules/{rule['rule_id']}", headers=_headers())
        self.assertEqual(removed.status_code, 200, removed.text)
        self.assertEqual(self.client.delete(f"/api/suppression-rules/{rule['rule_id']}",
                                            headers=_headers()).status_code, 404)

    def test_a_rule_that_names_nothing_is_refused_with_a_reason(self) -> None:
        response = self.client.post("/api/suppression-rules", json={"reason": "everything"}, headers=_headers())
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("must name", response.json()["detail"])

    def test_a_viewer_reads_and_an_analyst_changes(self) -> None:
        rule = self._create()
        watcher = f"supv-{uuid4().hex[:6]}"
        store.create_user(watcher, hash_password("x9!Watcher-Kestrel"), "viewer", "default")
        self.addCleanup(store.delete_user, watcher)
        viewer = _headers(role="viewer", subject=watcher)

        self.assertEqual(self.client.get("/api/suppression-rules", headers=viewer).status_code, 200)
        self.assertEqual(self.client.post("/api/suppression-rules",
                                          json={"finding_type": "email", "reason": "no"},
                                          headers=viewer).status_code, 403)
        self.assertEqual(self.client.delete(f"/api/suppression-rules/{rule['rule_id']}",
                                            headers=viewer).status_code, 403)

    def test_one_tenant_never_sees_or_removes_another_tenants_rule(self) -> None:
        tenant = f"t{uuid4().hex[:8]}"
        store.create_tenant(tenant, "other")
        admin = f"supa-{uuid4().hex[:6]}"
        store.create_user(admin, hash_password("x9!Other-Kestrel"), "admin", tenant)
        self.addCleanup(store.delete_user, admin)
        rule = self._create()

        listed = self.client.get("/api/suppression-rules", headers=_headers(tenant, subject=admin)).json()["rules"]
        self.assertEqual(listed, [])
        gone = self.client.delete(f"/api/suppression-rules/{rule['rule_id']}",
                                  headers=_headers(tenant, subject=admin))
        self.assertEqual(gone.status_code, 404)
        self.assertIsNotNone(store.get_suppression_rule("default", rule["rule_id"]))


class ADismissalThatWritesTheRuleTest(unittest.TestCase):
    """The gate's first half: the analyst dismisses once, and says what else it applies to."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def setUp(self) -> None:
        self.made: list[str] = []

    def tearDown(self) -> None:
        for rule_id in self.made:
            store.delete_suppression_rule("default", rule_id)

    def _dismiss(self, body: dict, finding: dict | None = None):
        stored = finding or _finding()
        with mock.patch.object(app_module, "update_finding_lifecycle", return_value=dict(stored, status="FALSE_POSITIVE")), \
                mock.patch.object(app_module, "get_finding", return_value=stored):
            response = self.client.post("/api/findings/fnd-1/false-positive", json=body, headers=_headers())
        if response.status_code == 200 and "suppression_rule" in response.json():
            self.made.append(response.json()["suppression_rule"]["rule_id"])
        return response

    def test_a_dismissal_alone_writes_no_rule(self) -> None:
        response = self._dismiss({"comment": "test card"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("suppression_rule", response.json(), "a dismissal is about one finding until asked")

    def test_the_file_scope_covers_this_finding_in_this_file(self) -> None:
        response = self._dismiss({"suppress_future": True, "comment": "the test card number"})
        self.assertEqual(response.status_code, 200, response.text)
        rule = response.json()["suppression_rule"]
        self.assertEqual(rule["finding_type"], "credit_card")
        self.assertEqual(rule["path_pattern"], r"C:\Data\Reports\customers.csv")
        self.assertEqual(rule["source"], "local")
        self.assertEqual(rule["reason"], "the test card number")
        self.assertEqual(rule["source_finding_id"], "fnd-1")
        self.assertEqual(rule["source_scan_id"], "20260917010203")

    def test_the_folder_scope_covers_what_is_under_it(self) -> None:
        rule = self._dismiss({"suppress_future": True, "suppression_scope": "folder",
                              "comment": "a folder of test data"}).json()["suppression_rule"]
        self.assertEqual(rule["path_pattern"], "C:/Data/Reports/*")

    def test_the_type_scope_keeps_no_path_at_all(self) -> None:
        rule = self._dismiss({"suppress_future": True, "suppression_scope": "type",
                              "comment": "we do not hold cards"}).json()["suppression_rule"]
        self.assertEqual((rule["path_pattern"], rule["source"], rule["finding_type"]), ("", "", "credit_card"))

    def test_the_value_scope_needs_one_value(self) -> None:
        rule = self._dismiss({"suppress_future": True, "suppression_scope": "value",
                              "comment": "this number is a test vector"}).json()["suppression_rule"]
        self.assertEqual(rule["fingerprint"], "fp-1")

        several = _finding(secure_value_fingerprints=["fp-1", "fp-2"])
        refused = self._dismiss({"suppress_future": True, "suppression_scope": "value", "comment": "no"}, several)
        self.assertEqual(refused.status_code, 400, refused.text)
        self.assertIn("several values", refused.json()["detail"])

    def test_an_unknown_scope_is_refused(self) -> None:
        refused = self._dismiss({"suppress_future": True, "suppression_scope": "everything", "comment": "no"})
        self.assertEqual(refused.status_code, 400, refused.text)
        self.assertIn("Unsupported suppression scope", refused.json()["detail"])

    def test_a_dismissal_without_a_comment_still_records_why(self) -> None:
        rule = self._dismiss({"suppress_future": True}).json()["suppression_rule"]
        self.assertIn("admin", rule["reason"])

    def test_the_rule_is_in_the_audit_trail(self) -> None:
        rule = self._dismiss({"suppress_future": True, "comment": "the test card number"}).json()["suppression_rule"]
        recorded = [event for event in store.read_audit_log("default", limit=50)
                    if event.get("action") == "suppression.created"]
        self.assertTrue(recorded, "writing a rule that hides findings must be recorded")
        self.assertEqual(recorded[-1]["detail"]["rule_id"], rule["rule_id"])
        self.assertEqual(recorded[-1]["detail"]["scope"], "file")


if __name__ == "__main__":
    unittest.main()
