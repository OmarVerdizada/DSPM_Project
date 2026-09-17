"""B6: the decision an analyst makes once, kept where the next scan can read it.

A false positive was something the estate remembered and every scan re-made: the row
kept its status, and the next scan created the finding again for somebody to dismiss
again. A suppression rule is the decision itself - a finding type, a path or a prefix,
a source, or one salted value fingerprint - stored per tenant and applied when a scan
emits its findings.

Two rules the store enforces because nothing downstream can: a rule that names nothing
would suppress the estate, and a rule with no reason cannot be reviewed later.
"""

from __future__ import annotations

import os
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from backend import store
from discovery.suppression import compile_rules, normalized_path


def _rule(**overrides) -> dict:
    rule = {
        "rule_id": "sup_1",
        "finding_type": "",
        "source": "",
        "path_pattern": "",
        "fingerprint": "",
        "active": True,
        "expires_at": "",
    }
    rule.update(overrides)
    return rule


class TheMatcherTest(unittest.TestCase):
    """What a rule covers, and what it deliberately does not."""

    def _match(self, rules, *, finding_type="credit_card", source="local",
               path=r"C:\Data\customers.csv", fingerprints=("fp-1",), truncated=False) -> str:
        return compile_rules(rules).match(
            finding_type=finding_type, source=source, path=path,
            fingerprints=fingerprints, truncated=truncated,
        )

    def test_a_type_rule_covers_that_type_anywhere(self) -> None:
        rules = [_rule(finding_type="credit_card", reason="test data")]
        self.assertEqual(self._match(rules), "sup_1")
        self.assertEqual(self._match(rules, path=r"D:\Other\file.txt"), "sup_1")
        self.assertEqual(self._match(rules, finding_type="email"), "", "one rule covered another detector")

    def test_a_path_is_the_same_file_however_it_is_spelled(self) -> None:
        rules = [_rule(path_pattern=r"C:\Data\Customers.csv")]
        for spelling in (r"C:\Data\customers.csv", "c:/data/CUSTOMERS.csv", "C:/Data/customers.csv"):
            with self.subTest(spelling=spelling):
                self.assertEqual(self._match(rules, path=spelling), "sup_1")
        self.assertEqual(self._match(rules, path=r"C:\Data\customers.csv.bak"), "")

    def test_a_prefix_covers_what_is_under_it(self) -> None:
        rules = [_rule(path_pattern=r"C:\Data\TestData\*")]
        self.assertEqual(self._match(rules, path=r"C:\Data\TestData\deep\file.csv"), "sup_1")
        self.assertEqual(self._match(rules, path=r"C:\Data\TestData2\file.csv"), "",
                         "the folder next to it is not under it")

    def test_a_fingerprint_rule_covers_one_value_and_not_the_detector(self) -> None:
        rules = [_rule(finding_type="credit_card", fingerprint="fp-2")]
        self.assertEqual(self._match(rules, fingerprints=("fp-2",)), "sup_1")
        self.assertEqual(self._match(rules, fingerprints=("fp-1",)), "", "a different number was suppressed")

    def test_a_finding_stands_until_every_value_in_it_is_covered(self) -> None:
        """One finding carries every match in the file; dismissing one card is not dismissing ten."""
        one = _rule(rule_id="a", finding_type="credit_card", fingerprint="fp-1")
        two = _rule(rule_id="b", finding_type="credit_card", fingerprint="fp-2")
        self.assertEqual(self._match([one], fingerprints=("fp-1", "fp-2")), "",
                         "nine other card numbers went with the one that was dismissed")
        self.assertIn(self._match([one, two], fingerprints=("fp-1", "fp-2")), {"a", "b"})

    def test_a_truncated_finding_is_never_covered_by_value(self) -> None:
        """Fewer fingerprints than matches: what the rules cover is not what was found."""
        rules = [_rule(finding_type="credit_card", fingerprint="fp-1")]
        self.assertEqual(self._match(rules, fingerprints=("fp-1",), truncated=True), "")
        self.assertEqual(self._match(rules, fingerprints=("fp-1",)), "sup_1")

    def test_a_type_rule_still_covers_a_truncated_finding(self) -> None:
        rules = [_rule(finding_type="credit_card")]
        self.assertEqual(self._match(rules, fingerprints=("fp-1",), truncated=True), "sup_1")

    def test_a_source_rule_stays_on_its_own_collector(self) -> None:
        rules = [_rule(finding_type="email", source="endpoint-winrm")]
        self.assertEqual(self._match(rules, finding_type="email", source="endpoint-winrm"), "sup_1")
        self.assertEqual(self._match(rules, finding_type="email", source="smb"), "")

    def test_an_inactive_or_expired_rule_covers_nothing(self) -> None:
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        soon = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        self.assertEqual(self._match([_rule(finding_type="credit_card", active=False)]), "")
        self.assertEqual(self._match([_rule(finding_type="credit_card", expires_at=past)]), "")
        self.assertEqual(self._match([_rule(finding_type="credit_card", expires_at=soon)]), "sup_1")
        self.assertEqual(self._match([_rule(finding_type="credit_card", expires_at="whenever")]), "",
                         "a rule nobody can date must stop hiding findings, not hide them forever")

    def test_no_rules_is_no_work(self) -> None:
        matcher = compile_rules([])
        self.assertFalse(matcher)
        self.assertEqual(len(matcher), 0)
        self.assertEqual(matcher.match(finding_type="credit_card", source="local", path="x"), "")

    def test_the_digest_follows_the_rules_and_not_their_order(self) -> None:
        one = _rule(rule_id="a", finding_type="email")
        two = _rule(rule_id="b", path_pattern="c:/data/*")
        self.assertEqual(compile_rules([one, two]).digest, compile_rules([two, one]).digest)
        self.assertNotEqual(compile_rules([one]).digest, compile_rules([one, two]).digest)
        self.assertEqual(compile_rules([]).digest, "")

    def test_a_path_has_one_spelling(self) -> None:
        self.assertEqual(normalized_path(r"C:\Data\Test\\"), "c:/data/test")
        self.assertEqual(normalized_path(""), "")


class TheRuleStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._previous_path = store.DB_PATH
        store.DB_PATH = Path(self._dir.name) / "suppression.sqlite"
        self._env = mock.patch.dict(os.environ, {"DSPM_ARTIFACT_DIR": str(Path(self._dir.name) / "artifacts")})
        self._env.start()
        store.init_db()
        self.tenant = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(self.tenant, "suppression")

    def tearDown(self) -> None:
        self._env.stop()
        store.DB_PATH = self._previous_path
        self._dir.cleanup()

    def _create(self, **overrides) -> dict:
        payload = {"finding_type": "credit_card", "reason": "synthetic test data", "created_by": "ana"}
        payload.update(overrides)
        return store.create_suppression_rule(self.tenant, **payload)

    def test_a_rule_is_stored_and_listed(self) -> None:
        rule = self._create(path_pattern=r"C:\Data\TestData\*", source="LOCAL")
        self.assertTrue(rule["rule_id"].startswith("sup_"))
        self.assertEqual(rule["finding_type"], "credit_card")
        self.assertEqual(rule["source"], "local", "a source is stored the way it is matched")
        self.assertTrue(rule["active"])
        self.assertEqual([item["rule_id"] for item in store.list_suppression_rules(self.tenant)], [rule["rule_id"]])

    def test_a_rule_that_names_nothing_is_refused(self) -> None:
        with self.assertRaises(ValueError) as caught:
            store.create_suppression_rule(self.tenant, finding_type="", reason="everything")
        self.assertIn("must name", str(caught.exception))

    def test_a_rule_without_a_reason_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            store.create_suppression_rule(self.tenant, finding_type="email", reason="   ")

    def test_the_same_decision_twice_is_one_rule(self) -> None:
        first = self._create(path_pattern=r"C:\Data\one.csv")
        second = self._create(path_pattern=r"C:\Data\one.csv", reason="said again")
        self.assertEqual(first["rule_id"], second["rule_id"])
        self.assertEqual(len(store.list_suppression_rules(self.tenant)), 1)

    def test_a_rule_can_be_turned_off_but_not_repointed(self) -> None:
        rule = self._create()
        updated = store.update_suppression_rule(
            self.tenant, rule["rule_id"], {"active": False, "reason": "reviewed 2026-09", "finding_type": "email"},
        )
        self.assertFalse(updated["active"])
        self.assertEqual(updated["reason"], "reviewed 2026-09")
        self.assertEqual(updated["finding_type"], "credit_card", "a rule that matched something else is a new rule")
        self.assertEqual(store.list_suppression_rules(self.tenant, active_only=True), [])
        self.assertEqual(len(store.list_suppression_rules(self.tenant)), 1)

    def test_an_expiry_must_be_a_timestamp_and_is_kept_in_utc(self) -> None:
        rule = self._create(expires_at="2026-12-31T00:00:00+02:00")
        self.assertTrue(rule["expires_at"].endswith("+00:00"))
        with self.assertRaises(ValueError):
            self._create(finding_type="email", expires_at="next year")

    def test_a_deleted_rule_is_gone(self) -> None:
        rule = self._create()
        self.assertTrue(store.delete_suppression_rule(self.tenant, rule["rule_id"]))
        self.assertFalse(store.delete_suppression_rule(self.tenant, rule["rule_id"]))
        self.assertIsNone(store.get_suppression_rule(self.tenant, rule["rule_id"]))

    def test_one_tenant_cannot_read_or_change_another_tenants_rule(self) -> None:
        other = f"t{uuid.uuid4().hex[:8]}"
        store.create_tenant(other, "other")
        rule = self._create()
        self.assertEqual(store.list_suppression_rules(other), [])
        self.assertIsNone(store.get_suppression_rule(other, rule["rule_id"]))
        self.assertIsNone(store.update_suppression_rule(other, rule["rule_id"], {"active": False}))
        self.assertFalse(store.delete_suppression_rule(other, rule["rule_id"]))
        self.assertTrue(store.get_suppression_rule(self.tenant, rule["rule_id"])["active"])

    def test_a_tenant_may_not_hold_an_unbounded_number_of_rules(self) -> None:
        with mock.patch.object(store, "MAX_SUPPRESSION_RULES", 2):
            self._create(path_pattern="a.csv")
            self._create(path_pattern="b.csv")
            with self.assertRaises(ValueError) as caught:
                self._create(path_pattern="c.csv")
        self.assertIn("at most", str(caught.exception))

    def test_a_scan_reads_the_active_rules_and_survives_a_table_it_cannot_read(self) -> None:
        active = self._create(path_pattern="a.csv")
        off = self._create(path_pattern="b.csv")
        store.update_suppression_rule(self.tenant, off["rule_id"], {"active": False})
        self.assertEqual(
            [item["rule_id"] for item in store.suppression_rules_for_scan(self.tenant)],
            [active["rule_id"]],
        )
        with mock.patch.object(store, "list_suppression_rules", side_effect=RuntimeError("no table")):
            self.assertEqual(store.suppression_rules_for_scan(self.tenant), [],
                             "a scan reports everything it finds when it cannot read the rules")

    def test_erasing_a_tenant_takes_its_rules(self) -> None:
        self._create()
        store.delete_tenant_with_data(self.tenant)
        self.assertEqual(store.list_suppression_rules(self.tenant), [])


if __name__ == "__main__":
    unittest.main()
