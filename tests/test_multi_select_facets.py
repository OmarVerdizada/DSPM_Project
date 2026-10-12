"""Round K: several answers per facet, applied when the operator asks.

Five things the console got wrong, and the contract that keeps them fixed:

1. Top risks looked pinned at three rows while Top data classes sized itself
   to the window. The capacity was never the difference.
2. "Email" and "Email address" were listed as two data classes of 423 files.
3. The Compliance frameworks card still named a framework the product removed.
4. The queue could not be ordered by the columns it showed.
5. Every facet was one answer, and every answer refetched the table.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend import db, store  # noqa: E402

APP_JS = Path("frontend/app.js").read_text(encoding="utf-8")
INDEX = Path("frontend/index.html").read_text(encoding="utf-8")
SHELL_CSS = Path("frontend/styles/shell.css").read_text(encoding="utf-8")
STORE = Path("backend/store.py").read_text(encoding="utf-8")


def _file(name, level, findings, protected=False):
    return {
        "path": f"/share/{name}", "name": name, "extension": ".txt", "size": 10,
        "owner": "ops", "modified_at": "2026-06-01T00:00:00+00:00",
        "risk": {"level": level, "score": {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40}.get(level, 10)},
        "findings": [{"type": value, "framework": "GDPR"} for value in findings],
        "protected": protected,
    }


class SeededStore(unittest.TestCase):
    """Three critical files, two high, and one locked one that is also HIGH -
    enough to tell a union from an intersection.

    Both spellings of the email class are present, on files that also carry the
    generic one, because that is how the estate stores them: `gdpr_email_address`
    never fires without the content detector firing too."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls._orig = store.DB_PATH
        store.DB_PATH = Path(cls._tmp.name) / "facets.sqlite"
        store.init_db()
        cls._seed()

    def setUp(self) -> None:
        # On PostgreSQL the suite has one database and empties it before every test.
        if db.is_postgres():
            type(self)._seed()

    @classmethod
    def _seed(cls) -> None:
        cls.tid = f"t-{uuid4().hex[:8]}"
        store.create_tenant(cls.tid, "FACETS")
        files = [
            _file("a.txt", "CRITICAL", ["Email", "Email address"]),
            _file("b.txt", "CRITICAL", ["Email"]),
            _file("c.txt", "CRITICAL", ["Credit card"]),
            _file("d.txt", "HIGH", ["Email", "Email address"]),
            _file("e.txt", "HIGH", ["Phone number"]),
            _file("locked.txt", "HIGH", [], protected=True),
        ]
        store.save_scan_history(cls.tid, {"scan_id": "s1", "source": "local", "summary": {}, "files": files})

    @classmethod
    def tearDownClass(cls) -> None:
        store.DB_PATH = cls._orig
        cls._tmp.cleanup()

    def total(self, **kwargs) -> int:
        return store.list_inventory(self.tid, limit=1, **kwargs)["total"]


class DataClassIdentityTests(unittest.TestCase):
    """One data class, one name - and only where they are the same class."""

    def test_only_identical_classes_are_merged(self) -> None:
        # The generic content detector calls an address "Email"; the GDPR
        # catalogue's gdpr_email_address calls it "Email address". Both resolve
        # to the canonical entity EMAIL_ADDRESS.
        self.assertEqual(store.canonical_finding_type("Email address"), "Email")
        self.assertEqual(store.canonical_finding_type("email address"), "Email")
        self.assertEqual(store.canonical_finding_type("Email"), "Email")
        # Similar is not the same. gdpr_api_token_oauth_secret covers OAuth
        # secrets and service tokens the generic api_key detector does not, and
        # their canonical types differ, so they stay two classes.
        for value in ("API key", "Confidential keyword", "Phone number"):
            with self.subTest(value=value):
                self.assertEqual(store.canonical_finding_type(value), value)
        self.assertLessEqual(len(store.FINDING_TYPE_ALIASES), 3,
                             "the bar for merging two data classes is that they denote the same entity")

    def test_the_alias_group_is_symmetric(self) -> None:
        self.assertEqual(store.finding_type_alias_group("Email"), ["Email", "email address"])
        self.assertEqual(store.finding_type_alias_group("Email address"), ["Email", "email address"])


class MergedClassCountTests(SeededStore):
    def test_either_spelling_asks_the_same_question(self) -> None:
        self.assertEqual(self.total(finding_type="Email"), 3)
        self.assertEqual(self.total(finding_type="Email address"), 3)

    def test_the_merged_row_counts_files_once(self) -> None:
        """Counts are files, and every file carrying "Email address" also
        carries "Email" - so the merged total is the larger of the two, never
        their sum. Summing them would report five files where three exist."""
        facets = store.inventory_facets(self.tid)
        rows = {str(item["value"]): int(item.get("file_count") or item.get("count") or 0)
                for item in facets.get("finding_types", [])}
        self.assertIn("Email", rows)
        self.assertNotIn("Email address", rows)
        self.assertEqual(rows["Email"], 3)


class RemovedFrameworkTests(unittest.TestCase):
    def test_the_catalogue_name_is_the_one_the_product_uses(self) -> None:
        self.assertIn('nist_sp800_60_enterprise: { label: "NIST"', APP_JS)
        self.assertNotIn("NIST SP 800-60", APP_JS)


class TopRisksCapacityTests(unittest.TestCase):
    """The list was never limited to three by its capacity."""

    def test_top_risks_size_themselves_like_top_data_classes(self) -> None:
        """One helper measures both lists against the room their card has,
        so neither can drift from the other."""
        self.assertIn("function dashListCapacity(", APP_JS)
        self.assertIn('dashListCapacity("#posture-card"', APP_JS)
        self.assertIn('dashListCapacity("#data-classes-card"', APP_JS)

    def test_a_credential_is_recognised_by_its_name_alone(self) -> None:
        """A finding on an inventory page carries {type, count, framework,
        frameworks, description} and no category at all, so a predicate reading
        data_category could never fire. "Exposed credentials" sat at zero while
        the estate held 852 of them."""
        self.assertIn("const SECRET_FINDING_NAMES = new Set([", APP_JS)
        predicate = APP_JS[APP_JS.index("function isSecretFinding("):]
        predicate = predicate[:predicate.index(chr(10) + "}" + chr(10))]
        self.assertIn("SECRET_FINDING_NAMES.has(", predicate)
        self.assertIn("findingDisplayName(finding)", predicate)


class QueueSortTests(unittest.TestCase):
    def test_every_column_the_queue_shows_can_order_it(self) -> None:
        for key in ("category", "data_type", "asset", "owner"):
            with self.subTest(key=key):
                self.assertIn(key, store.REMEDIATION_SORTS)
                self.assertIn(f'"{key}"', APP_JS)
        # The Category column falls back to the data type when a finding has
        # no category, and the order has to follow what the cell shows.
        # Restated for W4.4 (section 25): the same fallback, written as a CASE so an index can
        # seek it under row-level security.
        self.assertEqual(store.REMEDIATION_SORTS["category"][0],
                         "CASE WHEN category IS NULL OR category = '' THEN CASE WHEN data_type IS NULL THEN '' "
                         "ELSE data_type END ELSE category END")
        squeezed = re.sub(r"\s+", "", APP_JS)
        for key, label in (("category", "Category"), ("data_type", "Datatype"),
                           ("asset", "Affectedasset"), ("owner", "Owner")):
            with self.subTest(column=label):
                self.assertIn(f'remediationHeadCell("{key}","{label}"', squeezed)

    def test_a_text_column_starts_at_a(self) -> None:
        self.assertIn("const REMEDIATION_SORT_ASC_FIRST = new Set([", APP_JS)
        for key in ("category", "data_type", "asset", "owner", "finding_name"):
            with self.subTest(key=key):
                block = APP_JS[APP_JS.index("const REMEDIATION_SORT_ASC_FIRST"):]
                self.assertIn(f'"{key}"', block[:block.index("]);")])

    def test_the_cursor_knows_the_column_behind_each_key(self) -> None:
        """`asset` and `finding_name` are the client's names for columns the
        table calls something else; a cursor built on the client's name would
        page from a column that does not exist. Since the cursor fix (b05e5a6)
        it is built from the value the rows are ordered by - the sort expression,
        selected as `sort_value` - so no name has to be mapped to a column."""
        spec = STORE[STORE.index("REMEDIATION_SORTS: dict"):]
        spec = spec[:spec.index(chr(10) + "}")]
        self.assertIn('"asset": ("CASE WHEN affected_asset IS NULL', spec)  # W4.4: CASE, not COALESCE
        self.assertIn('"finding_name": ("CASE WHEN display_name IS NULL', spec)
        self.assertIn("AS sort_value FROM findings", STORE)
        self.assertIn('last["sort_value"]', STORE)


class FilterSplitterTests(unittest.TestCase):
    def test_the_splitter_drops_blanks_and_caps_the_list(self) -> None:
        self.assertEqual(store.filter_values("CRITICAL, high ,,ALL,critical", upper=True), ["CRITICAL", "HIGH"])
        self.assertEqual(store.filter_values(""), [])
        self.assertEqual(store.filter_values(["a", "b", "a"]), ["a", "b"])
        self.assertEqual(len(store.filter_values(",".join(str(n) for n in range(200)))), 40)

    def test_status_groups_union_and_all_means_no_filter(self) -> None:
        self.assertEqual(store.remediation_statuses(""), ())
        self.assertEqual(store.remediation_statuses("all"), ())
        self.assertEqual(store.remediation_statuses("open,all"), (),
                         "a set that contains everything is not a filter")
        merged = store.remediation_statuses("open,in_progress")
        self.assertEqual(set(merged),
                         set(store.remediation_statuses("open")) | set(store.remediation_statuses("in_progress")))
        self.assertEqual(len(merged), len(set(merged)), "a status appears once however many groups name it")


class MultiValueFilterTests(SeededStore):
    """A facet that takes several answers asks for their union, not for none."""

    def test_selecting_two_severities_returns_both(self) -> None:
        self.assertEqual(self.total(risk="CRITICAL"), 3)
        self.assertEqual(self.total(risk="HIGH"), 3)
        self.assertEqual(self.total(risk="CRITICAL,HIGH"), 6)
        # A repeated tick cannot multiply the clauses.
        self.assertEqual(self.total(risk="CRITICAL,CRITICAL"), 3)

    def test_two_data_classes_mean_either(self) -> None:
        self.assertEqual(self.total(finding_type="Email"), 3)
        self.assertEqual(self.total(finding_type="Credit card"), 1)
        self.assertEqual(self.total(finding_type="Email,Credit card"), 4)

    def test_protected_joins_the_facet_it_was_ticked_in(self) -> None:
        """"Protected" in the Severity list and "Protected / locked" in the
        Finding type list are the same stored flag wearing a costume. A single
        select could translate either into `protected=true`; a multi-select
        cannot, because "Critical or Protected" is an OR and an AND on the flag
        answers with almost nothing."""
        self.assertEqual(self.total(risk="PROTECTED"), 1)
        # The locked file is HIGH, so an AND on the flag would have answered
        # with one row where the operator asked for four.
        self.assertEqual(self.total(risk="CRITICAL,PROTECTED"), 4)
        self.assertEqual(self.total(finding_type="Protected / locked"), 1)
        self.assertEqual(self.total(finding_type="Email,Protected / locked"), 4)
        # The standalone parameter keeps its own AND meaning for the callers
        # that pass it directly.
        self.assertEqual(self.total(risk="CRITICAL", protected=True), 0)
        self.assertEqual(self.total(risk="HIGH", protected=True), 1)


class DeferredSearchTests(unittest.TestCase):
    """Ticking a facet used to refetch the table. Three facets cost three
    round trips and two thrown-away renders; now they cost one."""

    def test_both_pages_have_a_search_button(self) -> None:
        self.assertIn('id="inventory-apply-filters" class="facet-apply"', INDEX)
        self.assertIn('id="remediation-apply-filters" class="facet-apply"', INDEX)
        self.assertIn(".facet-apply {", SHELL_CSS)
        self.assertIn("inventoryApplyFiltersBtn?.addEventListener", APP_JS)
        self.assertIn("remediationApplyFiltersBtn?.addEventListener", APP_JS)

    def test_nothing_reloads_on_a_facet_change(self) -> None:
        for gone in (
            'inventorySourceFilter?.addEventListener("change"',
            'inventoryFindingFilter?.addEventListener("change"',
            'inventoryRiskSelect?.addEventListener("change"',
            'inventoryFrameworkSelect?.addEventListener("change"',
            'remediationFilters?.addEventListener("change"',
        ):
            with self.subTest(listener=gone):
                self.assertNotIn(gone, APP_JS)
        # Scope is the exception: it changes which rows exist, not which of
        # the loaded ones are shown.
        self.assertIn('remediationScopeFilter?.addEventListener("change"', APP_JS)

    def test_pending_and_applied_are_separate(self) -> None:
        self.assertIn("const facetPending = new Map();", APP_JS)
        self.assertIn("const facetApplied = new Map();", APP_JS)
        # The query builders read only what was searched for.
        self.assertIn('params.set("risk", [...inventoryRiskFacets].join(","))', APP_JS)
        self.assertIn("const value = facetAppliedParam(id);", APP_JS)
        # And the button says when there is something unpressed.
        self.assertIn("function facetGroupDirty(group)", APP_JS)
        self.assertIn(".facet-apply[data-facet-dirty]", SHELL_CSS)

    def test_the_two_facets_that_stay_single_stay_single(self) -> None:
        """Scope is exclusive by nature. Folder has no parameter of its own -
        it drives the free-text search, which takes one string."""
        block = APP_JS[APP_JS.index("const FACET_SINGLE_IDS"):]
        block = block[:block.index("]);")]
        self.assertIn('"inventory-folder-filter"', block)
        self.assertIn('"remediation-scope-filter"', block)
        for multi in ("inventory-risk-filter", "remediation-status-filter", "remediation-sla-filter"):
            with self.subTest(id=multi):
                self.assertNotIn(f'"{multi}"', block)

    def test_a_dashboard_card_still_searches_at_once(self) -> None:
        """The operator asked for that filter by clicking it."""
        jump = APP_JS[APP_JS.index("function applyInventoryRisk("):]
        jump = jump[:jump.index(chr(10) + "}" + chr(10))]
        self.assertIn('setFacetSelection("inventory-risk-filter"', jump)
        self.assertIn("applyFindingsFacets()", jump)
        opener = APP_JS[APP_JS.index("function openRemediationFiltered("):]
        opener = opener[:opener.index(chr(10) + "}" + chr(10))]
        self.assertIn("setFacetSelection(id, [value])", opener)
        self.assertIn("applyRemediationFacets()", opener)

    def test_the_control_keeps_drawing_itself(self) -> None:
        """The <select> stays: it is where a dozen renderers write their option
        lists, and it draws the leading glyph, the caret and the ellipsis. Only
        its input is taken away."""
        self.assertIn('const FACET_SUMMARY_VALUE = "__facet_summary__";', APP_JS)
        self.assertIn('trigger.className = "facet-trigger plain-btn";', APP_JS)
        self.assertIn("select[data-facet-multi]", SHELL_CSS)
        self.assertIn("pointer-events: none;", SHELL_CSS)
        # Every one of those lists is rebuilt with innerHTML by its own
        # renderer, which takes the summary option with it.
        self.assertIn("new MutationObserver(() => {", APP_JS)
        self.assertIn("function facetKeepChosen(select, values", APP_JS)


if __name__ == "__main__":
    unittest.main()
