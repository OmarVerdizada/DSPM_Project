"""C9: the Word and Excel reports are real Office files, built and recorded on the server.

They were HTML with a .doc or .xls name, built in the browser: Office warned that the file
did not match its extension, Excel re-parsed every cell - so a scanned file named
`=HYPERLINK(...)` was a live formula unless the page remembered to quote it - and the
server never saw what left. These tests read the packages back as Office would: the ZIP,
its content types and relationships, and the XML of every part.

Gate lines this pins: formula fixtures are inert; Azerbaijani characters round-trip in
Office; masking is the PDF's own; the export is permitted and audited through C3/C4.
Whether the files open in the target Office suite is checked by a person with the sample
files (tmp/c9-samples), not here.
"""

from __future__ import annotations

import io
import re
import tempfile
import unittest
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from fastapi.testclient import TestClient

from backend import security, store
from backend.app import app
from backend.reporting.office import render_docx, render_xlsx

PAN = "4111111111111111"
AZ = "müştəri_siyahısı.xlsx"
RU = "отчет_2026.csv"
FORMULAS = ['=HYPERLINK("http://example.test/x","click")', "+cmd|' /C calc'!A0", "-2+3", "@SUM(1,2)",
            "\t=1+1", "\r=1+1"]
NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
      "r": "http://schemas.openxmlformats.org/package/2006/relationships",
      "ct": "http://schemas.openxmlformats.org/package/2006/content-types"}


def _report() -> dict:
    return {
        "title": "Executive report",
        "lines": ["This scan · All severities", "Tenant default", "12 findings in scope"],
        "blocks": [
            {"label": "Posture", "table": {"headers": ["Measure", "Value"], "rows": [
                ["Files analysed", "1,204"], ["Share with owners", "82%"], ["Average score", "61.5"],
                ["Asset tag", "0042"], ["Reference", "12345678901234567890"], ["Raw count", 7]]}},
            {"label": "Findings register", "table": {
                "headers": ["Severity", "Finding", "File", "Owner", "Score"],
                "rows": [["Critical", "Payment card", AZ, "CORP\\ə.məmmədov", 94],
                         ["High", "Personal data", RU, "CORP\\i.petrov", 71],
                         ["Medium", "Card in a name", f"refund_{PAN}.csv", "", 55]]
                + [["Low", "Formula fixture", value, "attacker", 10] for value in FORMULAS]},
             "notes": ["No row in this scope carried Due, so that column is not printed."]},
            {"label": "Detailed findings", "detail": [{
                "finding": "Payment card", "severity": "Critical", "status": "Open", "file": f"\\\\fs01\\{AZ}",
                "data_class": "Payment card", "owner": "CORP\\ə.məmmədov", "frameworks": "PCI DSS", "score": "94",
                "occurrences": "12", "due": "", "reason": f"Kart nömrələri: card {PAN}",
                "recommendation": "=cmd() restrict the share"}]},
            {"label": "About", "paragraphs": ["Şəxsi məlumatlar.", "Bad \x00control\x1f chars are dropped."]},
        ],
    }


def _parts(data: bytes) -> dict[str, ElementTree.Element]:
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        names = package.namelist()
        return {name: ElementTree.fromstring(package.read(name)) for name in names if name.endswith((".xml", ".rels"))}


class _PackageChecks:
    """What any OOXML reader requires before it looks at the content."""

    def assert_package(self, data: bytes, main: str) -> dict[str, ElementTree.Element]:
        self.assertTrue(data.startswith(b"PK"))
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            self.assertIsNone(package.testzip())
            names = set(package.namelist())
            self.assertEqual(package.namelist()[0], "[Content_Types].xml")
        parts = _parts(data)  # every part parses as XML
        types = parts["[Content_Types].xml"]
        overrides = {item.get("PartName").lstrip("/") for item in types.findall("ct:Override", NS)}
        self.assertIn(main, overrides)
        for part in overrides:
            with self.subTest(override=part):
                self.assertIn(part, names, "a content type names a part the package lacks")
        for rels_name, rels in parts.items():
            if not rels_name.endswith(".rels"):
                continue
            base = rels_name.replace("_rels/", "").removesuffix(".rels")
            folder = base.rsplit("/", 1)[0] + "/" if "/" in base else ""
            for rel in rels.findall("r:Relationship", NS):
                target = rel.get("Target")
                with self.subTest(rels=rels_name, target=target):
                    self.assertIn((folder + target).lstrip("/"), names, "a relationship points at nothing")
        return parts


class TheWorkbookTest(_PackageChecks, unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.data, cls.stats = render_xlsx(_report())
        cls.parts = _parts(cls.data)

    def _sheet(self, name_prefix: str) -> ElementTree.Element:
        workbook = self.parts["xl/workbook.xml"]
        names = [sheet.get("name") for sheet in workbook.findall("s:sheets/s:sheet", NS)]
        index = next(i for i, name in enumerate(names, start=1) if name.startswith(name_prefix))
        return self.parts[f"xl/worksheets/sheet{index}.xml"]

    def _cells(self, sheet: ElementTree.Element) -> dict[str, ElementTree.Element]:
        return {cell.get("r"): cell for cell in sheet.iter(f"{{{NS['s']}}}c")}

    @staticmethod
    def _text(cell: ElementTree.Element) -> str:
        return "".join(node.text or "" for node in cell.iter(f"{{{NS['s']}}}t"))

    def test_it_is_a_well_formed_workbook_with_a_sheet_per_section(self) -> None:
        self.assert_package(self.data, "xl/workbook.xml")
        names = [sheet.get("name") for sheet in self.parts["xl/workbook.xml"].findall("s:sheets/s:sheet", NS)]
        self.assertEqual(names, ["Summary", "1. Posture", "2. Findings register", "3. Detailed findings", "4. About"])
        self.assertEqual(self.stats["sections"], 4)

    def test_no_cell_is_a_formula_and_every_formula_fixture_is_quoted_text(self) -> None:
        for part in self.parts.values():
            self.assertFalse(list(part.iter(f"{{{NS['s']}}}f")), "a workbook part holds a formula")
        styles = self.parts["xl/styles.xml"].findall("s:cellXfs/s:xf", NS)
        quoted = {str(index) for index, xf in enumerate(styles) if xf.get("quotePrefix") == "1"}
        cells = self._cells(self._sheet("2."))
        fixtures = {self._text(cell): cell for cell in cells.values() if self._text(cell) in FORMULAS}
        self.assertEqual(set(fixtures), set(FORMULAS), "every fixture is present, verbatim")
        for text, cell in fixtures.items():
            with self.subTest(fixture=text):
                self.assertEqual(cell.get("t"), "inlineStr")
                self.assertIn(cell.get("s"), quoted, "editing the cell must keep it text")

    def test_a_figure_is_a_number_and_an_identifier_stays_text(self) -> None:
        cells = self._cells(self._sheet("1."))
        values = {ref: (cell.get("t"), cell.findtext("s:v", namespaces=NS), self._text(cell)) for ref, cell in cells.items()}
        self.assertEqual(values["B2"][:2], (None, "1204"))
        self.assertEqual(values["B3"][:2], (None, "0.82"))
        self.assertEqual(values["B4"][:2], (None, "61.5"))
        self.assertEqual(values["B5"], ("inlineStr", None, "0042"))
        self.assertEqual(values["B6"], ("inlineStr", None, "12345678901234567890"))
        self.assertEqual(values["B7"][:2], (None, "7"))

    def test_azerbaijani_and_cyrillic_round_trip(self) -> None:
        texts = [self._text(cell) for cell in self._cells(self._sheet("2.")).values()]
        self.assertIn(AZ, texts)
        self.assertIn(RU, texts)
        self.assertIn("CORP\\ə.məmmədov", texts)

    def test_card_numbers_are_masked_wherever_they_arrive(self) -> None:
        with zipfile.ZipFile(io.BytesIO(self.data)) as package:  # the parts, not the compressed bytes
            raw = b"".join(package.read(name) for name in package.namelist())
        self.assertNotIn(PAN.encode(), raw)
        self.assertIn("refund_411111******1111.csv".encode(), raw)
        self.assertEqual(self.stats["masked_values"], 2)

    def test_a_table_filters_and_keeps_its_header_in_view(self) -> None:
        sheet = self._sheet("2.")
        self.assertEqual(sheet.find("s:autoFilter", NS).get("ref"), "A1:E10")
        pane = sheet.find("s:sheetViews/s:sheetView/s:pane", NS)
        self.assertEqual((pane.get("ySplit"), pane.get("state")), ("1", "frozen"))
        defined = self.parts["xl/workbook.xml"].findall("s:definedNames/s:definedName", NS)
        self.assertIn("'2. Findings register'!$A$1:$E$10", [item.text for item in defined])

    def test_characters_xml_cannot_carry_are_dropped(self) -> None:
        texts = [self._text(cell) for cell in self._cells(self._sheet("4.")).values()]
        self.assertIn("Bad control chars are dropped.", texts)


class SheetNamesTest(unittest.TestCase):

    def test_names_are_legal_unique_and_short(self) -> None:
        blocks = [{"label": label, "paragraphs": ["x"]} for label in
                  ("a/b:c*d?e[f]g\\h" * 3, "History", "Same", "Same", "'quoted'")]
        data, _stats = render_xlsx({"title": "t", "blocks": blocks})
        workbook = _parts(data)["xl/workbook.xml"]
        names = [sheet.get("name") for sheet in workbook.findall("s:sheets/s:sheet", NS)]
        self.assertEqual(len({name.lower() for name in names}), len(names))
        for name in names:
            with self.subTest(name=name):
                self.assertLessEqual(len(name), 31)
                self.assertIsNone(re.search(r"[\[\]:*?/\\]", name))
                self.assertFalse(name.startswith("'") or name.endswith("'"))
                self.assertNotEqual(name.lower(), "history")


class TheDocumentTest(_PackageChecks, unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.data, cls.stats = render_docx(_report())
        cls.parts = _parts(cls.data)
        body = cls.parts["word/document.xml"]
        cls.text = "".join(node.text or "" for node in body.iter(f"{{{NS['w']}}}t"))

    def test_it_is_a_well_formed_document(self) -> None:
        self.assert_package(self.data, "word/document.xml")
        styles = {style.get(f"{{{NS['w']}}}styleId") for style in self.parts["word/styles.xml"].iter(f"{{{NS['w']}}}style")}
        used = {node.get(f"{{{NS['w']}}}val") for node in self.parts["word/document.xml"].iter(f"{{{NS['w']}}}pStyle")}
        used |= {node.get(f"{{{NS['w']}}}val") for node in self.parts["word/document.xml"].iter(f"{{{NS['w']}}}tblStyle")}
        self.assertLessEqual(used, styles, "every style the body names is defined")

    def test_sections_are_headings_and_tables_repeat_their_header(self) -> None:
        body = self.parts["word/document.xml"]
        headings = ["".join(t.text or "" for t in p.iter(f"{{{NS['w']}}}t")) for p in body.iter(f"{{{NS['w']}}}p")
                    if any(s.get(f"{{{NS['w']}}}val") == "Heading1" for s in p.iter(f"{{{NS['w']}}}pStyle"))]
        self.assertEqual(headings, ["1. Posture", "2. Findings register", "3. Detailed findings", "4. About"])
        tables = list(body.iter(f"{{{NS['w']}}}tbl"))
        self.assertEqual(len(tables), 2)
        for table in tables:
            first_row = table.find("w:tr", NS)
            self.assertIsNotNone(first_row.find("w:trPr/w:tblHeader", NS))

    def test_unicode_round_trips_and_card_numbers_are_masked(self) -> None:
        for expected in (AZ, RU, "CORP\\ə.məmmədov", "Şəxsi məlumatlar.", "refund_411111******1111.csv",
                         "card 411111******1111"):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.text)
        self.assertNotIn(PAN, self.text)
        self.assertEqual(self.stats["masked_values"], 2)

    def test_the_document_names_itself(self) -> None:
        core = self.parts["docProps/core.xml"]
        self.assertEqual(core.findtext("{http://purl.org/dc/elements/1.1/}title"), "Executive report")
        self.assertEqual(core.findtext("{http://purl.org/dc/elements/1.1/}creator"), "SENTRO DSPM")


class TheExportRouteTest(unittest.TestCase):
    """Permitted by report.create, recorded with its shape and never its content (C3/C4)."""

    TENANT = "tenant-office"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp_dir.cleanup)
        original = store.DB_PATH
        store.DB_PATH = Path(self.temp_dir.name) / "office.sqlite"
        self.addCleanup(lambda: setattr(store, "DB_PATH", original))
        store.init_db()
        store.create_tenant(self.TENANT, "Office")
        for username, role in (("office-analyst", "analyst"), ("office-viewer", "viewer")):
            store.create_user(username, security.hash_password(f"{username}-pw-1"), role, self.TENANT)
        self.client = TestClient(app)

    def _headers(self, username: str, role: str) -> dict:
        return {"Authorization": f"Bearer {security.create_token(username, role, self.TENANT)}",
                "X-Tenant-ID": self.TENANT}

    def _export(self, fmt: str, username: str = "office-analyst", role: str = "analyst", **extra):
        payload = {"format": fmt, "report_type": "Executive", "scan_id": "scan-9",
                   "filename": "sentro_executive_2026-09-28", **_report(), **extra}
        return self.client.post("/api/v1/reports/office", headers=self._headers(username, role), json=payload)

    def test_each_format_comes_back_as_its_own_file_type(self) -> None:
        for fmt, media, main in (
                ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "word/document.xml"),
                ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xl/workbook.xml")):
            with self.subTest(fmt=fmt):
                response = self._export(fmt)
                self.assertEqual(response.status_code, 200, response.text[:300])
                self.assertEqual(response.headers["content-type"], media)
                self.assertEqual(response.headers["content-disposition"],
                                 f'attachment; filename="sentro_executive_2026-09-28.{fmt}"')
                self.assertEqual(response.headers.get("cache-control"), "no-store")
                self.assertIn(main, zipfile.ZipFile(io.BytesIO(response.content)).namelist())

    def test_a_viewer_is_refused_and_nothing_is_recorded(self) -> None:
        response = self._export("xlsx", "office-viewer", "viewer")
        self.assertEqual(response.status_code, 403)
        self.assertFalse([e for e in store.read_audit_log(self.TENANT, 50) if e["action"] == "report.exported"])

    def test_the_export_is_recorded_with_its_shape_and_no_content(self) -> None:
        self.assertEqual(self._export("xlsx").status_code, 200)
        events = [e for e in store.read_audit_log(self.TENANT, 50) if e["action"] == "report.exported"]
        self.assertEqual(len(events), 1)
        detail = events[0]["detail"]
        self.assertEqual({key: detail[key] for key in ("format", "report_type", "scan_id", "sections", "rows",
                                                       "masked_values")},
                         {"format": "xlsx", "report_type": "Executive", "scan_id": "scan-9", "sections": 4,
                          "rows": 16, "masked_values": 2})
        self.assertGreater(detail["bytes"], 0)
        recorded = repr(events[0])
        for secret in (PAN, "411111", AZ, "HYPERLINK"):
            self.assertNotIn(secret, recorded, "the audit trail records the export, not what it held")

    def test_a_hostile_file_name_cannot_steer_the_download(self) -> None:
        response = self._export("docx", filename='../../x"; filename*=UTF-8\'\'evil.exe')
        self.assertEqual(response.status_code, 200)
        disposition = response.headers["content-disposition"]
        self.assertRegex(disposition, r'^attachment; filename="[A-Za-z0-9_.-]+\.docx"$')

    def test_a_format_that_is_not_one_is_refused(self) -> None:
        # The app answers every request-validation failure with 400.
        self.assertEqual(self._export("xls").status_code, 400)
        self.assertEqual(self._export("docm").status_code, 400)

    def test_an_oversized_report_is_refused_before_it_is_built(self) -> None:
        wide = [{"label": f"S{index}", "table": {"headers": ["a"] * 40, "rows": [["1"] * 40] * 1000}}
                for index in range(11)]
        response = self._export("xlsx", blocks=wide)
        self.assertEqual(response.status_code, 413)
        self.assertIn("at most 400,000", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
