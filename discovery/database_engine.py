"""The discovery engine, reading a database's columns instead of a folder's files (D6).

Everything after collection is the engine's own - the detectors, the compliance mappings,
suppression, exact-data matching, risk and the report - so a column is judged exactly as a
file is. Only three things differ: the records come from collectors.database_scanner;
nothing is cached or reused between scans (a column's content is a sample, not a file with
a size and a modification time); and a column gets no preview - the sampled values are the
detectors' input, and only masked samples leave the scan, in the findings.
"""

from __future__ import annotations

from typing import Callable

from collectors import database_scanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig

NO_PREVIEW = {"available": False, "lines": [], "truncated": False,
              "reason": "Database columns are not previewed: the findings carry masked samples."}


class DatabaseDiscoveryEngine(DSPMDiscoveryEngine):

    def __init__(self, config: ScanConfig, source: database_scanner.DatabaseSource, *, connection=None) -> None:
        config.incremental_enabled = False
        config.persistent_cache_enabled = False
        config.walk_local_path = False
        super().__init__(config)
        self.source = source
        self._connection = connection

    def _collect_records(self, record_callback: Callable[[dict], None] | None = None) -> list[dict]:
        # The callback goes to the scanner, which hands on each table's columns as the table
        # is read - not every table's, after the last one.
        records, diagnostics = database_scanner.scan(self.source, connection=self._connection,
                                                     cancel_check=self._cancelled, record_callback=record_callback)
        self.last_scan_diagnostics = diagnostics
        return records

    def _analyze_record(self, record: dict) -> dict:
        result = super()._analyze_record(record)
        if result.get("source") == "database":
            result["preview"] = dict(NO_PREVIEW)
        return result
