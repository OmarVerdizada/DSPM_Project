"""The discovery engine, reading a SharePoint site through Graph instead of a share (D5).

Everything after collection is the engine's own. What is Graph's: the records come from
collectors.graph_scanner, which rebuilds the site's libraries from the last checkpoint
plus Graph's changes and offers every unchanged file to the engine's reuse - so an
incremental scan reads only what changed, and a deleted file is simply not in the scan.
The checkpoint to keep is left on the engine for the caller to save once the scan's
report is stored: a scan that fails does not move it.
"""

from __future__ import annotations

from collections.abc import Callable

from collectors import graph_scanner
from collectors.smb_scanner import SMBScanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class GraphDiscoveryEngine(DSPMDiscoveryEngine):

    def __init__(self, config: ScanConfig, source: graph_scanner.GraphSource, checkpoint: dict | None) -> None:
        config.use_sample_when_empty = False
        super().__init__(config)
        self.source = source
        self.checkpoint = checkpoint
        self.next_checkpoint: dict | None = None
        if config.allowed_extensions and config.extension_filter_enabled:
            source.allowed_extensions = list(config.allowed_extensions)

    def _collect_records(self, record_callback: Callable[[dict], None] | None = None) -> list[dict]:
        records, kept, diagnostics = graph_scanner.scan(
            self.source, self.checkpoint, reuse_probe=self._reuse_probe,
            read_text=SMBScanner._preview_content_from_bytes)
        self.next_checkpoint = kept
        self.last_scan_diagnostics = diagnostics
        if record_callback is not None:
            for record in records:
                record_callback(record)
        return records
