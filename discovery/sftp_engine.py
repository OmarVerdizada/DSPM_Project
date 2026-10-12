"""The discovery engine, reading a Linux or macOS host over SFTP (D9).

The records come from collectors.sftp_scanner, which offers every file to the engine's
reuse before reading it - so a scan that stopped part-way is resumed by running it again:
what the last run analysed unchanged is not read twice.
"""

from __future__ import annotations

from collections.abc import Callable

from collectors import sftp_scanner
from collectors.smb_scanner import SMBScanner
from discovery.discovery_engine import DSPMDiscoveryEngine, ScanConfig


class SftpDiscoveryEngine(DSPMDiscoveryEngine):

    def __init__(self, config: ScanConfig, source: sftp_scanner.SftpSource) -> None:
        config.walk_local_path = False
        super().__init__(config)
        self.source = source
        if config.allowed_extensions and config.extension_filter_enabled:
            source.allowed_extensions = list(config.allowed_extensions)

    def _collect_records(self, record_callback: Callable[[dict], None] | None = None) -> list[dict]:
        records, diagnostics = sftp_scanner.scan(self.source, reuse_probe=self._reuse_probe,
                                                 read_text=SMBScanner._preview_content_from_bytes,
                                                 cancel_check=self._cancelled)
        self.last_scan_diagnostics = diagnostics
        if record_callback is not None:
            for record in records:
                record_callback(record)
        return records
