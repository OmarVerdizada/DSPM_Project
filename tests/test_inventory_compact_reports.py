"""Track S-E compact report/job payload contracts."""

from backend.app import _compact_scan_report
from backend.jobs import _shrink_result


def _report() -> dict:
    return {
        "scan_id": "scan-se",
        "source": "local",
        "summary": {"total_files": 2, "high": 1, "low": 1},
        "files": [
            {"path": "/real/a.txt", "name": "a.txt"},
            {"path": "/real/b.txt", "name": "b.txt"},
        ],
        "endpoint": {"host": "host-a"},
    }


def test_compact_history_payload_preserves_metadata_and_omits_files() -> None:
    compact = _compact_scan_report(_report())
    assert compact["files"] == []
    assert compact["files_omitted"] is True
    assert compact["file_count"] == 2
    assert compact["summary"]["high"] == 1
    assert compact["endpoint"]["host"] == "host-a"
    assert compact["is_demo_sample"] is False


def test_completed_job_never_retains_a_file_preview() -> None:
    compact = _shrink_result(_report())
    assert compact["files"] == []
    assert compact["files_omitted"] is True
    assert compact["result_file_count"] == 2

