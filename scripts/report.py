from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def generate_report(report: Any, output_file: str | Path = "report.json") -> dict:
    data = report.to_dict() if hasattr(report, "to_dict") else report
    output_path = Path(output_file)

    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)

    return data
