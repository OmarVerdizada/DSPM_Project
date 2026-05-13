import json
from datetime import datetime

def generate_report(results, output_file="report.json"):
    report = {
        "timestamp": str(datetime.now()),
        "total_files": len(results),
        "findings": results
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Report saved to {output_file}")
