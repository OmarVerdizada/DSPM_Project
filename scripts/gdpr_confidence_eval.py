"""D2: what the GDPR confidence tiers are worth, measured on the labelled corpus.

    python scripts/gdpr_confidence_eval.py [--json docs/evidence/d2-gdpr-confidence.json]

Each document of ``tests/gdpr_corpus.py`` is classified; a finding type the document
holds is a true positive, one it does not hold a false positive, and a type it holds but
no finding reported a false negative. Measured at three thresholds - every finding,
MEDIUM and above, HIGH and above - so the report says what a reviewer gains and loses by
looking only at the confident tiers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THRESHOLDS = {"all": 0, "medium_and_above": 60, "high_and_above": 85}


def evaluate() -> dict:
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))
    from classification.compliance.gdpr_classifier import classify_gdpr_content
    from gdpr_corpus import CORPUS

    classified = []
    for doc in CORPUS:
        findings = classify_gdpr_content(doc["text"], {"tenant_id": "d2-eval", "path": f"{doc['id']}.txt"})
        classified.append((doc, {item["type"]: int(item["confidence"]) for item in findings}))

    report: dict = {"documents": len(CORPUS), "positive_documents": sum(1 for doc in CORPUS if doc["expected"]),
                    "labelled_types": sum(len(doc["expected"]) for doc in CORPUS), "thresholds": {}}
    for name, threshold in THRESHOLDS.items():
        tp = fp = fn = 0
        false_positives: dict[str, int] = {}
        for doc, found in classified:
            reported = {kind for kind, confidence in found.items() if confidence >= threshold}
            tp += len(reported & doc["expected"])
            fn += len(doc["expected"] - reported)
            for kind in reported - doc["expected"]:
                fp += 1
                false_positives[kind] = false_positives.get(kind, 0) + 1
        report["thresholds"][name] = {
            "threshold": threshold, "true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
            "recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
            "false_positives_by_type": dict(sorted(false_positives.items(), key=lambda item: (-item[1], item[0]))),
        }
    all_, medium = report["thresholds"]["all"], report["thresholds"]["medium_and_above"]
    report["false_positive_delta_at_medium"] = all_["false_positives"] - medium["false_positives"]
    report["true_positives_lost_at_medium"] = all_["true_positives"] - medium["true_positives"]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    report = evaluate()
    text = json.dumps(report, indent=2)
    print(text)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
