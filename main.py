from collectors.file_scanner import scan_directory
from classification.regex_classifier import classify_file
from risk.risk_engine import calculate_risk
from scripts.report import generate_report

def main():
    path = "./test_data"

    print("[+] DSPM STARTED")

    files = scan_directory(path)

    results = []

    for file in files:
        findings = classify_file(file)
        risk = calculate_risk(findings)

        result = {
            "file": file,
            "findings": findings,
            "risk": risk
        }

        results.append(result)

        print(result)

    generate_report(results)

if __name__ == "__main__":
    main()
