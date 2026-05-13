import re

patterns = {
    "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "password": r"password\s*=\s*\w+",
}

def classify_file(file_path):
    findings = []

    with open(file_path, "r", errors="ignore") as f:
        content = f.read()

        for label, pattern in patterns.items():
            if re.search(pattern, content):
                findings.append(label)

    return findings
