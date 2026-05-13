import re


EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
PASSWORD_REGEX = r"PASSWORD\s*=\s*([^\s]+)"


def classify_content(content: str):
    findings = []

    emails = re.findall(EMAIL_REGEX, content)
    passwords = re.findall(PASSWORD_REGEX, content)

    for e in emails:
        findings.append({
            "type": "email",
            "value": e,
            "risk": "medium"
        })

    for p in passwords:
        findings.append({
            "type": "password",
            "value": p,
            "risk": "high"
        })

    return findings
