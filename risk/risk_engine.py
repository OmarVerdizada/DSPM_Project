import re


SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "apikey",
    "email", "credit", "ssn", "confidential"
]


def analyze_content(content: str):
    findings = []

    content_lower = content.lower()

    for keyword in SENSITIVE_KEYWORDS:
        if keyword in content_lower:
            findings.append(f"Sensitive keyword detected: {keyword}")

    # regex email detection
    if re.search(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content):
        findings.append("Email pattern detected")

    return findings


def calculate_risk(file_obj):
    score = 0
    reasons = []

    path = file_obj.get("path", "")
    size = file_obj.get("size", 0)
    content = file_obj.get("content", "")

    # 1. keyword risk
    findings = analyze_content(content)
    if findings:
        score += 40
        reasons.extend(findings)

    # 2. filename risk
    if any(k in path.lower() for k in SENSITIVE_KEYWORDS):
        score += 20
        reasons.append("Sensitive filename pattern")

    # 3. size anomaly (very small files often creds)
    if 0 < size < 100:
        score += 10
        reasons.append("Small file anomaly")

    # 4. extension risk
    if path.endswith((".txt", ".log", ".env", ".bak")):
        score += 10
        reasons.append("High-risk file extension")

    # 5. default share exposure risk
    if "share" in path:
        score += 10
        reasons.append("Network share exposure")

    # normalize
    score = min(score, 100)

    return {
        "file": path,
        "risk_score": score,
        "risk_level": get_level(score),
        "reasons": reasons
    }


def get_level(score):
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"
