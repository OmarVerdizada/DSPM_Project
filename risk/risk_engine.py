def calculate_risk(findings):
    """
    findings = ["email", "password", ...]
    """

    score = 0

    if "email" in findings:
        score += 2

    if "password" in findings:
        score += 5

    if "api_key" in findings:
        score += 8

    if score >= 8:
        return "CRITICAL"
    elif score >= 5:
        return "HIGH"
    elif score >= 2:
        return "MEDIUM"
    else:
        return "LOW"
