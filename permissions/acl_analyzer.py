from __future__ import annotations


WIDE_ACCESS_MARKERS = {"everyone", "domain users", "authenticated users", "guest", "users"}
PRIVILEGED_MARKERS = {"domain admins", "enterprise admins", "administrators"}


def analyze_acl(acl: dict, file_record: dict | None = None) -> dict:
    principals = [str(item).lower() for item in acl.get("principals", [])]
    permissions = [str(item).lower() for item in acl.get("permissions", [])]

    wide_access = any(marker in principal for marker in WIDE_ACCESS_MARKERS for principal in principals)
    privileged_access = any(marker in principal for marker in PRIVILEGED_MARKERS for principal in principals)
    writable = any(permission in {"write", "modify", "full_control", "full control"} for permission in permissions)

    issues: list[str] = []
    if wide_access:
        issues.append("Broad group access detected")
    if wide_access and writable:
        issues.append("Broad writable access detected")
    if not acl:
        issues.append("ACL data was not available during this scan")

    score = 0
    if wide_access:
        score += 20
    if writable:
        score += 15
    if privileged_access and not wide_access:
        score += 5

    return {
        "score": min(score, 40),
        "wide_access": wide_access,
        "writable": writable,
        "privileged_access": privileged_access,
        "issues": issues,
    }
