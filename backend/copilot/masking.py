from __future__ import annotations

import re
from typing import Any


_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_ASSIGNMENT_SECRET_RE = re.compile(
    r"\b(password|passwd|pwd|api[_-]?key|apikey|secret|token|access[_-]?token|refresh[_-]?token|private[_-]?key)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----.*?(?:-----END\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----|$)",
    re.IGNORECASE | re.DOTALL,
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
# JWTs (header.payload.signature) start with the base64url of '{"' -> "eyJ".
# These leak whether or not they follow a token= assignment or Bearer prefix,
# e.g. a raw JWT sitting inside a scanned config file.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
# AWS access key IDs (AKIA/ASIA + 16 uppercase alnum) are self-identifying.
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_LIKELY_KEY_RE = re.compile(r"\b(?:sk|pk|ghp|glpat|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b", re.IGNORECASE)
_WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\Users\\[^ \n\r\t]+")
_UNIX_PATH_RE = re.compile(r"(?<!\w)/(?:Users|home)/[^ \n\r\t]+")


def mask_sensitive_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = _PRIVATE_KEY_BLOCK_RE.sub("[PRIVATE_KEY_MASKED]", text)
    text = _EMAIL_RE.sub("[EMAIL_MASKED]", text)
    text = _ASSIGNMENT_SECRET_RE.sub(lambda m: f"{m.group(1)}=[SECRET_MASKED]", text)
    text = _BEARER_RE.sub("Bearer [TOKEN_MASKED]", text)
    text = _JWT_RE.sub("[JWT_MASKED]", text)
    text = _AWS_KEY_RE.sub("[KEY_MASKED]", text)
    text = _LIKELY_KEY_RE.sub("[KEY_MASKED]", text)
    text = _WINDOWS_PATH_RE.sub("[LOCAL_PATH_MASKED]", text)
    text = _UNIX_PATH_RE.sub("[LOCAL_PATH_MASKED]", text)
    return text
