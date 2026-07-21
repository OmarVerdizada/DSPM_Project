from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


Detector = Callable[[str, dict], list[str]]


@dataclass(frozen=True, slots=True)
class GDPRRule:
    finding_type: str
    label: str
    tier: str
    category: str
    risk: str
    description: str
    keywords: tuple[str, ...]
    detector: Detector


def compile_keyword_pattern(keywords: tuple[str, ...]) -> re.Pattern[str]:
    escaped = sorted((re.escape(item) for item in keywords if item), key=len, reverse=True)
    return re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(escaped) + r")(?![A-Za-z0-9_])", re.IGNORECASE)
