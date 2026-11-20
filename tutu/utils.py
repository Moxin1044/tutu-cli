from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Iterable, List, Optional

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CVE_PREFIX_RE = re.compile(r"^CVE-\d{4}(?:-\d+)?$", re.I)
SEVERITY_ORDER = {
    "CRITICAL": 5,
    "严重": 5,
    "HIGH": 4,
    "高危": 4,
    "MEDIUM": 3,
    "中危": 3,
    "LOW": 2,
    "低危": 2,
    "NONE": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def strip_html(value: str) -> str:
    if not value:
        return ""
    value = re.sub(r"(?is)<(script|style).*?</\1>", " ", value)
    value = _TAG_RE.sub(" ", value)
    return clean_text(html.unescape(value))


def clean_text(value: str) -> str:
    if not value:
        return ""
    return _WS_RE.sub(" ", str(value)).strip()


def truncate(value: str, limit: int = 300) -> str:
    value = clean_text(value)
    if limit <= 0 or len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def first_sentence(value: str, limit: int = 300) -> str:
    value = clean_text(value)
    if not value:
        return ""
    match = re.search(r"(?<=[.!?。！？])\s+", value)
    if match and match.start() < limit:
        value = value[: match.start() + 1]
    return truncate(value, limit)


def is_exact_cve(value: str) -> bool:
    return bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", (value or "").strip(), re.I))


def is_cve_prefix(value: str) -> bool:
    return bool(CVE_PREFIX_RE.fullmatch((value or "").strip()))


def extract_cves(value: str) -> List[str]:
    return [m.upper() for m in CVE_RE.findall(value or "")]


def normalize_severity(value: str) -> str:
    value = clean_text(value).upper()
    mapping = {
        "CRITICAL": "CRITICAL",
        "CRIT": "CRITICAL",
        "严重": "CRITICAL",
        "HIGH": "HIGH",
        "高危": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "中危": "MEDIUM",
        "LOW": "LOW",
        "低危": "LOW",
        "NONE": "NONE",
    }
    return mapping.get(value, value or "UNKNOWN")


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(normalize_severity(value), 0)


def short_date(value: str) -> str:
    """尽量把 ISO / RFC3339 时间压成 YYYY-MM-DD。"""
    value = clean_text(value)
    if not value:
        return ""
    match = re.search(r"(\d{4})[-/年](\d{1,2})[-/月](\d{1,2})", value)
    if match:
        y, m, d = match.groups()
        return f"{y}-{int(m):02d}-{int(d):02d}"
    return value[:10]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def join_nonempty(parts: Iterable[Optional[str]], sep: str = " · ") -> str:
    return sep.join([clean_text(p) for p in parts if p and clean_text(p)])


def dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
