from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Iterable, List, Optional

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CVE_PREFIX_RE = re.compile(r"^CVE-\d{4}(?:-\d+)?$", re.I)
HEADER_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?\s*([a-zA-Z0-9_\-]+)", re.I)
META_CHARSET_RE = re.compile(
    rb"""<meta[^>]+charset\s*=\s*["']?\s*([a-zA-Z0-9_\-]+)""", re.I
)
# requests 对 text/* 且未声明 charset 的响应默认给出 ISO-8859-1；
# 这类编码几乎不会解码失败，却是中文页面乱码的常见原因，不能优先采用。
_ASCII_LIKE_CODECS = {
    "iso-8859-1",
    "iso8859-1",
    "latin-1",
    "latin1",
    "l1",
    "us-ascii",
    "ascii",
    "cp1252",
    "windows-1252",
}
_GB_CODECS = {"gb2312", "gbk", "gb18030", "gb_2312-80", "x-gbk", "cp936"}
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


def repair_mojibake(value: str) -> str:
    """修复 UTF-8 字节被按 Latin-1 解码后产生的乱码（如 ä¿¡é...）。"""
    if not value or not re.search(r"[\u00c0-\u00ff]", value):
        return value
    try:
        repaired = value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return value
    if repaired == value or not re.search(r"[\u4e00-\u9fff]", repaired):
        return value
    # 修复后仍应保留正常中文，且不再大量出现 Latin-1 高位字符。
    if len(re.findall(r"[\u00c0-\u00ff]", repaired)) > len(re.findall(r"[\u00c0-\u00ff]", value)) // 3:
        return value
    return repaired


def _add_codec(candidates: List[str], value: Optional[str]) -> None:
    if not value:
        return
    codec = str(value).strip().strip("\"'").lower()
    if not codec or codec in _ASCII_LIKE_CODECS or codec in candidates:
        return
    candidates.append(codec)


def decode_html(
    body: bytes,
    encoding: Optional[str] = None,
    content_type: str = "",
) -> str:
    """尽量正确地解码 HTML：忽略不可信的 Latin-1 默认值，优先 UTF-8/声明编码。"""
    if not body:
        return ""
    declared: List[str] = []
    _add_codec(declared, encoding)
    match = HEADER_CHARSET_RE.search(content_type or "")
    if match:
        _add_codec(declared, match.group(1))
    match = META_CHARSET_RE.search(body[:4096])
    if match:
        _add_codec(declared, match.group(1).decode("ascii", "ignore"))

    candidates: List[str] = []
    # 非 GB 系编码（Big5 / Shift-JIS / EUC-KR 等）按其声明优先尝试。
    for codec in declared:
        if codec not in _GB_CODECS and codec not in candidates:
            candidates.append(codec)
    # 中文站点常见：页面实际是 UTF-8，但声明为 gb2312/gbk，先试 UTF-8。
    if "utf-8" not in candidates:
        candidates.append("utf-8")
    for codec in declared:
        if codec in _GB_CODECS and codec not in candidates:
            candidates.append(codec)
    if "gb18030" not in candidates:
        candidates.append("gb18030")

    for codec in candidates:
        try:
            text = body.decode(codec)
        except (LookupError, UnicodeDecodeError):
            continue
        return repair_mojibake(text)
    return repair_mojibake(body.decode("utf-8", "ignore"))


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
