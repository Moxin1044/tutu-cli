"""受影响版本区间解析、展示与本地版本匹配。

不同数据源给出的版本表达方式差异很大：

* NVD CPE：`cpe:2.3:a:vendor:product:*:*`，配合
  `versionStartIncluding` / `versionEndExcluding` 等字段
* CISA Vulnrichment：同样使用 CPE 匹配串
* OSV：`ranges: [{type: SEMVER|ECOSYSTEM, events: [{introduced}, {fixed}, …]}]`
* MITRE CNA：`affected: [{versions: [{status, version, lessThan|lessThanOrEqual}]}]`

这里统一转换成 ``VersionRange``，再渲染成 ``pkg 1.0.0 ~ 2.0.1`` 形式。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .utils import clean_text

_PLACEHOLDERS = {"", "*", "-", "n/a", "na", "any", "all"}


def normalize_product(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "")).strip().lower()


def _key(part: str) -> tuple:
    """把单个版本片段转换成可比较的元组：(数字, 是否正式片段, 文本)。"""
    part = part.strip().lower()
    if not part:
        return (0, 1, "")
    if part.isdigit():
        return (int(part), 1, "")
    match = re.match(r"^(\d+)([a-z].*)$", part)
    if match:  # 1rc1 / 2beta3
        return (int(match.group(1)), 0, match.group(2))
    return (0, 0, part)


def version_key(value: str) -> tuple:
    """把任意版本号转成可比较的 key；预发布版本排在正式版之前。"""
    value = clean_text(value).lower()
    if value.startswith("v") and value[1:2].isdigit():
        value = value[1:]
    value = value.split("+", 1)[0]
    if "-" in value:
        main, _, pre = value.partition("-")
        parts = tuple(_key(p) for p in main.split("."))
        pre_parts = tuple(_key(p) for p in re.split(r"[.\-]", pre) if p)
        return (parts, 0, pre_parts)
    parts = tuple(_key(p) for p in value.split("."))
    return (parts, 1, ())


def compare_versions(left: str, right: str) -> int:
    """返回 -1 / 0 / 1；数字段按数值比较，缺失段视为 0。"""
    la, lrel, lpre = version_key(left)
    ra, rrel, rpre = version_key(right)
    length = max(len(la), len(ra))
    for index in range(length):
        lpart = la[index] if index < len(la) else (0, 1, "")
        rpart = ra[index] if index < len(ra) else (0, 1, "")
        if lpart != rpart:
            return -1 if lpart < rpart else 1
    if lrel != rrel:
        # 预发布 < 正式版
        return 1 if lrel > rrel else -1
    if lpre != rpre:
        return -1 if lpre < rpre else 1
    return 0


def base_version(value: str) -> str:
    value = clean_text(value)
    match = re.match(r"^v?(\d+(?:\.\d+)*)", value, re.I)
    return match.group(1) if match else value


@dataclass
class VersionRange:
    """一条受影响版本区间；空字段表示该侧无界。"""

    product: str = ""
    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""
    exact: List[str] = field(default_factory=list)
    source: str = ""
    cpe: str = ""

    def is_empty(self) -> bool:
        return not any(
            (
                self.start_including,
                self.start_excluding,
                self.end_including,
                self.end_excluding,
                self.exact,
            )
        )

    def is_wildcard(self) -> bool:
        """CPE 为 `*` 且无区间：即该产品所有版本。"""
        return self.is_empty()

    def display_product(self) -> str:
        return self.product or "未知产品"

    def label(self) -> str:
        product = self.display_product()
        if self.is_wildcard():
            return f"{product} 所有版本"
        parts: List[str] = []
        if self.start_including:
            parts.append(f">= {self.start_including}")
        if self.start_excluding:
            parts.append(f"> {self.start_excluding}")
        if self.end_including:
            parts.append(f"<= {self.end_including}")
        if self.end_excluding:
            parts.append(f"< {self.end_excluding}")
        if self.exact and not parts:
            if len(self.exact) <= 3:
                parts.append("= " + ", ".join(self.exact))
            else:
                parts.append("= " + ", ".join(self.exact[:3]) + f" 等 {len(self.exact)} 个")
        return f"{product} {' , '.join(parts)}".strip()

    def contains(self, version: str) -> bool:
        version = clean_text(version)
        if not version:
            return False
        if self.is_wildcard():
            return True
        if self.exact and not any(
            (
                self.start_including,
                self.start_excluding,
                self.end_including,
                self.end_excluding,
            )
        ):
            if any(compare_versions(version, target) == 0 for target in self.exact):
                return True
            # CPE 里的 2.14.1 常代表 2.14.x 这一行
            base = base_version(version)
            for target in self.exact:
                target_base = base_version(target)
                if (
                    compare_versions(base, target_base) == 0
                    and target_base.count(".") < base.count(".")
                ):
                    return True
            return False
        if self.start_including and compare_versions(version, self.start_including) < 0:
            return False
        if self.start_excluding and compare_versions(version, self.start_excluding) <= 0:
            return False
        if self.end_including and compare_versions(version, self.end_including) > 0:
            return False
        if self.end_excluding and compare_versions(version, self.end_excluding) >= 0:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "product": self.product,
            "start_including": self.start_including,
            "start_excluding": self.start_excluding,
            "end_including": self.end_including,
            "end_excluding": self.end_excluding,
            "exact": list(self.exact),
            "source": self.source,
            "cpe": self.cpe,
        }


def _clean_version(value: Any) -> str:
    value = clean_text(str(value if value is not None else ""))
    if value.lower() in _PLACEHOLDERS:
        return ""
    return value


def parse_cpe(criteria: str) -> Dict[str, str]:
    """解析 CPE 2.3 字符串，返回 vendor / product / version。"""
    parts = (criteria or "").split(":")
    if len(parts) < 6 or parts[0] != "cpe":
        return {}
    return {
        "vendor": parts[3].replace("\\", ""),
        "product": parts[4].replace("\\", ""),
        "version": parts[5].replace("\\", ""),
    }


def ranges_from_cpe(match: Dict[str, Any], source: str = "") -> Optional[VersionRange]:
    if not isinstance(match, dict):
        return None
    cpe = parse_cpe(match.get("criteria") or "")
    if not cpe:
        return None
    label = "/".join(x for x in (cpe["vendor"], cpe["product"]) if x)
    if not label:
        return None
    version = _clean_version(cpe["version"])
    return VersionRange(
        product=label,
        start_including=_clean_version(match.get("versionStartIncluding")),
        start_excluding=_clean_version(match.get("versionStartExcluding")),
        end_including=_clean_version(match.get("versionEndIncluding")),
        end_excluding=_clean_version(match.get("versionEndExcluding")),
        exact=[version] if version else [],
        source=source,
        cpe=match.get("criteria") or "",
    )


def ranges_from_osv(vuln: Dict[str, Any], source: str = "osv") -> List[VersionRange]:
    out: List[VersionRange] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        name = clean_text(pkg.get("name") or "")
        ecosystem = clean_text(pkg.get("ecosystem") or "")
        label = name + (f" ({ecosystem})" if ecosystem else "")
        label = label or "未知产品"
        explicit = [_clean_version(v) for v in affected.get("versions") or []]
        explicit = [v for v in explicit if v]
        ranged: List[VersionRange] = []
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            current: Optional[VersionRange] = None
            for event in rng.get("events") or []:
                if not isinstance(event, dict):
                    continue
                if "introduced" in event:
                    if current is not None:
                        ranged.append(current)
                    current = VersionRange(
                        product=label,
                        start_including=_clean_version(event.get("introduced")),
                        source=source,
                    )
                elif "fixed" in event:
                    item = current or VersionRange(product=label, source=source)
                    item.end_excluding = _clean_version(event.get("fixed"))
                    ranged.append(item)
                    current = None
                elif "last_affected" in event:
                    item = current or VersionRange(product=label, source=source)
                    item.end_including = _clean_version(event.get("last_affected"))
                    ranged.append(item)
                    current = None
                elif "limit" in event:
                    item = current or VersionRange(product=label, source=source)
                    item.end_excluding = _clean_version(event.get("limit"))
                    ranged.append(item)
                    current = None
            if current is not None:
                ranged.append(current)
        out.extend(ranged)
        if not ranged:
            # 只有 versions 列表，没有 ranges
            out.append(VersionRange(product=label, exact=explicit, source=source))
    return [r for r in out if r.display_product()]


def ranges_from_mitre_versions(
    product: str,
    versions: List[Dict[str, Any]],
    source: str = "mitre",
) -> List[VersionRange]:
    out: List[VersionRange] = []
    for row in versions or []:
        if not isinstance(row, dict):
            continue
        status = clean_text(row.get("status") or "").lower()
        if status and status not in ("affected", "unknown"):
            continue
        rng = VersionRange(product=product or "未知产品", source=source)
        value = _clean_version(row.get("version"))
        less = _clean_version(row.get("lessThan"))
        less_equal = _clean_version(row.get("lessThanOrEqual"))
        if less:
            rng.start_including = value
            rng.end_excluding = less
        elif less_equal:
            rng.start_including = value
            rng.end_including = less_equal
        elif value:
            rng.exact = [value]
        if not rng.is_empty():
            out.append(rng)
    return out


def dedupe_ranges(ranges: Iterable[VersionRange]) -> List[VersionRange]:
    seen: set = set()
    out: List[VersionRange] = []
    for rng in ranges:
        key = (
            normalize_product(rng.product),
            rng.start_including,
            rng.start_excluding,
            rng.end_including,
            rng.end_excluding,
            tuple(rng.exact),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(rng)
    return out


def range_priority(rng: VersionRange) -> int:
    """排序优先级：双边区间 > 精确版本 > 单边区间 > 全版本通配。"""
    if rng.is_wildcard():
        return 3
    has_start = bool(rng.start_including or rng.start_excluding)
    has_end = bool(rng.end_including or rng.end_excluding)
    if has_start and has_end:
        return 0
    if rng.exact:
        return 1
    return 2


def sort_ranges(ranges: Iterable[VersionRange]) -> List[VersionRange]:
    return sorted(dedupe_ranges(ranges), key=range_priority)


def format_ranges(ranges: List[VersionRange], limit: int = 6) -> List[str]:
    """渲染成人类可读的列表，例如 `apache/http_server 2.4.0 ~ 2.4.51（不含 2.4.51）`。"""
    out: List[str] = []
    for rng in sort_ranges(ranges)[:limit]:
        if rng.start_including and rng.end_excluding:
            label = (
                f"{rng.display_product()} {rng.start_including} ~ "
                f"{rng.end_excluding}（不含 {rng.end_excluding}）"
            )
        elif rng.start_including and rng.end_including:
            label = f"{rng.display_product()} {rng.start_including} ~ {rng.end_including}"
        else:
            label = rng.label()
        out.append(label)
    return out


def match_version(ranges: List[VersionRange], version: str) -> List[VersionRange]:
    return [rng for rng in ranges if rng.contains(version)]


def product_tokens(value: str) -> List[str]:
    """产品名拆词，用于把资产指纹映射到漏洞受影响产品。"""
    tokens: List[str] = []
    for raw in re.split(r"[/\s,()_]+", normalize_product(value)):
        raw = raw.strip()
        if len(raw) < 2:
            continue
        if raw in ("the", "inc", "ltd", "corp", "http", "https", "server", "web"):
            continue
        tokens.append(raw)
    return tokens


def asset_matches_product(asset_product: str, asset_version: str, rng: VersionRange) -> bool:
    """资产指纹（产品 + 检测到的版本）是否落在某个受影响区间内。"""
    tokens = product_tokens(asset_product)
    if not tokens:
        return False
    target = normalize_product(rng.product)
    if not any(token in target for token in tokens):
        return False
    if not asset_version:
        return True
    return rng.contains(asset_version)


_OP_RE = re.compile(r"^(<=|>=|<|>|==|=)\s*v?(\S+)$")


def ranges_from_string(
    product: str,
    expression: str,
    source: str = "github",
) -> List["VersionRange"]:
    """解析 `>= 1.0.0, < 1.4.2` / `<= 2.3` 这类范围表达式。"""
    expression = clean_text(expression)
    if not expression:
        return []
    rng = VersionRange(product=product or "未知产品", source=source)
    for raw in re.split(r"[,;]", expression):
        part = raw.strip()
        if not part:
            continue
        lowered = part.lower()
        if lowered.startswith(">="):
            rng.start_including = _clean_version(part[2:])
        elif lowered.startswith("<="):
            rng.end_including = _clean_version(part[2:])
        elif lowered.startswith(">"):
            rng.start_excluding = _clean_version(part[1:])
        elif lowered.startswith("<"):
            rng.end_excluding = _clean_version(part[1:])
        elif lowered.startswith("=="):
            value = _clean_version(part[2:])
            if value:
                rng.exact.append(value)
        elif lowered.startswith("="):
            value = _clean_version(part[1:])
            if value:
                rng.exact.append(value)
        else:
            value = _clean_version(part)
            if value and value.lower() not in ("*", "all", "any"):
                rng.exact.append(value)
    return [] if rng.is_empty() else [rng]


def range_matches_product(rng: "VersionRange", product: str) -> bool:
    """区间所属产品是否与给定产品名匹配（不比较版本）。"""
    tokens = product_tokens(product)
    if not tokens:
        return False
    target = normalize_product(rng.product)
    return any(token in target for token in tokens)
