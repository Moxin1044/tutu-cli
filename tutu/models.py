from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .versions import VersionRange, format_ranges


def _jsonable(value: Any) -> Any:
    if isinstance(value, Item):
        return value.to_dict()
    if isinstance(value, VersionRange):
        return value.to_dict()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return value


@dataclass
class Item:
    """一条聚合结果。

    category 约定：
      vulnerability / exploit / apt / campaign / news / notice / ransomware /
      group / ioc / portal
    """

    source: str
    category: str
    title: str
    url: str = ""
    date: str = ""
    summary: str = ""
    severity: str = ""
    score: str = ""
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "category": self.category,
            "title": self.title,
            "url": self.url,
            "date": self.date,
            "summary": self.summary,
            "severity": self.severity,
            "score": self.score,
            "tags": list(self.tags),
            "extra": _jsonable(dict(self.extra)),
        }


@dataclass
class VulnCard:
    cve: str
    summary: str = ""
    severity: str = ""
    score: str = ""
    published: str = ""
    modified: str = ""
    sources: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    refs: List[str] = field(default_factory=list)
    kev: bool = False
    ransomware: bool = False
    epss: float = 0.0
    epss_percentile: float = 0.0
    version_ranges: List[VersionRange] = field(default_factory=list)
    exploits: List[Item] = field(default_factory=list)
    items: List[Item] = field(default_factory=list)

    def affected_versions(self, limit: int = 8) -> List[str]:
        return format_ranges(self.version_ranges, limit)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve": self.cve,
            "summary": self.summary,
            "severity": self.severity,
            "score": self.score,
            "published": self.published,
            "modified": self.modified,
            "sources": self.sources,
            "tags": self.tags,
            "affected_products": self.affected_products,
            "affected_versions": self.affected_versions(),
            "version_ranges": [r.to_dict() for r in self.version_ranges],
            "refs": self.refs,
            "kev": self.kev,
            "ransomware": self.ransomware,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "exploits": [i.to_dict() for i in self.exploits],
        }


@dataclass
class SourceResult:
    source: str
    label: str
    items: List[Item] = field(default_factory=list)
    elapsed: float = 0.0
    error: str = ""
    note: str = ""

    @property
    def ok(self) -> bool:
        return not self.error
