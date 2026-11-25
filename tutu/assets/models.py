"""资产搜集（攻击面梳理）使用的数据模型。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..models import SourceResult


@dataclass
class Service:
    """一个 HTTP(S) 服务指纹。"""

    host: str
    url: str = ""
    scheme: str = ""
    port: int = 0
    status: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""
    content_type: str = ""
    length: int = 0
    redirect: str = ""
    tech: List[Dict[str, str]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    tls: Dict[str, Any] = field(default_factory=dict)

    @property
    def tech_names(self) -> List[str]:
        out: List[str] = []
        for row in self.tech:
            product = row.get("product") or ""
            version = row.get("version") or ""
            label = f"{product} {version}".strip()
            if label and label not in out:
                out.append(label)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "url": self.url,
            "scheme": self.scheme,
            "port": self.port,
            "status": self.status,
            "title": self.title,
            "server": self.server,
            "powered_by": self.powered_by,
            "content_type": self.content_type,
            "length": self.length,
            "redirect": self.redirect,
            "tech": self.tech,
            "headers": self.headers,
            "tls": self.tls,
        }


@dataclass
class PortResult:
    """一个开放端口。

    host 是资产主机名（域名或输入 IP），ip 是实际被扫描的地址；
    同一个域名解析到多个 IP 时，会分别出现在 open_ports 中。
    """

    host: str
    port: int
    ip: str = ""
    service: str = ""
    banner: str = ""
    scheme: str = ""
    status: int = 0
    title: str = ""
    tech: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "ip": self.ip,
            "port": self.port,
            "service": self.service,
            "scheme": self.scheme,
            "status": self.status,
            "title": self.title,
            "tech": list(self.tech),
            "banner": self.banner,
        }


@dataclass
class Asset:
    """一个子域名 / 主机资产。"""

    host: str
    ips: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    open_ports: List[PortResult] = field(default_factory=list)
    wildcard: bool = False
    note: str = ""
    extra_ip: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "ips": self.ips,
            "cnames": self.cnames,
            "sources": self.sources,
            "services": [s.to_dict() for s in self.services],
            "open_ports": [p.to_dict() for p in self.open_ports],
            "wildcard": self.wildcard,
            "note": self.note,
            "extra_ip": self.extra_ip,
        }


@dataclass
class CveHit:
    """资产指纹关联到的 CVE。"""

    cve: str
    product: str = ""
    version: str = ""
    host: str = ""
    url: str = ""
    severity: str = ""
    score: str = ""
    summary: str = ""
    affected: str = ""
    match: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve": self.cve,
            "product": self.product,
            "version": self.version,
            "host": self.host,
            "url": self.url,
            "severity": self.severity,
            "score": self.score,
            "summary": self.summary,
            "affected": self.affected,
            "match": self.match,
        }


@dataclass
class AttackSurface:
    """一次资产搜集的完整结果。"""

    domain: str
    assets: List[Asset] = field(default_factory=list)
    cve_hits: List[CveHit] = field(default_factory=list)
    source_results: List[SourceResult] = field(default_factory=list)
    reverse_ips: List[Dict[str, Any]] = field(default_factory=list)
    icp: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    generated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "generated": self.generated,
            "stats": self.stats,
            "assets": [a.to_dict() for a in self.assets],
            "cve_hits": [c.to_dict() for c in self.cve_hits],
            "reverse_ips": list(self.reverse_ips),
            "icp": self.icp,
            "source_results": [
                {
                    "source": r.source,
                    "label": r.label,
                    "count": len(r.items),
                    "elapsed": round(r.elapsed, 2),
                    "error": r.error,
                    "note": r.note,
                }
                for r in self.source_results
            ],
            "notes": self.notes,
        }
