from __future__ import annotations

from typing import Any, Dict, List

from ..http import HttpClient, SourceError
from ..models import Item
from ..utils import (
    clean_text,
    first_sentence,
    is_exact_cve,
    normalize_severity,
    short_date,
)
from ..versions import VersionRange, format_ranges, ranges_from_mitre_versions
from .base import Source

CVE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"


def _description(cna: Dict[str, Any]) -> str:
    for row in cna.get("descriptions") or []:
        if row.get("lang") == "en":
            return clean_text(row.get("value", ""))
    rows = cna.get("descriptions") or []
    return clean_text(rows[0].get("value", "")) if rows else ""


def _metric(containers: List[Dict[str, Any]]) -> Dict[str, Any]:
    for container in containers:
        for metric in container.get("metrics") or []:
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                data = metric.get(key)
                if data:
                    return {
                        "score": data.get("baseScore"),
                        "severity": data.get("baseSeverity"),
                        "vector": data.get("vectorString"),
                        "version": data.get("version"),
                    }
    return {}


def _affected(cna: Dict[str, Any], limit: int = 6) -> List[str]:
    out: List[str] = []
    for row in cna.get("affected") or []:
        vendor = clean_text(row.get("vendor", ""))
        product = clean_text(row.get("product", ""))
        label = "/".join([p for p in (vendor, product) if p])
        if label and label not in out:
            out.append(label)
        if len(out) >= limit:
            break
    return out


def _affected_ranges(cna: Dict[str, Any], limit: int = 16) -> List[VersionRange]:
    out: List[VersionRange] = []
    for row in cna.get("affected") or []:
        if not isinstance(row, dict):
            continue
        vendor = clean_text(row.get("vendor", ""))
        product = clean_text(row.get("product", ""))
        label = "/".join([p for p in (vendor, product) if p])
        out.extend(ranges_from_mitre_versions(label, row.get("versions") or []))
        if len(out) >= limit:
            break
    return out[:limit]


class MitreCveSource(Source):
    name = "mitre"
    label = "MITRE CVE"
    kind = "vuln"
    description = "CVE Program 官方 CVE Record（CVE Services API，无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        query = query.strip()
        if not is_exact_cve(query):
            return []
        cve_id = query.upper()
        try:
            data = http.get_json(CVE_API.format(cve_id=cve_id))
        except SourceError as exc:
            if "404" in str(exc):
                self.last_note = "MITRE 未收录该 CVE"
                return []
            raise
        meta = data.get("cveMetadata") or {}
        containers = (data.get("containers") or {})
        cna = containers.get("cna") or {}
        adp = containers.get("adp") or []
        desc = _description(cna) or _description(adp[0] if adp else {})
        metric = _metric([cna] + list(adp))
        refs = [
            r.get("url")
            for r in (cna.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ][:5]
        products = _affected(cna)
        versions = _affected_ranges(cna)
        tags: List[str] = []
        for problem in cna.get("problemTypes") or []:
            for row in problem.get("descriptions") or []:
                cwe = row.get("cweId")
                if cwe and cwe not in tags:
                    tags.append(cwe)
        return [
            Item(
                source=self.name,
                category="vulnerability",
                title=cve_id,
                url=f"https://www.cve.org/CVERecord?id={cve_id}",
                date=short_date(meta.get("datePublished") or ""),
                summary=first_sentence(desc, 500),
                severity=normalize_severity(metric.get("severity") or ""),
                score=str(metric.get("score") or ""),
                tags=tags,
                extra={
                    "cve": cve_id,
                    "state": meta.get("state") or "",
                    "assigner": meta.get("assignerShortName") or "",
                    "published": meta.get("datePublished") or "",
                    "modified": meta.get("dateUpdated") or "",
                    "vector": metric.get("vector") or "",
                    "references": refs,
                    "description": desc,
                    "products": products,
                    "version_ranges": versions,
                    "affected_versions": format_ranges(versions),
                },
            )
        ]
