from __future__ import annotations

import re
from typing import Any, Dict, List

from ..http import HttpClient
from ..models import Item
from ..utils import (
    clean_text,
    first_sentence,
    is_exact_cve,
    normalize_severity,
    short_date,
)
from .base import Source

RAW = (
    "https://raw.githubusercontent.com/cisagov/vulnrichment/"
    "develop/{year}/{bucket}/CVE-{year}-{seq}.json"
)


def _url_for(cve_id: str) -> str:
    match = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve_id.upper())
    if not match:
        return ""
    year, seq = match.groups()
    bucket = re.sub(r"\d{3}$", "xxx", seq)
    return RAW.format(year=year, bucket=bucket, seq=seq)


def _walk_metrics(obj: Any, out: List[Dict[str, Any]]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key.startswith("cvssV") and isinstance(value, dict):
                out.append(value)
            elif key in ("metrics", "adp", "containers"):
                _walk_metrics(value, out)
            elif isinstance(value, (dict, list)):
                _walk_metrics(value, out)
    elif isinstance(obj, list):
        for row in obj:
            _walk_metrics(row, out)


def _walk_ssvc(obj: Any, out: List[str]) -> None:
    if isinstance(obj, dict):
        if "ssvcV2" in obj or "ssvc" in obj:
            for key in ("ssvcV2", "ssvc"):
                value = obj.get(key)
                if isinstance(value, dict):
                    for k, v in value.items():
                        if isinstance(v, str):
                            out.append(f"{k}={v}")
        for value in obj.values():
            if isinstance(value, (dict, list)):
                _walk_ssvc(value, out)
    elif isinstance(obj, list):
        for row in obj:
            _walk_ssvc(row, out)


class VulnrichmentSource(Source):
    name = "vulnrichment"
    label = "CISA Vulnrichment"
    kind = "vuln"
    description = "CISA ADP 漏洞富化数据（GitHub 原始 JSON，无需 Key）"

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        query = query.strip()
        if not is_exact_cve(query):
            return []
        cve_id = query.upper()
        url = _url_for(cve_id)
        if not url:
            return []
        try:
            data = http.get_json(url)
        except Exception as exc:  # noqa: BLE001
            # CISA 尚未富化该 CVE，属于正常情况
            if "404" in str(exc):
                self.last_note = "CISA 尚未富化该 CVE"
            return []
        meta = data.get("cveMetadata") or {}
        containers = data.get("containers") or {}
        cna = containers.get("cna") or {}
        desc = ""
        for row in cna.get("descriptions") or []:
            if row.get("lang") == "en":
                desc = clean_text(row.get("value", ""))
                break
        metric_rows: List[Dict[str, Any]] = []
        _walk_metrics(data, metric_rows)
        metric_rows.sort(key=lambda r: float(r.get("baseScore") or 0), reverse=True)
        metric = metric_rows[0] if metric_rows else {}
        ssvc: List[str] = []
        _walk_ssvc(data, ssvc)
        refs: List[str] = []
        for container in (cna, *[a for a in (containers.get("adp") or []) if isinstance(a, dict)]):
            for ref in container.get("references") or []:
                u = ref.get("url") if isinstance(ref, dict) else None
                if u and u not in refs:
                    refs.append(u)
        return [
            Item(
                source=self.name,
                category="vulnerability",
                title=cve_id,
                url=f"https://github.com/cisagov/vulnrichment",
                date=short_date(meta.get("dateUpdated") or meta.get("datePublished") or ""),
                summary=first_sentence(desc, 500),
                severity=normalize_severity(metric.get("baseSeverity") or ""),
                score=str(metric.get("baseScore") or ""),
                tags=ssvc[:4],
                extra={
                    "cve": cve_id,
                    "adp": True,
                    "vector": metric.get("vectorString") or "",
                    "ssvc": ssvc[:8],
                    "references": refs[:5],
                },
            )
        ]
