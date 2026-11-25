"""把资产 Web 指纹与 NVD 漏洞库关联，给出可能命中的 CVE。"""
from __future__ import annotations

import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Sequence, Tuple

from ..http import HttpClient
from ..sources.nvd import NVD_API, parse_vulnerability
from ..utils import clean_text, severity_rank
from ..versions import format_ranges, range_matches_product
from .models import Asset, CveHit

log = logging.getLogger("tutu.assets.correlate")

# Web 指纹产品名 → NVD CPE product 字段
PRODUCT_SLUGS: Dict[str, str] = {
    "nginx": "nginx",
    "apache httpd": "http_server",
    "microsoft iis": "internet_information_services",
    "openresty": "openresty",
    "litespeed": "litespeed_web_server",
    "caddy": "caddy",
    "php": "php",
    "tomcat": "tomcat",
    "jetty": "jetty",
    "node.js express": "express",
    "asp.net": "asp.net_core",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "phpmyadmin": "phpmyadmin",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "atlassian jira/confluence": "jira",
    "spring boot": "spring_boot",
    "weblogic": "weblogic_server",
    "apache shiro": "shiro",
    "thinkphp": "thinkphp",
    "struts2": "struts",
    "swagger ui": "swagger_ui",
    "grafana": "grafana",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
    "zabbix": "zabbix",
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "next.js": "next.js",
    "vue.js": "vue.js",
    "react": "react",
    "nacos": "nacos",
    "minio": "minio",
    "rabbitmq": "rabbitmq",
    "harbor": "harbor",
}


class CorrelationError(ValueError):
    pass


def fingerprint_targets(assets: Sequence[Asset]) -> List[Dict[str, str]]:
    """抽取 (产品, 版本) 指纹，只保留检测到版本的条目。"""
    out: List[Dict[str, str]] = []
    seen = set()
    for asset in assets:
        for service in asset.services:
            for row in service.tech:
                product = clean_text(row.get("product") or "")
                version = clean_text(row.get("version") or "")
                if not product or not version:
                    continue
                key = (product.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "product": product,
                        "version": version,
                        "host": asset.host,
                        "url": service.url,
                    }
                )
    return out


def _slug(product: str) -> str:
    key = product.lower().strip()
    if key in PRODUCT_SLUGS:
        return PRODUCT_SLUGS[key]
    slug = re.sub(r"[^a-z0-9]+", "_", key).strip("_")
    return slug or key


def _api_key() -> Optional[str]:
    for name in ("TUTU_NVD_API_KEY", "NVD_API_KEY"):
        value = os.environ.get(name)
        if value and value.strip():
            return value.strip()
    return None


def search_fingerprint(
    target: Dict[str, str],
    http: HttpClient,
    limit: int = 5,
) -> List[CveHit]:
    product = target["product"]
    version = target["version"]
    match_string = (
        f"cpe:2.3:a:*:{_slug(product)}:{version}:*:*:*:*:*:*:*"
    )
    headers = {"Accept": "application/json"}
    key = _api_key()
    if key:
        headers["apiKey"] = key
    data = http.get_json(
        NVD_API,
        params={
            "virtualMatchString": match_string,
            "resultsPerPage": max(1, min(limit, 20)),
            "noRejected": "",
        },
        headers=headers,
        timeout=max(http.timeout, 30.0),
    )
    hits: List[CveHit] = []
    for row in data.get("vulnerabilities") or []:
        cve = row.get("cve") or {}
        item = parse_vulnerability(cve)
        if not item.title:
            continue
        ranges = item.extra.get("version_ranges") or []
        if any(
            range_matches_product(rng, product) and rng.contains(version)
            for rng in ranges
        ):
            match = "version"
        elif ranges:
            match = "product"
        else:
            match = "unknown"
        affected = " · ".join(
            format_ranges(
                [rng for rng in ranges if range_matches_product(rng, product)] or ranges,
                2,
            )
        )
        hits.append(
            CveHit(
                cve=item.title,
                product=product,
                version=version,
                host=target["host"],
                url=item.url,
                severity=item.severity,
                score=item.score,
                summary=item.summary,
                affected=affected,
                match=match,
            )
        )
    return hits


def correlate_assets(
    assets: Sequence[Asset],
    timeout: float = 20.0,
    max_fingerprints: int = 5,
    per_fingerprint: int = 5,
    debug: bool = False,
) -> Tuple[List[CveHit], List[str]]:
    """并发查询 NVD；返回 (CVE 命中, 说明)。"""
    targets = fingerprint_targets(assets)[:max_fingerprints]
    if not targets:
        return [], ["未从 Web 响应中提取到带版本号的技术栈，跳过漏洞关联"]
    hits: List[CveHit] = []
    notes: List[str] = []
    with ThreadPoolExecutor(max_workers=min(4, len(targets))) as pool:
        futures = {
            pool.submit(
                search_fingerprint,
                target,
                HttpClient(timeout=timeout),
                per_fingerprint,
            ): target
            for target in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            try:
                hits.extend(future.result())
            except Exception as exc:  # noqa: BLE001
                message = str(exc)[:160] or exc.__class__.__name__
                if debug:
                    log.debug("关联 %s %s 失败: %s", target["product"], target["version"], message)
                if "403" in message or "429" in message:
                    notes.append("NVD 限流（未认证约 5 次/30 秒），可设置 NVD_API_KEY 提高配额")
                else:
                    notes.append(f"{target['product']} {target['version']}: {message}")
    hits.sort(
        key=lambda h: (
            0 if h.match == "version" else 1,
            -severity_rank(h.severity),
            h.cve,
        )
    )
    return hits, notes
