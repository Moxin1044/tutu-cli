"""HTTP(S) 存活探测与 Web 指纹识别。"""
from __future__ import annotations

import logging
import re
import socket
import ssl
import warnings
from typing import Dict, List, Optional, Tuple

from urllib3.exceptions import InsecureRequestWarning

from ..http import HttpClient, SourceError
from ..utils import clean_text, decode_html, truncate
from .models import Service

log = logging.getLogger("tutu.assets.probe")

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
MAX_BODY = 96 * 1024

# (产品名, 正则, 是否只在头部匹配)
SIGNATURES: List[Tuple[str, str, bool]] = [
    ("nginx", r"\bnginx(?:/([0-9][\w.\-]*))?", False),
    ("Apache httpd", r"\bApache(?:/([0-9][\w.\-]*))?", False),
    ("Microsoft IIS", r"Microsoft-IIS/([0-9.]+)", False),
    ("OpenResty", r"\bopenresty(?:/([0-9][\w.\-]*))?", False),
    ("LiteSpeed", r"\bLiteSpeed(?:/([0-9][\w.\-]*))?", False),
    ("Caddy", r"\bCaddy(?:/([0-9][\w.\-]*))?", False),
    ("PHP", r"\bPHP/([0-9][\w.\-]*)", False),
    ("Tomcat", r"(?:Apache-Coyote|Tomcat)/([0-9][\w.\-]*)", False),
    ("Jetty", r"\bJetty(?:/([0-9][\w.\-]*))?", False),
    ("Node.js Express", r"\bExpress\b", True),
    ("ASP.NET", r"\bASP\.NET\b", False),
    ("Cloudflare", r"\bcloudflare\b", True),
    ("WordPress", r"wp-(?:content|includes)", False),
    ("Drupal", r"Drupal\.settings|sites/default/files", False),
    ("Joomla", r"/media/system/js/|option=com_", False),
    ("phpMyAdmin", r"phpMyAdmin", False),
    ("Jenkins", r"\bJenkins\b", False),
    ("GitLab", r"\bGitLab\b", False),
    ("Atlassian Jira/Confluence", r"atlassian", False),
    ("Spring Boot", r"Whitelabel Error Page|X-Application-Context", False),
    ("WebLogic", r"\bWebLogic\b", False),
    ("Apache Shiro", r"rememberMe=", False),
    ("ThinkPHP", r"ThinkPHP", False),
    ("Struts2", r"\bstruts", False),
    ("Swagger UI", r"swagger-ui|swagger-resources", False),
    ("Grafana", r"\bgrafana\b", False),
    ("Kibana", r"\bkibana\b", False),
    ("Elasticsearch", r"You Know, for Search|elasticsearch", False),
    ("Zabbix", r"\bzabbix\b", False),
    ("Next.js", r"__NEXT_DATA__|/_next/", False),
    ("Vue.js", r"__VUE__|data-v-[0-9a-f]{6,}", False),
    ("React", r"data-reactroot|react\.production\.min\.js", False),
    ("jQuery", r"jquery[-.]([0-9.]+)(?:\.min)?\.js", False),
    ("Bootstrap", r"bootstrap(?:\.min)?\.(?:css|js)", False),
    ("Nacos", r"\bnacos\b", False),
    ("MinIO", r"MinIO", False),
    ("RabbitMQ", r"RabbitMQ Management", False),
    ("Harbor", r"\bharbor\b", False),
]

HEADER_KEYS = (
    "server",
    "x-powered-by",
    "via",
    "cf-ray",
    "x-jenkins",
    "x-application-context",
    "content-type",
    "location",
    "x-frame-options",
    "strict-transport-security",
)


def _tech_from_text(headers_text: str, body_text: str) -> List[Dict[str, str]]:
    found: List[Dict[str, str]] = []
    seen = set()
    for product, pattern, header_only in SIGNATURES:
        sources = [headers_text] if header_only else [headers_text, body_text]
        version = ""
        matched = False
        for text in sources:
            match = re.search(pattern, text, re.I)
            if not match:
                continue
            matched = True
            if match.groups():
                version = clean_text(match.group(1) or "")
                if version:
                    break
        if not matched:
            continue
        key = (product, version)
        if key in seen:
            continue
        seen.add(key)
        found.append({"product": product, "version": version})
    return found


def _tls_info(host: str, port: int = 443, timeout: float = 8.0) -> Dict[str, object]:
    info: Dict[str, object] = {}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                info["protocol"] = tls.version() or ""
                cipher = tls.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        log.debug("TLS %s:%s 失败: %s", host, port, exc)
        return info
    if not der:
        return info
    try:  # 可选依赖：有 cryptography 时解析证书主题与有效期
        from cryptography import x509  # type: ignore

        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        info["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        info["serial"] = format(cert.serial_number, "x")
    except Exception:  # noqa: BLE001 - 解析失败不影响探测
        pass
    return info


def _decode(
    body: bytes,
    encoding: Optional[str],
    content_type: str = "",
) -> str:
    """兼容旧调用；实际解码逻辑在 utils.decode_html。"""
    return decode_html(body, encoding, content_type)


def _read_body(resp) -> bytes:
    try:
        return resp.raw.read(MAX_BODY, decode_content=True) or b""
    except Exception:  # noqa: BLE001
        try:
            return resp.content[:MAX_BODY]
        except Exception:  # noqa: BLE001
            return b""


def probe_url(
    host: str,
    url: str,
    scheme: str,
    http: HttpClient,
    timeout: float = 10.0,
) -> Optional[Service]:
    try:
        resp = http.request_raw(
            "GET",
            url,
            verify=False,
            allow_redirects=True,
            stream=True,
            timeout=timeout,
        )
    except SourceError as exc:
        log.debug("探测 %s 失败: %s", url, exc)
        return None
    body = _read_body(resp)
    text = _decode(body, resp.encoding, resp.headers.get("content-type", ""))
    headers = {key: resp.headers.get(key, "") for key in HEADER_KEYS if resp.headers.get(key)}
    headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    tech = _tech_from_text(headers_text, text[:MAX_BODY])
    generator = GENERATOR_RE.search(text)
    if generator:
        raw = clean_text(generator.group(1)).split(" - ")[0]
        parts = raw.split()
        if len(parts) >= 2 and re.match(r"^v?\d", parts[1]):
            name, version = truncate(parts[0], 40), truncate(parts[1], 32)
        else:
            name, version = truncate(raw, 48), ""
        if name and not any(name.lower() in item["product"].lower() for item in tech):
            tech.append({"product": name, "version": version})
    title_match = TITLE_RE.search(text)
    title = clean_text(title_match.group(1)) if title_match else ""
    port = 443 if scheme == "https" else 80
    parsed_port = re.match(r"^[a-z]+://[^/]+:(\d+)", url)
    if parsed_port:
        port = int(parsed_port.group(1))
    service = Service(
        host=host,
        url=resp.url or url,
        scheme=scheme,
        port=port,
        status=resp.status_code,
        title=truncate(title, 160),
        server=truncate(headers.get("server", ""), 120),
        powered_by=truncate(headers.get("x-powered-by", ""), 120),
        content_type=truncate(headers.get("content-type", ""), 120),
        length=len(body),
        redirect=resp.url if resp.url and resp.url != url else "",
        tech=tech,
        headers=headers,
        tls=_tls_info(host, port, timeout) if scheme == "https" else {},
    )
    try:
        resp.close()
    except Exception:  # noqa: BLE001
        pass
    return service


def probe_host(
    host: str,
    http: HttpClient,
    timeout: float = 10.0,
) -> List[Service]:
    """依次尝试 https / http，返回存活服务列表。"""
    services: List[Service] = []
    for scheme in ("https", "http"):
        service = probe_url(host, f"{scheme}://{host}", scheme, http, timeout)
        if service is None:
            continue
        services.append(service)
    if len(services) > 1 and any(s.scheme == "https" for s in services):
        services = [
            s
            for s in services
            if not (s.scheme == "http" and s.redirect.startswith("https://"))
        ]
    return services
