"""TCP connect 端口扫描（仅在显式指定 --ports 时启用）。

扫描以 IP 为单位执行，因此一个域名解析到多个 A/AAAA 记录时，每个 IP
都会单独扫描；对常见 Web 端口会额外发送 HTTP(S) 请求，识别状态码、
Server、页面标题与技术栈。
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..utils import decode_html, repair_mojibake, truncate
from .models import PortResult
from .probe import TITLE_RE, _tech_from_text

log = logging.getLogger("tutu.assets.ports")

TOP_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 83, 84, 85, 88, 89,
    99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
    163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465,
    481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555,
    563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687,
    691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801,
    808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990,
    992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022,
    1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034,
    1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046,
    1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
    1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069,
]

WEB_PORTS = [
    80, 81, 443, 591, 3000, 4443, 5000, 7001, 7002, 8000, 8008, 8080, 8081,
    8088, 8090, 8181, 8443, 8888, 9000, 9001, 9090, 9200, 9443, 10000, 10443,
]

PORT_SERVICES: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 500: "isakmp", 512: "rexec", 513: "rlogin", 514: "rsh",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "http-dev", 3260: "iscsi", 3306: "mysql", 3389: "rdp", 4369: "epmd",
    5000: "http-dev", 5432: "postgres", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 6443: "k8s-api",
    7001: "weblogic", 7002: "weblogic-tls", 8000: "http-alt", 8009: "ajp",
    8080: "http-alt", 8081: "http-alt", 8088: "http-alt", 8161: "activemq",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9001: "http-alt",
    9042: "cassandra", 9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 9443: "https-alt", 10000: "webmin",
    10250: "kubelet", 11211: "memcached", 15672: "rabbitmq", 27017: "mongodb",
    27018: "mongodb", 50000: "sap", 50070: "hadoop", 61616: "activemq",
}

BANNER_PORTS = {21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 3306, 5432, 6379, 11211, 27017}

TLS_PORTS = {
    443, 465, 636, 853, 990, 992, 993, 995, 2376, 5986, 6443, 7002, 8443,
    9443, 10443,
}

_BANNER_HINTS = [
    (re.compile(r"^SSH-", re.I), "ssh"),
    (re.compile(r"^220.*(?:FTP|ftp)", re.I), "ftp"),
    (re.compile(r"^220.*SMTP", re.I), "smtp"),
    (re.compile(r"^\+OK", re.I), "pop3"),
    (re.compile(r"^\* OK", re.I), "imap"),
    (re.compile(r"REDIS", re.I), "redis"),
    (re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+.*MariaDB", re.I), "mysql"),
    (re.compile(r"PostgreSQL", re.I), "postgres"),
]

_TLS_CONTEXT = ssl.create_default_context()
_TLS_CONTEXT.check_hostname = False
_TLS_CONTEXT.verify_mode = ssl.CERT_NONE

_HTTP_REQUEST = (
    "GET / HTTP/1.0\r\n"
    "Host: {host}\r\n"
    "User-Agent: Mozilla/5.0 (compatible; tutu/0.4; +https://github.com/Moxin1044/tutu-cli)\r\n"
    "Accept: */*\r\n"
    "Connection: close\r\n\r\n"
).encode("ascii")


class PortSpecError(ValueError):
    pass


def parse_ports(spec: Optional[str]) -> List[int]:
    """解析 `80,443`、`1-1024`、`top100`、`web` 等端口表达式。"""
    if not spec:
        return []
    text = spec.strip().lower()
    if text in ("top100", "top", "default"):
        return sorted(set(TOP_PORTS))
    if text in ("web", "http"):
        return sorted(set(WEB_PORTS))
    ports: set = set()
    for part in re.split(r"[,\s]+", text):
        part = part.strip()
        if not part:
            continue
        if part in ("top100", "top"):
            ports.update(TOP_PORTS)
            continue
        if part in ("web", "http"):
            ports.update(WEB_PORTS)
            continue
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if match:
            start, end = int(match.group(1)), int(match.group(2))
            if start < 1 or end > 65535 or start > end:
                raise PortSpecError(f"无效端口区间: {part}")
            ports.update(range(start, end + 1))
            continue
        if part.isdigit():
            port = int(part)
            if port < 1 or port > 65535:
                raise PortSpecError(f"无效端口: {part}")
            ports.add(port)
            continue
        raise PortSpecError(f"无法解析端口: {part}")
    if len(ports) > 5000:
        raise PortSpecError(f"端口数量 {len(ports)} 过多，请缩小范围（上限 5000）")
    return sorted(ports)


def _service_for(port: int, banner: str) -> str:
    for pattern, name in _BANNER_HINTS:
        if pattern.search(banner or ""):
            return name
    return PORT_SERVICES.get(port, "")


def _recv(sock, limit: int = 32768) -> bytes:
    chunks: List[bytes] = []
    total = 0
    while total < limit:
        try:
            chunk = sock.recv(min(8192, limit - total))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _http_probe(ip: str, port: int, timeout: float) -> Optional[Dict[str, object]]:
    """通过 HTTP(S) 请求识别 Web 服务；失败时返回 None，但不影响端口存活结论。"""
    tls = port in TLS_PORTS
    request = _HTTP_REQUEST.replace(b"{host}", ip.encode("ascii", "ignore"))
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(min(4.0, max(1.0, timeout)))
            if tls:
                with _TLS_CONTEXT.wrap_socket(sock, server_hostname=ip) as tls_sock:
                    tls_sock.sendall(request)
                    raw = _recv(tls_sock)
            else:
                sock.sendall(request)
                raw = _recv(sock)
    except (OSError, ssl.SSLError):
        return None
    if not raw:
        return None
    text = decode_html(raw, None, "text/html")
    status = 0
    match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", text[:400], re.I)
    if match:
        status = int(match.group(1))
    server_match = re.search(r"(?im)^Server:\s*(.+?)\s*$", text[:8192])
    server = repair_mojibake((server_match.group(1) if server_match else "").strip())
    title_match = TITLE_RE.search(text)
    title = repair_mojibake(title_match.group(1).strip()) if title_match else ""
    tech = _tech_from_text(text[:8192], text[: 96 * 1024])
    banner_parts = [
        f"HTTP {status}" if status else "HTTP",
        f"Server: {server}" if server else "",
        truncate(title, 80) if title else "",
    ]
    return {
        "scheme": "https" if tls else "http",
        "status": status,
        "title": truncate(title, 120),
        "tech": [
            f"{row.get('product', '')} {row.get('version', '')}".strip()
            for row in tech
            if row.get("product")
        ],
        "banner": truncate(" | ".join(part for part in banner_parts if part), 200),
    }


def _scan_one(host: str, ip: str, port: int, timeout: float) -> Optional[PortResult]:
    banner = ""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(min(1.5, max(0.3, timeout)))
            if port in BANNER_PORTS:
                raw = _recv(sock, 256)
                banner = repair_mojibake(decode_html(raw, None).strip())
    except (socket.timeout, OSError):
        return None

    web = _http_probe(ip, port, timeout) if (port in WEB_PORTS or banner.startswith("HTTP/")) else None
    if web:
        return PortResult(
            host=host,
            ip=ip,
            port=port,
            service=str(web.get("scheme") or "http"),
            scheme=str(web.get("scheme") or ""),
            status=int(web.get("status") or 0),
            title=str(web.get("title") or ""),
            tech=list(web.get("tech") or []),
            banner=str(web.get("banner") or ""),
        )
    return PortResult(
        host=host,
        ip=ip,
        port=port,
        service=_service_for(port, banner),
        banner=banner[:200],
    )


def scan_targets(
    targets: Sequence[Tuple[str, str]],
    ports: Iterable[int],
    timeout: float = 2.0,
    threads: int = 64,
    max_checks: int = 50000,
) -> List[PortResult]:
    """扫描 (host, ip) 列表；同一 IP 的端口探测可被多个主机共享。"""
    port_list = list(ports)
    if not targets or not port_list:
        return []
    total = len(targets) * len(port_list)
    if total > max_checks:
        raise ValueError(
            f"端口扫描组合过多（{len(targets)} 主机 × {len(port_list)} 端口 = {total}），"
            f"请缩小范围或提高 --max-checks（当前上限 {max_checks}）"
        )
    results: List[PortResult] = []
    with ThreadPoolExecutor(max_workers=max(1, min(threads, 256))) as pool:
        futures = [
            pool.submit(_scan_one, host, ip, port, timeout)
            for host, ip in targets
            for port in port_list
        ]
        for future in as_completed(futures):
            try:
                item = future.result()
            except Exception:  # noqa: BLE001
                continue
            if item is not None:
                results.append(item)
    results.sort(key=lambda r: (r.ip, r.host, r.port))
    return results


def scan_ips(
    ips: Sequence[str],
    ports: Iterable[int],
    timeout: float = 2.0,
    threads: int = 64,
    max_checks: int = 50000,
) -> List[PortResult]:
    """按 IP 扫描端口（host 与 ip 相同）。"""
    unique: List[str] = []
    for ip in ips:
        if ip and ip not in unique:
            unique.append(ip)
    return scan_targets(
        [(ip, ip) for ip in unique],
        ports,
        timeout=timeout,
        threads=threads,
        max_checks=max_checks,
    )


def scan_hosts(
    hosts: Sequence[str],
    ports: Iterable[int],
    timeout: float = 2.0,
    threads: int = 64,
    max_checks: int = 50000,
) -> List[PortResult]:
    """兼容旧接口：主机名与扫描地址相同。"""
    return scan_targets(
        [(host, host) for host in hosts],
        ports,
        timeout=timeout,
        threads=threads,
        max_checks=max_checks,
    )
