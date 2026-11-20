from __future__ import annotations

import logging
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger("tutu.http")

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


class SourceError(RuntimeError):
    """单个情报源失败时抛出，不终止整个聚合流程。"""


def _short_error(exc: Exception) -> str:
    text = str(exc).strip().replace("\n", " ")
    return text[:240] or exc.__class__.__name__


class HttpClient:
    """带重试、统一 UA 的轻量 HTTP 客户端。每个线程使用独立实例。"""

    def __init__(self, timeout: float = 20.0, user_agent: str = DEFAULT_UA):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Connection": "keep-alive",
            }
        )
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            status=2,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            raise SourceError(_short_error(exc)) from exc
        if resp.status_code >= 400:
            raise SourceError(f"HTTP {resp.status_code} {resp.reason or ''}".strip())
        return resp

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def get_text(self, url: str, **kwargs: Any) -> str:
        resp = self.get(url, **kwargs)
        if not resp.encoding or resp.encoding.lower() == "iso-8859-1":
            resp.encoding = resp.apparent_encoding or "utf-8"
        return resp.text

    def get_json(self, url: str, **kwargs: Any) -> Any:
        resp = self.get(url, **kwargs)
        try:
            return resp.json()
        except ValueError as exc:
            raise SourceError("响应不是合法 JSON（可能被 WAF/登录页拦截）") from exc

    def post_json(self, url: str, payload: Any, **kwargs: Any) -> Any:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("Accept", "application/json")
        resp = self.post(url, json=payload, headers=headers, **kwargs)
        try:
            return resp.json()
        except ValueError as exc:
            raise SourceError("响应不是合法 JSON") from exc
