from __future__ import annotations

import math
import re
from typing import Any, List
from urllib.parse import quote

from ..http import HttpClient, SourceError
from ..models import Item
from ..utils import clean_text, truncate
from .base import Source

BASE = "https://x.threatbook.com"
HOME = BASE + "/"
RECOMMEND_API = BASE + "/v5/node/vnext/searchAndIntelRecommend"
CHALLENGE_RE = re.compile(r"Challenge=(\d+)")
CHALLENGE_ID_RE = re.compile(r"ChallengeId=(\d+)")


def solve_challenge(challenge: str) -> str:
    """复刻微步反爬页里的 JavaScript test(Challenge)。

    注意：var_arr.sort() 后 subvar2 = (2 * a[2]) + a[1] 在 JS 中是
    数字 + 字符串的字符串拼接；最后 answer += subvar2 也是拼接。
    """
    arr = list(str(challenge))
    last_dig = arr[::-1][0]
    arr.sort()
    min_dig = arr[0]
    subvar1 = 2 * int(arr[2]) + int(arr[1])
    subvar2 = str(2 * int(arr[2])) + arr[1]
    my_pow = (int(arr[0]) + 2) ** int(arr[1])
    x = int(challenge) * 3 + subvar1
    y = math.cos(math.pi * float(subvar2))
    answer = int(x * y) - my_pow + (int(min_dig) - int(last_dig))
    return str(answer) + subvar2


def _csrf_token(html: str) -> str:
    match = re.search(r'"csrf"\s*:\s*"([^"]+)"', html)
    return match.group(1) if match else ""


class ThreatBookSource(Source):
    name = "threatbook"
    label = "微步在线 X"
    kind = "intel"
    description = "微步在线 X 情报社区（需过公开反爬挑战；未登录仅开放推荐位）"

    def _bootstrap(self, http: HttpClient) -> str:
        resp = http.get(HOME, headers={"Referer": HOME})
        text = resp.text
        for _ in range(3):
            challenge = CHALLENGE_RE.search(text)
            challenge_id = CHALLENGE_ID_RE.search(text)
            if not challenge or not challenge_id:
                break
            value = challenge.group(1)
            result = solve_challenge(value)
            http.post(
                HOME,
                headers={
                    "X-AA-Challenge-ID": challenge_id.group(1),
                    "X-AA-Challenge-Result": result,
                    "X-AA-Challenge": value,
                    "Content-Type": "text/plain",
                    "Referer": HOME,
                    "Origin": BASE,
                },
                data="",
            )
            text = http.get(HOME, headers={"Referer": HOME}).text
        if CHALLENGE_RE.search(text):
            raise SourceError("微步反爬挑战未通过")
        return text

    def _search(self, query: str, limit: int, http: HttpClient) -> List[Item]:
        home = self._bootstrap(http)
        token = _csrf_token(home)
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Referer": HOME,
            "X-csrf-token": token,
        }
        data = http.get_json(
            RECOMMEND_API,
            params={"keyword": query},
            headers=headers,
        )
        payload = data.get("data") or {}
        needle = query.lower()
        items: List[Item] = []

        for row in payload.get("intelligence") or []:
            keyword = clean_text(row.get("keyword") or "")
            if needle not in keyword.lower():
                continue
            bits = []
            if row.get("holeClassZh"):
                bits.append(f"漏洞类型: {row['holeClassZh']}")
            if row.get("riskLevel"):
                bits.append(f"风险: {row['riskLevel']}")
            if row.get("judgment"):
                bits.append(f"判定: {row['judgment']}")
            items.append(
                Item(
                    source=self.name,
                    category="ioc",
                    title=keyword,
                    url=f"{BASE}/v5/generalSearch?baseq={quote(keyword, safe='')}",
                    summary=" · ".join(bits),
                    tags=[clean_text(row.get("riskLevel") or "")],
                    extra={"keyword": keyword, "raw": row},
                )
            )
            if len(items) >= limit:
                break

        for row in payload.get("recommend") or []:
            if len(items) >= limit:
                break
            title = clean_text(row.get("keyword") or "")
            if needle not in title.lower():
                continue
            items.append(
                Item(
                    source=self.name,
                    category="news",
                    title=title,
                    url=clean_text(row.get("url") or ""),
                    summary="微步在线公开推荐内容",
                    tags=["推荐"],
                )
            )

        for row in payload.get("search") or []:
            if len(items) >= limit:
                break
            keyword = clean_text(row.get("keyword") or "")
            if needle not in keyword.lower():
                continue
            items.append(
                Item(
                    source=self.name,
                    category="ioc",
                    title=keyword,
                    url=f"{BASE}/v5/generalSearch?baseq={quote(keyword, safe='')}",
                    summary=f"关联检索词 · 命中 {row.get('count', 'N/A')}",
                    tags=["热搜"],
                )
            )

        if not items:
            self.last_note = (
                "微步未登录状态下只开放推荐位，完整情报/漏洞检索需要登录；"
                "已生成站内检索入口。"
            )
            items.append(
                Item(
                    source=self.name,
                    category="portal",
                    title="微步在线 X · 站内检索入口",
                    url=f"{BASE}/v5/generalSearch?baseq={quote(query, safe='')}",
                    summary=truncate(
                        "反爬挑战已通过，但微步对未登录用户隐藏了完整搜索结果。"
                        "点击此链接可在浏览器中登录后继续检索。",
                        300,
                    ),
                    tags=["入口", "需登录"],
                    extra={"portal": True},
                )
            )
        return items
