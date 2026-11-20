# tutu — 多源漏洞与威胁情报聚合搜索

[![CI](https://github.com/Moxin1044/tutu/actions/workflows/ci.yml/badge.svg)](https://github.com/Moxin1044/tutu/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tutu-vuln-intel.svg)](https://pypi.org/project/tutu-vuln-intel/)
[![Python](https://img.shields.io/pypi/pyversions/tutu-vuln-intel.svg)](https://pypi.org/project/tutu-vuln-intel/)

`tutu` 是一个 Python 编写的命令行漏洞 / 威胁情报聚合搜索工具，目标是 **开箱即用、无需配置账号或 Token**：

```bash
tutu -v CVE-2026
tutu CVE-2021-44228
tutu -t APT28
tutu -t lockbit --limit 10
```

它会并行查询多个公开数据源，把同一个 CVE 的 NVD、CISA KEV、MITRE、OSV、CISA Vulnrichment、Exploit/PoC 等结果合并成一张卡片；`-t` 则用于 APT 组织、攻击活动、威胁新闻、漏洞通告、勒索软件受害者/组织等情报。

> 所有默认源均不需要账号、API Key 或 Token。部分站点存在反爬 / 登录限制，工具会尽量抓取公开数据，并在“数据源状态”中明确标注限制，不会静默失败。

---

## 功能

- **漏洞聚合 `-v`**
  - NVD（官方 REST API 2.0）
  - CISA KEV（已知利用漏洞目录）
  - MITRE CVE / CVE.org（官方 CVE Record）
  - OSV.dev（开源生态漏洞）
  - CISA Vulnrichment（CISA ADP 富化数据）
  - Sploitus（公开 Exploit / PoC 搜索）
  - FIRST EPSS 自动富化
  - 按 CVE 合并、去重、按 KEV / 严重性 / EPSS / 时间排序
- **威胁情报 `-t`**
  - 绿盟 NTI：APT 组织、攻击活动、威胁新闻、漏洞通告
  - 360 威胁情报：公开安全通告（站内检索受限时给出入口）
  - 微步在线 X：自动过公开反爬挑战，未登录时给出站内检索入口
  - loudong.org.cn：HTML 爬虫，支持 `--deep` 翻页
  - ransomware.live：公开 API v2
  - RansomLook：公开 API
  - SOCRadar Ransomware：公开 Web API
  - Ransomwatch：GitHub 公开 JSON
- **工程化**
  - 多线程并行查询，单源失败不影响整体
  - 本地 JSON 缓存（KEV、组织列表、站点页面等）
  - `--json` 结构化输出，方便接入其他工具
  - 清晰的 Rich 终端卡片 / 状态表

---

## 安装

需要 Python 3.9+。

**从 PyPI 安装（发布后）：**

```bash
pip install tutu-vuln-intel
# 或
pipx install tutu-vuln-intel
```

安装完成后直接运行 `tutu`：

```bash
tutu --version
tutu -v CVE-2026
```

**从源码安装：**

```bash
git clone https://github.com/Moxin1044/tutu.git
cd tutu
pip install .
```

或使用 pipx：

```bash
pipx install .
```

开发模式：

```bash
pip install -e ".[dev]"
```

安装后即可直接运行 `tutu`。

如果没有 pip 环境，也可以在当前目录直接运行：

```bash
python3 -m tutu -v CVE-2026
```

---

## 使用

```bash
# 漏洞搜索：完整 CVE / CVE 前缀 / 关键词
tutu -v CVE-2021-44228
tutu -v CVE-2026
tutu CVE-2024-3400                  # 省略 -v 时默认按漏洞搜索
tutu -v log4j --limit 5

# 威胁情报
tutu -t APT28
tutu -t "LockBit"
tutu -t CVE-2021-44228
tutu -t lockbit --sources ransomware_live,ransomlook,socradar

# 同时查漏洞和情报
tutu -v CVE-2024-3400 -t CVE-2024-3400

# JSON
tutu -v CVE-2021-44228 --json > result.json

# 查看数据源
tutu sources

# 抓取 loudong 更多列表页
tutu -t CVE-2026 --sources loudong --deep
```

### 常用参数

| 参数 | 说明 |
| --- | --- |
| `-v, --vuln QUERY` | 漏洞聚合搜索 |
| `-t, --threat QUERY` | 威胁情报搜索 |
| `-s, --sources LIST` | 逗号分隔数据源，例如 `nvd,kev`；`all` 表示全部 |
| `-l, --limit N` | 每个来源 / 卡片的最大展示条数，默认 8 |
| `--timeout N` | 单请求超时秒数，默认 20 |
| `--json` | 输出 JSON |
| `--deep` | 对 loudong 等站点翻页，获得更多结果 |
| `--no-color` | 禁用彩色输出 |
| `--debug` | 输出调试日志 |
| `--version` | 版本号 |

### 数据源名称

漏洞：

```text
nvd  kev  mitre  osv  vulnrichment  sploitus  github
```

情报：

```text
nsfocus  360  threatbook  loudong  ransomware_live  ransomlook  socradar  ransomwatch
```

`github` 默认关闭：GitHub Advisory API 未认证时只有 60 次/小时。若已有 `GITHUB_TOKEN`，工具会自动读取该环境变量；不配置也能运行，只是可能被限流。

---

## 输出示例

```text
tutu  ·  漏洞与威胁情报聚合搜索
查询: CVE-2021-44228   模式: 漏洞   源: NVD, CISA KEV, MITRE CVE, ...

╭──────────────────────────────────────────────────────────────╮
│ CVE-2021-44228  CRITICAL  CVSS 10.0  KEV  勒索利用  EPSS 100%│
│ Apache Log4j2 ...                                            │
│ 来源: NVD · CISA KEV · MITRE CVE · OSV.dev · CISA Vulnrichment│
│ 发布: 2021-12-10   更新: 2026-10-24                          │
│ 标签: CWE-502, apache/log4j ...                              │
│ Exploit/PoC (5):                                             │
│   ↳ Log4Shell RCE ...                                        │
╰──────────────────────────────────────────────────────────────╯
```

`--json` 输出包含：

- `vulnerabilities`：合并后的漏洞卡片（含 KEV、EPSS、Exploit 列表）
- `exploits`：未关联到 CVE 的 Exploit/PoC
- `threat_intel`：按来源分组的情报结果
- `sources`：漏洞源状态（条数、耗时、错误、备注）

---

## 数据源与限制说明

| 源 | 类型 | 是否需要账号 | 说明 |
| --- | --- | --- | --- |
| NVD | 漏洞 | 否 | 官方 API，未认证有速率限制 |
| CISA KEV | 漏洞 | 否 | 官方 JSON，本地缓存 6 小时 |
| MITRE CVE | 漏洞 | 否 | 仅支持完整 CVE 详情 |
| OSV.dev | 漏洞 | 否 | 仅支持完整 CVE 详情 |
| CISA Vulnrichment | 漏洞 | 否 | GitHub raw JSON；未富化的 CVE 会跳过 |
| Sploitus | Exploit | 否 | 公开 POST 搜索接口 |
| 绿盟 NTI | 情报 | 否 | 公开 API，返回 APT / 活动 / 新闻 / 通告 |
| 360 威胁情报 | 情报 | 否 | 公开内容 API 只返回最新通告；站内检索被云防护拦截 |
| 微步在线 X | 情报 | 否（完整检索需登录） | 自动过公开反爬挑战；未登录只开放推荐位 |
| loudong.org.cn | 情报 | 否 | HTML 爬虫；搜索接口经常为空，高频请求会 403 |
| ransomware.live | 勒索情报 | 否 | 免费 API v2；每个端点约 1 次/分钟，结果缓存 10 分钟 |
| RansomLook | 勒索情报 | 否 | 公开 API |
| SOCRadar Ransomware | 勒索情报 | 否 | 公开 Web API；可能触发 Cloudflare 人机挑战 |
| Ransomwatch | 勒索情报 | 否 | GitHub 公开 JSON，本地缓存 12 小时 |

### 实际使用的公开接口 / 抓取路径

| 站点 | 接口 / 路径 | 用途 |
| --- | --- | --- |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE 详情 / 关键词 |
| CISA | `known_exploited_vulnerabilities.json` | KEV 全量 Feed |
| MITRE | `cveawg.mitre.org/api/cve/{id}` | CVE Record |
| OSV | `api.osv.dev/v1/vulns/{id}` | 开源漏洞 |
| FIRST | `api.first.org/data/v1/epss` | EPSS 富化 |
| Sploitus | `POST sploitus.com/search` | Exploit / PoC |
| 绿盟 NTI | `/api/v2/apt/objects/`、`/campaign/`、`/news/`、`/report/notie/` | APT / 活动 / 新闻 / 通告 |
| 360 TI | `/api/custom/sc/v3/researches` | 公开安全通告 |
| 微步 X | `/v5/node/vnext/searchAndIntelRecommend` | 公开推荐位（完整检索需登录） |
| loudong | `/search?q=`、`/vulns?page=`、`/news` | HTML 爬虫 |
| ransomware.live | `/v2/searchvictims/{q}`、`/v2/groups` | 受害者 / 组织 |
| RansomLook | `/api/search?q=` | 组织 / 帖子 |
| SOCRadar | `/api/ransomware/search?q=` | 受害者 / 组织 |
| Ransomwatch | `raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json` | 泄露帖子 |

> 这些接口均为站点前端实际调用的公开接口或公开 HTML 页面，可能随站点改版而变化；工具已对失败做降级处理，不会因单站改版而整体不可用。

### 关于反爬

- 微步在线 X 使用 `<script>Challenge=...` 类型的 JS 挑战。`tutu` 在 Python 中复刻了 `test(Challenge)` 的计算（包括 JS 中数字 + 字符串的隐式拼接），通过后再调用公开接口。
- 360 的 `ti.360.cn` 搜索 API 对非浏览器请求返回云防护拦截页；工具改用公开内容 API，并在无匹配时生成浏览器检索入口。
- SOCRadar 可能返回 Cloudflare `Just a moment...`。这属于站点策略，工具不会尝试绕过 Cloudflare 验证码，只会给出明确的失败原因。
- 请遵守目标站点条款与当地法律，控制请求频率。

---

## 缓存

默认缓存目录：

```text
~/.cache/tutu
```

可通过环境变量修改：

```bash
export TUTU_CACHE_DIR=/tmp/tutu-cache
```

缓存内容：

- CISA KEV feed：6 小时
- ransomware.live 组织列表：6 小时；受害者检索：10 分钟
- Ransomwatch：12 小时
- loudong 搜索 / 列表页：30~60 分钟

---

## 项目结构

```text
tutu/
├── cli.py                 # argparse CLI
├── search.py              # 并行调度、CVE 合并、EPSS 富化
├── render.py              # Rich 终端输出
├── http.py                # 带重试的 HTTP 客户端
├── cache.py               # 本地 JSON 缓存
├── models.py              # Item / SourceResult / VulnCard
└── sources/
    ├── nvd.py
    ├── kev.py
    ├── mitre.py
    ├── osv.py
    ├── vulnrichment.py
    ├── sploitus.py
    ├── github_advisory.py
    ├── nsfocus.py
    ├── ti360.py
    ├── threatbook.py
    ├── loudong.py
    ├── ransomware_live.py
    ├── ransomlook.py
    ├── socradar.py
    └── ransomwatch.py
```

### 添加一个新数据源

1. 在 `tutu/sources/` 下新建文件，继承 `Source`：

```python
from .base import Source
from ..models import Item

class MySource(Source):
    name = "mysource"
    label = "我的情报源"
    kind = "intel"
    description = "公开接口 / 爬虫说明"

    def _search(self, query, limit, http):
        data = http.get_json("https://example.com/api/search", params={"q": query})
        return [
            Item(
                source=self.name,
                category="news",
                title=row["title"],
                url=row["url"],
                summary=row.get("summary", ""),
            )
            for row in data.get("items", [])[:limit]
        ]
```

2. 在 `tutu/sources/__init__.py` 中 import 并加入 `VULN_SOURCE_CLASSES` 或 `INTEL_SOURCE_CLASSES`。
3. 如需默认启用，加入 `DEFAULT_VULN_SOURCES` / `DEFAULT_INTEL_SOURCES`。
4. 用 `tutu -t 关键词 -s mysource` 测试。

---

## 开发与测试

```bash
python3 -m compileall tutu
python3 -m tutu --help
python3 -m tutu -v CVE-2021-44228 --limit 3
pytest
```

---

## 免责声明

本项目仅用于合法授权的安全研究、漏洞管理与企业防御。所有数据来自第三方公开服务，工具不保证其完整性、准确性或实时性。请遵守各数据源的使用条款，不要用于未授权的攻击、扫描或数据滥用。
