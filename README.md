# tutu — 多源漏洞与威胁情报聚合搜索

[![CI](https://github.com/Moxin1044/tutu-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Moxin1044/tutu-cli/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tutu-cli.svg)](https://pypi.org/project/tutu-cli/)
[![Python](https://img.shields.io/pypi/pyversions/tutu-cli.svg)](https://pypi.org/project/tutu-cli/)

`tutu` 是一个 Python 编写的命令行漏洞 / 威胁情报聚合搜索工具，目标是 **开箱即用、无需配置账号或 Token**：

```bash
tutu -v CVE-2026
tutu CVE-2021-44228
tutu -v CVE-2021-44228 --product log4j --check-version 2.14.1
tutu -t APT28
tutu -t lockbit --limit 10
tutu -asset example.com
tutu -asset example.com --ports top100 --ip-intel --reverse-ip
tutu -ip 8.8.8.8
tutu -icp example.com
tutu -asset example.com -o assets.xlsx
```

它会并行查询多个公开数据源，把同一个 CVE 的 NVD、CISA KEV、MITRE、OSV、CISA Vulnrichment、Exploit/PoC 等结果合并成一张卡片；`-t` 则用于 APT 组织、攻击活动、威胁新闻、漏洞通告、勒索软件受害者/组织等情报。

`-asset` 用公开被动数据搜集子域名，再做 DNS 解析、HTTP 指纹和（可选的）端口扫描，把域名 → IP → 端口 → 服务 → 关联 CVE 整理成一张攻击面清单；`-ip` 可反查与 IP 关联的域名，`-icp` 可查询备案信息；任意模式都可用 `-o` 导出 JSON / CSV / XLSX。

> 所有默认源均不需要账号、API Key 或 Token。部分站点存在访问或登录限制，工具会尽量使用公开数据，并在“数据源状态”中明确标注限制，不会静默失败。

---

## 功能

- **漏洞聚合 `-v`**
  - NVD（官方 REST API 2.0）
  - CISA KEV（已知利用漏洞目录）
  - MITRE CVE / CVE.org（官方 CVE Record）
  - OSV.dev（开源生态漏洞）
  - CISA Vulnrichment（CISA ADP 富化数据）
  - ProjectDiscovery vulnx（CVE / Nuclei 模板 / POC / KEV）
  - SOCRadar CVE（CVE 详情 / Exploit-DB / SSVC）
  - Exploit-DB（官方 Git 仓库 CSV）
  - Red Hat Security Data（受影响产品 / 厂商 CVSS）
  - Sploitus（公开 Exploit / PoC 搜索）
  - FIRST EPSS 自动富化
  - 按 CVE 合并、去重、按 KEV / 严重性 / EPSS / 时间排序
  - 卡片展示 🎯 Affected Products（NVD CPE / SOCRadar / vulnx / Red Hat / OSV 等）
  - 卡片展示 📦 受影响版本区间（NVD CPE / OSV ranges / MITRE / Vulnrichment / GitHub Advisory）
  - `--check-version` 判断自己使用的版本是否落在受影响区间
- **资产搜集 / 攻击面 `-asset`**
  - 被动子域名：crt.sh、Cert Spotter、HackerTarget、RapidDNS、urlscan.io、subdomain.center
  - DNS 解析：A / AAAA / CNAME（可选 MX / NS / TXT），优先 DNS-over-HTTPS，失败回退系统解析
  - 泛解析（wildcard DNS）检测
  - HTTP(S) 存活探测：状态码、标题、Server / X-Powered-By、跳转、TLS 信息
  - Web 技术栈指纹（nginx、Apache、IIS、PHP、Tomcat、WordPress、Spring、WebLogic、Shiro、ThinkPHP…）
  - 可选 TCP connect 端口扫描（`--ports top100|web|80,443|1-1024`，默认关闭）
  - 按解析到的每个 IP 分别扫描端口；Web 端口额外识别状态码、Server、标题与技术栈
  - 域名解析到多个 A/AAAA 记录时，每个 IP 的结果都会归属到对应域名
  - 可选 IP 反查域名（`--reverse-ip`）：webscan.cc / HackerTarget / OTX / RapidDNS
  - 默认查询根域 ICP 备案（`--no-icp` 关闭）
  - 资产指纹与 NVD 关联漏洞（只对带版本号的技术栈查询）
  - 可选 IP 情报（`--ip-intel`）：信誉、ASN / 组织、被动端口
- **IP 反查 / 备案 `-ip` / `-icp`**
  - `-ip` 默认反查与 IP 关联的域名（`--no-reverse` 关闭，`--reverse-limit` 限制数量）
  - `-icp` 支持域名、备案号（如 `豫ICP备16005160号`）与主办单位名称
  - 反查结果缓存 6 小时，ICP 结果缓存 1 小时，只缓存有结果的查询
- **结果导出 `-o`**
  - `-o result.json` / `-o result.csv` / `-o result.xlsx`，格式按扩展名判断
  - `--export-format` 可覆盖格式；`--json` 与 `-o` 可同时使用
  - CSV 使用 `utf-8-sig`，Excel 打开中文不乱码；XLSX 分 sheet 展示资产、端口、反查、备案与 CVE
- **威胁情报 `-t`**
  - 绿盟 NTI：APT 组织、攻击活动、威胁新闻、漏洞通告
  - 360 威胁情报：公开安全通告（站内检索受限时给出入口）
  - 微步在线 X：公开接口 + 未登录检索入口
  - loudong.org.cn：HTML 爬虫，支持 `--deep` 翻页
  - SOCRadar IOC：恶意 IP / 域名 / URL / 哈希指标
  - ransomware.live：公开 API v2
  - RansomLook：公开 API
  - SOCRadar Ransomware：公开 Web API
  - Ransomwatch：GitHub 公开 JSON
- **IP / 哈希 / 文件 `-ip` `-hash` `-file`**
  - IP 信誉、地理位置、ASN/组织、代理/IDC 标记
  - IP 情报：SOCRadar IOC、ThreatBook、VirusTotal、AlienVault OTX
  - 哈希情报：SOCRadar IOC、CIRCL Hashlookup、OTX、ThreatBook、VirusTotal
  - 文件本地哈希（MD5/SHA1/SHA256/SHA512）、类型识别
  - VirusTotal / 微步沙箱上传与多引擎结果
- **本地配置 `-config`**
  - 交互式配置微步在线 API Key、VirusTotal API Key
  - 保存到本地 `~/.config/tutu/config.json`，权限 `0600`
  - 支持环境变量覆盖，不把 Key 写入仓库
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
pip install tutu-cli
# 或
pipx install tutu-cli
```

安装完成后直接运行 `tutu`：

```bash
tutu --version
tutu -v CVE-2026
```

**从源码安装：**

```bash
git clone https://github.com/Moxin1044/tutu-cli.git
cd tutu-cli
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

# IP 信誉 / 归属 / IOC
tutu -ip 8.8.8.8
tutu -ip 159.203.93.255 --json

# 哈希情报
tutu -hash 44d88612fea8a8f36de82e1278abb02f

# 文件本地哈希 + 公开情报 + 沙箱上传（需要 Key）
tutu -file sample.exe
tutu -file sample.exe --no-upload
tutu -file sample.exe --sandbox win10_1903_enx64_office2016 --run-time 120

# 受影响版本判定：本地版本是否落在披露区间内
tutu -v CVE-2021-44228 --product log4j --check-version 2.14.1
tutu -v CVE-2024-3400 --product pan-os --check-version 10.2.9

# 资产搜集 / 攻击面梳理
tutu -asset example.com                        # 被动子域名 + DNS + HTTP 指纹 + ICP
tutu -asset example.com --ports web            # 额外扫描常见 Web 端口
tutu -asset example.com --ports 80,443,8080    # 指定端口
tutu -asset 203.0.113.10 --ports top100        # 单 IP 资产
tutu -asset 10.0.0.0/24 --ports web            # CIDR（受 --asset-limit 限制）
tutu -asset example.com --no-probe --json      # 只做子域名与 DNS，输出 JSON
tutu -asset example.com --ip-intel             # 补充 IP 信誉 / 归属 / 被动端口
tutu -asset example.com --reverse-ip           # 按每个公网 IP 反查关联域名
tutu -asset example.com --no-icp               # 跳过 ICP 备案查询
tutu -asset example.com --no-asset-vuln        # 不做 NVD 漏洞关联

# IP 反查域名 / ICP 备案
tutu -ip 8.8.8.8                               # 默认附带反查域名
tutu -ip 8.8.8.8 --no-reverse                  # 只看 IP 情报
tutu -ip 8.8.8.8 --reverse-limit 30            # 每个 IP 最多保留 30 个域名
tutu -icp example.com                          # 按域名查备案
tutu -icp 豫ICP备16005160号                     # 按备案号查
tutu -icp 信阳职业技术学院                        # 按主办单位查

# 导出（json / csv / xlsx）
tutu -asset example.com -o assets.xlsx
tutu -ip 8.8.8.8 -o ip.csv
tutu -icp example.com -o icp.json
tutu -v CVE-2021-44228 -o cve.xlsx
tutu -asset example.com --json -o assets.json  # 终端 JSON + 另存文件

# 配置微步 / VirusTotal API Key（本地持久化）
tutu -config
tutu config show
tutu config set threatbook <KEY>
tutu config set virustotal <KEY>
tutu config path

# JSON
tutu -v CVE-2021-44228 --json > result.json
tutu -ip 8.8.8.8 --json > ip.json

# 查看数据源
tutu sources

# 抓取 loudong 更多列表页
tutu -t CVE-2026 --sources loudong --deep
```

### API Key 配置

`-v` / `-t` 不需要任何 Key。`-ip` / `-hash` / `-file` 会自动使用已配置的微步和 VirusTotal Key 补充情报：

```bash
tutu -config
```

建议用交互方式输入 Key，避免出现在 shell history；`tutu config set ...` 仅用于自动化环境。

配置文件默认位置：

```text
~/.config/tutu/config.json
```

权限为 `0600`。也可以使用环境变量（优先级高于配置文件）：

```bash
export TUTU_THREATBOOK_API_KEY=...
export TUTU_VIRUSTOTAL_API_KEY=...
```

支持的其他变量名：

```text
THREATBOOK_API_KEY
VIRUSTOTAL_API_KEY
VT_API_KEY
```

`-file` 默认会在配置了 Key 时上传到 VirusTotal / 微步沙箱；如果只想本地计算哈希和查询公开情报库：

```bash
tutu -file sample.exe --no-upload
```

> 上传文件前请确认文件内容可以发送给第三方沙箱。工具不会上传未配置 Key 的站点。

### 常用参数

| 参数 | 说明 |
| --- | --- |
| `-v, --vuln QUERY` | 漏洞聚合搜索 |
| `-t, --threat QUERY` | 威胁情报搜索 |
| `-ip, --ip IP` | IP 信誉 / 归属 / IOC 查询（默认附带反查域名） |
| `-icp, --icp QUERY` | ICP 备案查询：域名 / 备案号 / 主办单位名称 |
| `--reverse-ip` | 资产模式：按解析到的每个公网 IP 反查关联域名 |
| `--reverse-limit N` | 每个 IP 最多保留多少个反查域名（默认 100） |
| `--no-reverse` | `-ip` 查询时跳过反查域名 |
| `--no-icp` | 资产模式跳过 ICP 备案查询 |
| `-o, --output PATH` | 导出结果到 `.json` / `.csv` / `.xlsx`（可与终端输出同时使用） |
| `--export-format {json,csv,xlsx}` | 覆盖导出格式；默认按文件扩展名判断 |
| `-hash, --hash HASH` | MD5 / SHA1 / SHA256 哈希查询 |
| `-file, --file PATH` | 文件哈希、公开情报与沙箱上传 |
| `-asset, --asset DOMAIN|IP|CIDR` | 资产搜集：子域名 / DNS / 存活 / 指纹 / 端口 / 关联漏洞 |
| `--check-version VERSION` | 配合 `-v`：判断该版本是否在受影响区间内 |
| `--product NAME` | 配合 `--check-version` 指定产品名 |
| `--ports PORTS` | 资产模式端口：`top100` / `web` / `80,443` / `1-1024`（默认关闭） |
| `--no-probe` | 资产模式跳过 HTTP(S) 存活探测 |
| `--asset-limit N` | 资产模式最多处理多少个子域名（默认 120） |
| `--threads N` | 资产模式并发线程数（默认 12） |
| `--no-asset-vuln` | 资产模式不做 NVD 漏洞关联 |
| `--max-fingerprints N` | 资产模式最多关联多少个技术栈指纹（默认 5） |
| `--ip-intel` | 资产模式补充公网 IP 信誉 / 归属 / 被动端口 |
| `-config, --config` | 交互配置微步 / VirusTotal API Key |
| `--no-upload` | `-file` 只做本地哈希和公开情报查询 |
| `--sandbox TYPE` | 微步沙箱类型，默认 `win7_sp1_enx86_office2013` |
| `--run-time SEC` | 微步沙箱运行时间，默认 60 秒 |
| `-s, --sources LIST` | 逗号分隔数据源，例如 `nvd,kev`；`all` 表示全部 |
| `-l, --limit N` | 每个来源 / 卡片的最大展示条数，默认 8 |
| `--timeout N` | 单请求超时秒数，默认 20 |
| `--json` | 输出 JSON |
| `--deep` | 对 loudong 等站点翻页，获得更多结果 |
| `--no-color` | 禁用彩色输出 |
| `--debug` | 输出调试日志 |
| `--version` | 版本号 |

### 资产搜集（攻击面）

`-asset` 按下面的顺序整理攻击面：

```text
域名
 ├─ 被动子域名（crt.sh / Cert Spotter / HackerTarget / RapidDNS / urlscan.io / subdomain.center）
 ├─ DNS 解析（A / AAAA / CNAME，DoH 优先）
 ├─ HTTP(S) 存活探测（状态码 / 标题 / Server / 跳转 / TLS）
 ├─ Web 技术栈指纹（产品 + 版本）
 ├─ 可选端口扫描（--ports，默认关闭；按每个解析 IP 分别扫描）
 ├─ 可选 IP 反查域名（--reverse-ip）
 ├─ ICP 备案（默认开启，--no-icp 关闭）
 └─ 与 NVD 关联（只对带版本号的指纹查询，最多 --max-fingerprints 个）
```

默认行为是“被动优先”：

- 输入支持域名、单个 IP 或 CIDR；IP / CIDR 会跳过被动子域名源，并按 `--asset-limit` 限制地址数量；
- 只访问公开的证书日志 / 公开 API / 目标自身的 HTTP(S) 端口，不爆破子域名；
- 端口扫描默认关闭，必须显式指定 `--ports`；一个域名解析到多个 IP 时，每个 IP 都会被扫描；
- 默认每域名最多处理 120 个子域名（`--asset-limit`），避免误伤大域；
- 扫描组合上限 50000（主机 × 端口），超过会直接报错；
- ICP 查询默认使用根域；`--reverse-ip` 只对公网 IP 反查，且每个 IP 最多保留 `--reverse-limit` 个域名。

示例输出（简略）：

```text
资产攻击面  example.com
子域名 42   主机 40   存活 12   服务 18   开放端口 6   关联 CVE 3   耗时 18.4s
ICP 备案  示例单位  京ICP备00000000号-1  企业

资产清单
主机                 IP               HTTP  标题 / 技术栈            来源
www.example.com      93.184.216.34    200   Example  nginx 1.18.0   crtsh, rapiddns
...
开放端口 / 服务
目标              IP              端口  服务    HTTP  标题 / 技术栈
www.example.com   93.184.216.34   443   https   200   Example  nginx 1.18.0
资产关联漏洞（NVD 指纹匹配）
CVE-2021-23017       HIGH   www.example.com  nginx 1.18.0  f5/nginx 0.6.18 ~ 1.20.1
```

说明：

- 漏洞关联使用 NVD `virtualMatchString`，每个指纹一次请求；未认证时 NVD 约 5 次/30 秒，可通过环境变量 `NVD_API_KEY` / `TUTU_NVD_API_KEY` 提高配额。
- 指纹版本来自响应头（如 `Server: nginx/1.18.0`）或页面特征，识别不到版本时会跳过关联，避免误报。
- 端口扫描以 IP 为单位执行，同一 IP 只扫一次，结果按域名的 DNS 归属展开。
- Web 端口会额外发送一次 HTTP(S) 请求，识别状态码、`Server`、页面标题与技术栈；失败不影响端口存活结论。
- 中文标题会按 UTF-8 / GB18030 / 页面声明编码依次尝试，避免 `ISO-8859-1` 默认解码造成乱码。
- `--ip-intel` 会额外调用 IP 情报源；对公网 IP 默认最多查询 20 个。
- **请只对自己拥有或已获授权的资产使用端口扫描与存活探测。**

JSON：

```bash
tutu -asset example.com --ports web --json > assets.json
```

输出包含 `assets[]`（子域名、IP、CNAME、服务、开放端口含 `ip/service/status/title/tech`）、`cve_hits[]`、`reverse_ips[]`、`icp`、`source_results[]`、`stats` 与 `notes`。

### IP 反查域名与 ICP 备案

`-ip` 默认会附带“反查域名（被动 DNS）”，使用以下公开来源合并去重：

```text
webscan.cc     公开反查接口，通常带页面标题，国内覆盖较好
HackerTarget   reverseiplookup，免费额度有限
OTX AlienVault 被动 DNS 历史记录
RapidDNS       sameip 聚合页
```

反查结果缓存 6 小时，只缓存有结果的查询；`--no-reverse` 可只看 IP 情报，`--reverse-limit` 控制每个 IP 保留的域名数量。

`-icp` 支持三种查询方式：

```bash
tutu -icp example.com             # 域名
tutu -icp 豫ICP备16005160号        # 备案号
tutu -icp 信阳职业技术学院          # 主办单位
```

主数据源为糖豆子 API（数据来自工信部，接口自带缓存），失败时会尝试 vvhan / oioweb / uomg 等公开备用源；结果缓存 1 小时。备案接口约 1 秒 1 次，频繁调用可能被临时限流。

### 导出结果

```bash
tutu -asset example.com -o assets.xlsx
tutu -asset example.com -o assets.csv
tutu -ip 8.8.8.8 -o ip.json
tutu -icp example.com -o icp.xlsx
tutu -v CVE-2021-44228 -o cve.xlsx
```

- 格式默认按扩展名判断，也可用 `--export-format json|csv|xlsx` 覆盖；
- `--json` 与 `-o` 可以同时使用：JSON 输出到终端，`-o` 另写文件；
- CSV 使用 `utf-8-sig`，Excel 直接打开中文不乱码；
- XLSX 需要 `openpyxl`（已列入依赖），缺少时会提示安装命令；
- 资产 XLSX 包含 `资产清单`、`开放端口`、`反查域名`、`ICP备案`、`关联CVE`、`数据源` 六个 sheet。

### 数据源名称

漏洞：

```text
nvd  kev  mitre  osv  vulnrichment  vulnx  socradar_cve
exploitdb  sploitus  redhat  github
```

情报：

```text
nsfocus  360  threatbook  loudong  socradar_ioc
ransomware_live  ransomlook  socradar  ransomwatch
```

资产（被动）：

```text
crtsh  certspotter  hackertarget  rapiddns  urlscan  subdomain_center
```

IP 反查 / 备案：

```text
webscan  hackertarget  otx  rapiddns        # IP 反查域名
tangdouz  vvhan  oioweb  uomg               # ICP 备案（主源 + 备用源）
```

- `github` 默认关闭：GitHub Advisory API 未认证时只有 60 次/小时。若已有 `GITHUB_TOKEN`，工具会自动读取该环境变量。
- `vulnx` 无需 Key；如果设置了 `PDCP_API_KEY` / `TUTU_PDCP_API_KEY`，会自动使用 ProjectDiscovery 的更高配额。
- `exploitdb` 首次查询会下载官方 CSV（约 10MB），之后缓存 24 小时。
- `socradar_cve` / `socradar_ioc` 使用公开 Web API，可能受站点访问策略影响；失败不会影响其他源。

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
│ 📦 受影响版本: apache/log4j 2.0.1 ~ 2.3.1 · 2.4.0 ~ 2.12.2  │
│ 标签: CWE-502, apache/log4j ...                              │
│ Exploit/PoC (5):                                             │
│   ↳ Log4Shell RCE ...                                        │
╰──────────────────────────────────────────────────────────────╯
```

`--json` 输出包含：

- `vulnerabilities`：合并后的漏洞卡片（含 KEV、EPSS、`affected_products`、`affected_versions`、`version_ranges`、Exploit 列表）
- `exploits`：未关联到 CVE 的 Exploit/PoC
- `threat_intel`：按来源分组的情报结果
- `sources`：漏洞源状态（条数、耗时、错误、备注）
- `version_check`：使用 `--check-version` 时给出 `affected` / `unaffected` / `unknown`

`-asset --json` 输出包含 `assets`（子域名、IP、CNAME、服务、端口）、`cve_hits`、`reverse_ips`、`icp`、`source_results`、`stats` 与 `notes`。

`-ip --json` 的 `reverse` 字段包含反查到的 `domains`、`titles`、`sources` 与各来源错误；`-icp --json` 包含 `records`（主办单位 / 性质 / 备案号 / 审核时间）与 `source`。

---

## 数据源与限制说明

| 源 | 类型 | 是否需要账号 | 说明 |
| --- | --- | --- | --- |
| NVD | 漏洞 | 否 | 官方 API，未认证有速率限制 |
| CISA KEV | 漏洞 | 否 | 官方 JSON，本地缓存 6 小时 |
| MITRE CVE | 漏洞 | 否 | 仅支持完整 CVE 详情 |
| OSV.dev | 漏洞 | 否 | 仅支持完整 CVE 详情 |
| CISA Vulnrichment | 漏洞 | 否 | GitHub raw JSON；未富化的 CVE 会跳过 |
| ProjectDiscovery vulnx | 漏洞 | 否 | 公开 API；可选用 `PDCP_API_KEY` 提升配额 |
| SOCRadar CVE | 漏洞 | 否 | 公开 Web API；可能受访问策略影响 |
| Exploit-DB | Exploit | 否 | 官方 Git 仓库 CSV，约 10MB，缓存 24 小时 |
| Red Hat Security Data | 漏洞 | 否 | 仅支持完整 CVE 详情 |
| Sploitus | Exploit | 否 | 公开 POST 搜索接口 |
| 绿盟 NTI | 情报 | 否 | 公开 API，返回 APT / 活动 / 新闻 / 通告 |
| 360 威胁情报 | 情报 | 否 | 公开内容 API 只返回最新通告；站内检索受限 |
| 微步在线 X | 情报 | 否（完整检索需登录） | 未登录时只开放公开推荐位 |
| loudong.org.cn | 情报 | 否 | HTML 爬虫；搜索接口经常为空，高频请求会 403 |
| SOCRadar IOC | 情报 | 否 | 公开 Web API；可能受访问策略影响 |
| ransomware.live | 勒索情报 | 否 | 免费 API v2；每个端点约 1 次/分钟，结果缓存 10 分钟 |
| RansomLook | 勒索情报 | 否 | 公开 API |
| SOCRadar Ransomware | 勒索情报 | 否 | 公开 Web API；可能受访问策略影响 |
| Ransomwatch | 勒索情报 | 否 | GitHub 公开 JSON，本地缓存 12 小时 |
| crt.sh | 资产 | 否 | 公开 CT 日志；请求较慢时可能 502，失败不影响其他源 |
| Cert Spotter | 资产 | 否 | 公开 CT 日志 API，未认证有限流 |
| HackerTarget | 资产 | 否 | 公开 hostsearch API，免费额度有限 |
| RapidDNS | 资产 | 否 | 公开子域名聚合页，HTML 解析 |
| urlscan.io | 资产 | 否 | 公开搜索 API，只取页面域名 |
| subdomain.center | 资产 | 否 | 公开聚合 API，结果质量不稳定且可能繁忙 |
| dns.google | 资产 | 否 | DNS-over-HTTPS 解析 A / AAAA / CNAME |
| NVD `virtualMatchString` | 资产 | 否（可选 Key） | 资产指纹→CVE 关联；未认证约 5 次/30 秒 |
| webscan.cc | 反查 | 否 | 公开 IP 反查接口，含页面标题 |
| HackerTarget | 反查 | 否 | reverseiplookup，免费额度有限 |
| OTX AlienVault | 反查 | 否 | 被动 DNS 历史记录 |
| RapidDNS | 反查 | 否 | sameip 聚合页，HTML 解析 |
| 糖豆子 API | 备案 | 否 | 工信部数据，支持域名 / 备案号 / 单位名 |
| vvhan / oioweb / uomg | 备案 | 否 | 备用公开接口，仅支持域名 |

### 实际使用的公开接口 / 抓取路径

| 站点 | 接口 / 路径 | 用途 |
| --- | --- | --- |
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE 详情 / 关键词 |
| CISA | `known_exploited_vulnerabilities.json` | KEV 全量 Feed |
| MITRE | `cveawg.mitre.org/api/cve/{id}` | CVE Record |
| OSV | `api.osv.dev/v1/vulns/{id}` | 开源漏洞 |
| FIRST | `api.first.org/data/v1/epss` | EPSS 富化 |
| ProjectDiscovery vulnx | `api.projectdiscovery.io/v2/vulnerability/...` | CVE / POC / Nuclei / KEV |
| SOCRadar CVE | `cve.socradar.io/api/cves/{id}`、`/api/catalog/cves` | CVE 详情 / 目录检索 |
| Exploit-DB | `gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | Exploit 元数据 |
| Red Hat | `access.redhat.com/hydra/rest/securitydata/cve/{id}.json` | 厂商影响 / CVSS |
| Sploitus | `POST sploitus.com/search` | Exploit / PoC |
| 绿盟 NTI | `/api/v2/apt/objects/`、`/campaign/`、`/news/`、`/report/notie/` | APT / 活动 / 新闻 / 通告 |
| 360 TI | `/api/custom/sc/v3/researches` | 公开安全通告 |
| 微步 X | `/v5/node/vnext/searchAndIntelRecommend` | 公开推荐位（完整检索需登录） |
| loudong | `/search?q=`、`/vulns?page=`、`/news` | HTML 爬虫 |
| ransomware.live | `/v2/searchvictims/{q}`、`/v2/groups` | 受害者 / 组织 |
| RansomLook | `/api/search?q=` | 组织 / 帖子 |
| SOCRadar | `/api/ransomware/search?q=` | 受害者 / 组织 |
| Ransomwatch | `raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json` | 泄露帖子 |
| crt.sh | `/?q=%.{domain}&output=json` | 证书透明日志子域名 |
| Cert Spotter | `/v1/issuances?domain=` | 证书透明日志子域名 |
| HackerTarget | `/hostsearch/?q=` | 子域名 + IP |
| RapidDNS | `/subdomain/{domain}?full=1` | 子域名 HTML |
| urlscan.io | `/api/v1/search/?q=domain:{domain}` | 公开扫描结果域名 |
| subdomain.center | `/?domain=` | 公开子域名聚合 |
| dns.google | `/resolve?name=&type=` | DoH 解析 A / AAAA / CNAME |
| NVD | `/rest/json/cves/2.0?virtualMatchString=` | 资产指纹关联 CVE |
| webscan.cc | `/?action=query&ip=` | IP 反查域名（含标题） |
| HackerTarget | `/reverseiplookup/?q=` | IP 反查域名 |
| OTX | `/api/v1/indicators/IPv{4,6}/{ip}/passive_dns` | 被动 DNS |
| RapidDNS | `/sameip/{ip}?full=1` | IP 反查域名 |
| 糖豆子 | `/a/icp/?type=web&search=` | ICP 备案 |
| ipwho.is | `/8.8.8.8` | IP 归属 |
| ipinfo.io | `/{ip}/json` | IP 归属 / 主机名 |
| ip-api.com | `/json/{ip}` | IP 归属 / 代理标记 |
| AlienVault OTX | `/api/v1/indicators/IPv4/{ip}/general`、`/file/{hash}/general` | IP / 哈希情报（免 Key） |
| SOCRadar IOC | `ioc.socradar.io/api/v1/iocs/{value}`、`/api/v1/iocs?q=` | IP / 哈希 / IOC |
| CIRCL | `hashlookup.circl.lu/lookup/{kind}/{hash}` | 哈希文件情报（免 Key） |
| 微步 API | `/v3/scene/ip_reputation`、`/v3/file/report`、`/v3/file/report/multiengines` | IP / 哈希（需 Key） |
| 微步沙箱 | `POST /v3/file/upload` | 文件沙箱（需 Key） |
| VirusTotal | `/api/v3/ip_addresses/{ip}`、`/files/{hash}`、`POST /files` | IP / 哈希 / 沙箱（需 Key） |

> 这些接口均为站点前端实际调用的公开接口或公开 HTML 页面，可能随站点改版而变化；工具已对失败做降级处理，不会因单站改版而整体不可用。

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
- 资产搜集的被动子域名结果：1 小时（按域名 + 数据源缓存）

---

## 项目结构

```text
tutu/
├── cli.py                 # argparse CLI
├── search.py              # 并行调度、CVE 合并、EPSS 富化、版本判定
├── render.py              # Rich 终端输出
├── http.py                # 带重试的 HTTP 客户端
├── cache.py               # 本地 JSON 缓存
├── models.py              # Item / SourceResult / VulnCard
├── versions.py            # 受影响版本区间解析、比较与匹配
├── assets/
│   ├── attack.py          # 资产搜集主流程
│   ├── subdomain.py       # 被动子域名源
│   ├── dns.py             # DoH / 系统 DNS 解析
│   ├── probe.py           # HTTP(S) 存活与 Web 指纹
│   ├── ports.py           # 可选端口扫描
│   ├── correlate.py       # 资产指纹 → NVD 漏洞关联
│   └── models.py          # Asset / Service / PortResult / AttackSurface
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
