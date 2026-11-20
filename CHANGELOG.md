# Changelog

## 0.2.1 — 2026-11-21

- 修复 `--json` 输出中 SOCRadar CVE 嵌套 Exploit 条目无法序列化的问题
- 完善 SOCRadar IOC / CISA / 公开源字段的 JSON 序列化

## 0.2.0 — 2026-11-21

### 新增漏洞源

- ProjectDiscovery vulnx：CVE、POC、Nuclei 模板、KEV、EPSS
- SOCRadar CVE：CVE 详情、Exploit-DB、SSVC、PoC
- Exploit-DB：官方 Git 仓库 CSV，按 CVE / 关键词检索
- Red Hat Security Data：厂商 CVSS、受影响产品

### 新增情报源

- SOCRadar IOC：恶意 IP / 域名 / URL / 哈希指标

### IP / 哈希增强

- `-ip` 增加 SOCRadar IOC 情报
- `-hash` 增加 SOCRadar IOC 情报
- 支持 IP 的 Tor / VPN / Proxy / Scanner / Botnet 标记和关联报告
- `-t` 支持直接检索 SOCRadar IOC

### 其他

- 发行名改为 `tutu-cli`，安装后命令仍为 `tutu`
- 新增 `PDCP_API_KEY` / `TUTU_PDCP_API_KEY` 支持（可选）
- README / 发布说明更新

## 0.1.0 — 2026-11-21

首个公开版本。

### 漏洞聚合

- NVD（REST API 2.0）
- CISA KEV（含勒索软件利用标记）
- MITRE CVE / CVE.org
- OSV.dev
- CISA Vulnrichment
- Sploitus Exploit / PoC
- FIRST EPSS 富化
- 按 CVE 合并、去重、排序

### 威胁情报

- 绿盟 NTI：APT 组织、攻击活动、威胁新闻、漏洞通告
- 360 威胁情报：公开安全通告
- 微步在线 X：公开反爬挑战处理、未登录检索入口
- loudong.org.cn：HTML 爬虫，支持 `--deep`
- ransomware.live
- RansomLook
- SOCRadar Ransomware
- Ransomwatch

### IP / 哈希 / 文件

- `tutu -ip 8.8.8.8`：IP 归属、ASN、代理/IDC 标记、ThreatBook / VirusTotal / OTX 情报
- `tutu -hash <HASH>`：CIRCL Hashlookup、OTX、ThreatBook 多引擎、VirusTotal
- `tutu -file <PATH>`：本地 MD5/SHA1/SHA256/SHA512、类型识别、公开情报、VirusTotal / 微步沙箱上传
- `--no-upload`：只查哈希，不上传沙箱
- `--sandbox` / `--run-time`：微步沙箱参数

### 配置

- `tutu -config` 交互配置微步 / VirusTotal API Key
- `tutu config show|set|unset|path`
- Key 持久化到 `~/.config/tutu/config.json`（权限 0600）
- 支持 `TUTU_THREATBOOK_API_KEY` / `TUTU_VIRUSTOTAL_API_KEY` 等环境变量

### CLI

- `tutu -v CVE-2026`
- `tutu CVE-2021-44228`
- `tutu -t APT28`
- `tutu sources`
- `--json` / `--limit` / `--sources` / `--deep` / `--no-color`
- Rich 终端卡片和数据源状态表
- 本地 JSON 缓存
