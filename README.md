# NetProbe

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Vue](https://img.shields.io/badge/Vue-3-42b883?logo=vue.js&logoColor=white)](https://vuejs.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)]()

> 开源一体化资产探测与攻击面管理平台

NetProbe 是一个面向红蓝对抗与资产巡检的一站式攻击面管理平台，采用 **FastAPI + Vue 3 前后端分离**架构。一条管道打通「子域名发现 → 端口扫描 → 指纹识别 → 漏洞扫描 → 风险评分 → 变更检测 → 资产关联 → 多渠道告警」全流程，内置 961 条 Web 指纹与 566 条敏感路径规则，融合中英文情报源，提供 Web UI 与命令行两种使用方式，支持 Docker 一键部署。

![NetProbe Web 界面](readme_resource/scan_1.png)
![NetProbe Web2 界面](readme_resource/scan_2.png)

## 功能特性

- **一站式扫描管道** — 子域名 → 端口 → Web 指纹 → 漏洞 → 风险评分 → 变更检测 → 资产关联 → 告警，单次任务全流程覆盖
- **指纹识别** — 961 条 Web 技术指纹规则，覆盖 CMS、前端框架、Web 服务器、CDN、WAF、统计分析等类别，支持 HTTP 头部 + HTML 内容 + Cookie 多维度匹配
- **敏感路径探测** — 566 条敏感路径规则，检测 Git/SVN 泄露、配置文件、备份文件、管理后台、API 文档、Spring Actuator 等，按 high/medium/low/info 分级
- **漏洞扫描** — 集成 [nuclei v3](https://github.com/projectdiscovery/nuclei)，基于模板的自动化漏洞检测，结果入库并纳入风险评分
- **接管检测** — 96 条子域名接管指纹，识别 CNAME 悬挂 / 未解析 / 可注册等高危场景
- **风险评分** — 6 维度加权计算 0–100 综合风险分（漏洞、敏感路径、暴露端口、过期证书、接管风险、技术栈老旧），自动分级 low/medium/high/critical
- **变更检测** — 与历史基线做 6 维 diff（端口 / 指纹 / 敏感路径 / Web 标题 / 证书 / 漏洞），生成变更时间线
- **资产关联图谱** — 基于 ECharts 的 6 维度关联图谱（IP / 证书 / Banner / 指纹 / 标题 / ASN），可视化资产横向关系
- **JS 文件分析** — 从页面 JavaScript 中提取 API 端点，并检测泄露的密钥/Token（AWS Key、GitHub Token、JWT、Private Key 等）
- **多渠道通知** — Webhook、钉钉、企业微信、飞书、Telegram、邮件共 6 种告警渠道，高危发现实时推送
- **中英文情报融合** — FOFA / Hunter（中文源）+ crt.sh / Shodan / Censys（国际源），多源聚合子域名与资产画像
- **多扫描引擎** — nmap / masscan / rustscan 三引擎 + nuclei 漏洞扫描，按可靠性优先级自动调度、优雅降级
- **定时巡检** — APScheduler 定时任务 + 告警策略，资产持续监控
- **跨平台** — Windows / macOS / Linux 全平台支持，自动适配工具安装路径

## 快速开始（Docker 部署，推荐）

> 前提：已安装 [Docker](https://docs.docker.com/get-docker/) 与 Docker Compose（Docker Desktop 自带）。

```bash
git clone https://github.com/lium1128/NetProbe.git
cd NetProbe

# 一键启动（首次会自动构建前端 + 安装 nmap/masscan/subfinder/nuclei）
docker compose up -d

# 浏览器访问
#   http://localhost:8000
```

容器内已预装 nmap、masscan、subfinder、nuclei、Playwright chromium，开箱即用。

### 数据持久化与配置

`docker-compose.yml` 已配置以下挂载，**数据库、配置、报告、nuclei 模板**在容器重建后均不丢失：

| 挂载 | 容器路径 | 说明 |
|------|---------|------|
| `./data` | `/app/data` | SQLite 数据库 `netprobe.db` + `settings.json` 配置 + 截图 |
| `./output` | `/app/output` | 扫描报告输出目录 |
| `nuclei-templates`（命名卷）| `/root/nuclei-templates` | nuclei 模板，避免重启重新下载 |

### 环境变量（情报源 API Keys）

API Key 既可以在 `data/settings.json` 中配置，也可以通过环境变量注入（见 `docker-compose.yml` 的 `environment` 段）。两者二选一即可：

```yaml
environment:
  TZ: Asia/Shanghai
  FOFA_EMAIL: ""        # FOFA 邮箱
  FOFA_KEY: ""          # FOFA API Key
  HUNTER_KEY: ""        # 奇安信鹰图
  NVD_API_KEY: ""       # NVD 漏洞库（nuclei 漏洞丰富度）
  SHODAN_API_KEY: ""    # Shodan
```

### 启用 SYN 扫描（可选）

nmap 的 SYN 扫描（`-sS`）和 masscan 需要 `CAP_NET_RAW` 权限。如需启用，取消 `docker-compose.yml` 中以下两行的注释：

```yaml
    cap_add:
      - NET_RAW
```

> 默认 TCP connect 扫描无需额外权限即可工作，SYN 扫描更快更隐蔽。

## 手动部署

适用于不使用 Docker、需要本地开发或自定义环境的场景。

### 环境要求

- **Python 3.10+**（推荐 3.12）
- **Node.js 18+**（推荐 20 LTS，用于构建前端）
- **外部扫描工具**（按需安装）：nmap、masscan、subfinder、nuclei

### 1. 后端（FastAPI）

```bash
# 安装 Python 依赖
pip install -r server/requirements.txt

# 开发模式（带热重载，任选其一）
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload
python -m server.main

# 生产模式
uvicorn server.main:app --host 0.0.0.0 --port 8000 --workers 1
```

后端启动后监听 **8000** 端口，同时托管 `frontend/dist/` 静态文件（同源访问，无需单独起前端服务）。

### 2. 前端（Vue 3 + Vite，仅开发时需要）

```bash
cd frontend
npm install

# 开发模式：vite dev server 监听 5173，自动代理 /api → 8000
npm run dev
# 访问 http://localhost:5173

# 生产构建：产物输出到 frontend/dist/，后端自动托管
npm run build
```

### 3. 安装外部扫描工具

**必选：**

- **Nmap** — [官网下载](https://nmap.org/download.html)
  - Windows：安装时勾选 "Add to PATH"
  - macOS：`brew install nmap`
  - Linux：`sudo apt install nmap` / `sudo yum install nmap`

**推荐（Go 工具，国内加速）：**

```bash
# 安装 Go：https://go.dev/dl/
go env -w GOPROXY=https://goproxy.cn,direct

# subfinder（被动子域名）+ nuclei（漏洞扫描）
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**可选：**

- **Masscan** — 世界最快端口扫描器，需 root/管理员权限
  - Linux：`sudo apt install masscan`　macOS：`brew install masscan`
- **RustScan** — 快速端口发现 + 自动调用 nmap 服务检测（[Releases](https://github.com/RustScan/RustScan/releases)）

## 使用方式

### 方式一：Web UI（推荐）

启动后端后访问 **http://localhost:8000**：

- 多目标输入（逗号 / 换行 / 空格分隔），支持域名与 IP（IP 自动反向 DNS）
- 引擎选择（子域名 / 端口 / DNS / Web 各阶段可指定引擎，或选 auto 自动调度）
- 实时进度日志（SSE 推送），显示每个引擎的运行状态与降级情况
- 结果按目标分组展示：主机、端口、服务、Web 站点、技术栈标签、SSL 证书、敏感路径、JS 分析、漏洞、Banner、风险评分、资产关联图谱
- 设置页配置 API Key 与通知渠道
- 定时任务与告警策略管理

### 方式二：命令行（CLI）

```bash
# 执行完整扫描
python main.py scan example.com

# 多目标
python main.py scan example.com baidu.com qq.com

# 输入 IP（自动反向解析后探测）
python main.py scan 8.8.8.8

# 保存结果为指定格式（txt / csv / json / html）
python main.py scan example.com -f json -o report.json

# 跳过子域名枚举 / Web 探测
python main.py scan example.com --no-dns-brute --no-web

# 自定义子域名字典
python main.py scan example.com -w custom_wordlist.txt

# CI/CD 模式：发现高危时退出码非零，便于接入流水线
python main.py ci example.com --severity-threshold 70 --fail-on high_risk

# 从 Wappalyzer 拉取并合并最新指纹库
python main.py update-fingerprints
```

常用参数：

| 参数 | 说明 |
|------|------|
| `targets` | 目标域名或 IP，空格分隔（必填）|
| `-f, --format` | 输出格式：txt / csv / json / html（默认 txt）|
| `-o, --output` | 输出文件路径（不指定则自动按 `域名_时间.格式` 命名）|
| `-w, --wordlist` | 外部子域名字典文件 |
| `--no-dns-brute` | 跳过子域名枚举 |
| `--no-web` | 跳过 Web 站点探测 |
| `--no-validate` | 跳过 DNS 解析验证 |
| `--timeout` | 扫描超时秒数（默认 300）|
| `-v, --verbose` | 显示详细过程 |

`ci` 子命令额外参数：

| 参数 | 说明 |
|------|------|
| `--severity-threshold` | 风险分阈值，≥此值视为高危（默认 70）|
| `--fail-on` | 失败条件：`high_risk` / `sensitive` / `any`（默认 high_risk）|

## 项目结构

```
domain-Identify/
├── server/                     # 后端：FastAPI 应用（API + ORM + 调度 + 静态托管）
│   ├── main.py                 # 入口：create_app()，uvicorn 启动
│   ├── config.py               # 路径与数据库配置
│   ├── db.py                   # SQLAlchemy 引擎 / 会话
│   ├── utils.py                # 通用工具
│   ├── models/                 # ORM 模型（12 张表）
│   ├── schemas/                # Pydantic 请求/响应模型
│   ├── routers/                # API 路由（扫描 / 资产 / 调度 / 告警 / 设置 ...）
│   ├── services/               # 业务服务层（扫描调度、通知、变更检测、关联等）
│   └── requirements.txt        # 后端 Python 依赖
├── frontend/                   # 前端：Vue 3 + TypeScript + Element Plus
│   ├── src/                    # 源码（视图、组件、store、路由、i18n）
│   ├── dist/                   # 构建产物（后端托管，gitignore）
│   ├── vite.config.ts          # dev server 5173，代理 /api → 8000
│   └── package.json
├── netprobe/                   # 核心扫描引擎包（CLI 与 server 共用）
│   ├── engine.py               # 统一扫描流水线
│   ├── scanner.py              # Nmap 交互层（dns-brute + 两步端口扫描）
│   ├── web_probe.py            # Web 探测（HTTP/HTTPS + SSL + 编码 + JS URL）
│   ├── fingerprint.py          # 技术栈指纹识别
│   ├── sensitive_probe.py      # 敏感路径探测
│   ├── takeover_detect.py      # 子域名接管检测
│   ├── risk.py                 # 6 维风险评分
│   ├── js_analyzer.py          # JS 分析（API + 密钥泄露）
│   ├── banner_grab.py          # Banner 抓取（多协议）
│   ├── dns_utils.py            # DNS 工具（含系统 DNS fallback）
│   ├── screenshot.py           # Playwright 截图
│   ├── formatter.py            # 结果格式化（终端 + TXT/CSV/JSON/HTML）
│   ├── data/
│   │   ├── fingerprints.json       # 961 条 Web 指纹
│   │   ├── sensitive_paths.json    # 566 条敏感路径
│   │   ├── takeover_fingerprints.json  # 96 条接管指纹
│   │   └── cdn_cidrs.json
│   └── tools/                  # 外部工具适配（nmap/masscan/rustscan/subfinder/nuclei/crt.sh/fofa/hunter/shodan/censys）
├── scripts/
│   └── import_wappalyzer.py    # Wappalyzer 指纹导入脚本
├── data/
│   ├── netprobe.db             # SQLite 数据库（12 张表）
│   └── settings.json           # API Key + 布局/主题配置
├── output/                     # 扫描报告输出
├── main.py                     # CLI 入口（scan / ci / update-fingerprints）
├── Dockerfile                  # 多阶段构建（前端构建 + 运行时）
├── docker-compose.yml          # 一键部署编排
├── requirements.txt            # 核心扫描包依赖（netprobe）
└── README.md
```

## 配置说明

### settings.json

位于 `data/settings.json`，由 Web UI「设置」页维护，也可手动编辑：

```json
{
  "layout": "topnav",
  "theme": "light",
  "api_keys": {
    "shodan": "",
    "fofa_email": "",
    "fofa_key": "",
    "censys_id": "",
    "censys_secret": ""
  }
}
```

通知渠道（钉钉 / 企业微信 / 飞书 / Telegram / 邮件 / Webhook）的 webhook 地址、邮件 SMTP、Telegram bot token 等同样在设置页配置，写入数据库。

### 环境变量

| 变量 | 说明 | 默认 |
|------|------|------|
| `FOFA_EMAIL` + `FOFA_KEY` | FOFA 网络空间搜索（[注册](https://fofa.info/)）| 空，跳过 |
| `HUNTER_KEY` | 奇安信鹰图（[注册](https://hunter.qianxin.com/)）| 空，跳过 |
| `SHODAN_API_KEY` | Shodan 国际资产搜索 | 空，跳过 |
| `CENSYS_ID` + `CENSYS_SECRET` | Censys 资产搜索 | 空，跳过 |
| `NVD_API_KEY` | NVD 漏洞库，提升漏洞识别率 | 空，跳过 |
| `TZ` | 时区（影响定时任务调度）| Asia/Shanghai |

> 不配置任何 Key 时，crt.sh（证书透明度，免费）仍可正常使用，其余源自动跳过。

## 技术栈

| 类别 | 技术 |
|------|------|
| 后端框架 | FastAPI + Uvicorn |
| 数据库 | SQLite + SQLAlchemy ORM（12 张表）|
| 数据校验 | Pydantic v2 |
| 定时任务 | APScheduler |
| 浏览器自动化 | Playwright（Web 截图）|
| 前端框架 | Vue 3 + TypeScript |
| UI 组件库 | Element Plus |
| 图表 | ECharts + vue-echarts（资产关联图谱、风险分布）|
| 状态/路由 | Pinia + Vue Router |
| 国际化 | vue-i18n（中英双语）|
| 构建工具 | Vite |
| 端口扫描 | python-nmap（nmap）/ masscan / rustscan |
| 漏洞扫描 | nuclei v3 |
| 子域名 | subfinder + crt.sh + FOFA + Hunter + nmap dns-brute |
| DNS | dnspython（含系统 DNS fallback）|
| HTTP | requests |
| 规则数据 | JSON（961 指纹 + 566 敏感路径 + 96 接管指纹）|

## 法律与免责声明

**请务必阅读以下内容后再使用本工具。**

### 合法使用要求

本工具涉及域名枚举、端口扫描、服务探测等网络行为，在许多国家和地区，未经授权对他人网络系统进行扫描可能构成违法行为。使用本工具前，请确保：

1. **已获得明确授权** — 仅对你拥有或已获得所有者书面授权的目标进行扫描
2. **遵守当地法律法规** — 不同国家/地区对网络扫描的法律定义不同，使用前请了解并遵守你所在地区的相关法律
3. **仅用于合法目的** — 包括但不限于：自有资产安全审计、授权渗透测试、安全教学与研究、CTF 竞赛

### 禁止用途

严禁将本工具用于以下用途：

- 未经授权扫描任何第三方系统或网络
- 非法获取他人网络信息或系统访问权限
- 任何形式的网络攻击或破坏行为
- 侵犯他人隐私或商业秘密
- 其他违反法律法规的行为

### 法律风险提示

在中国大陆地区，未经授权的网络扫描行为可能涉及以下法律：

- **《中华人民共和国网络安全法》** — 禁止非法侵入他人网络、干扰他人网络正常功能
- **《中华人民共和国刑法》第 285 条** — 非法侵入计算机信息系统罪、非法获取计算机信息系统数据罪
- **《中华人民共和国刑法》第 286 条** — 破坏计算机信息系统罪
- **《治安管理处罚法》第 29 条** — 对计算机信息系统造成危害的行政处罚

### 免责声明

- 本工具仅供**合法的安全研究和授权测试**使用
- 使用者因不当使用本工具而产生的一切法律责任，由使用者**自行承担**
- 本工具开发者**不承担**任何因使用本工具造成的直接或间接法律责任
- 使用本工具即视为你已阅读、理解并同意以上全部内容

**如果你不确定自己的使用行为是否合法，请不要使用本工具。**

## 致谢

本工具依赖以下优秀的开源项目：

- [Nmap](https://nmap.org/) — 网络发现和安全审计
- [Subfinder](https://github.com/projectdiscovery/subfinder) — 被动子域名枚举
- [Masscan](https://github.com/robertdavidgraham/masscan) — 高速端口扫描
- [RustScan](https://github.com/RustScan/RustScan) — Rust 端口扫描器
- [Httpx](https://github.com/projectdiscovery/httpx) — 批量 Web 探测
- [DNSx](https://github.com/projectdiscovery/dnsx) — DNS 工具包
- [crt.sh](https://crt.sh/) — 证书透明度日志
- [FOFA](https://fofa.info/) — 网络空间搜索引擎
- [Hunter](https://hunter.qianxin.com/) — 奇安信鹰图平台
- [Flask](https://flask.palletsprojects.com/) — Python Web 框架
- [dnspython](https://github.com/rthalley/dnspython) — DNS 工具包

## 贡献指南

欢迎贡献！可以通过以下方式参与：

1. **提交 Issue** — 报告 Bug、提出功能建议
2. **提交 Pull Request** — 修复问题或添加新功能
3. **完善规则** — 扩充 Web 指纹 (`netprobe/data/fingerprints.json`)、敏感路径 (`netprobe/data/sensitive_paths.json`) 或接管指纹 (`netprobe/data/takeover_fingerprints.json`)

### 开发指南

```bash
# 克隆项目
git clone https://github.com/lium1128/NetProbe.git
cd NetProbe

# 后端依赖
pip install -r server/requirements.txt

# 启动后端（开发，热重载）
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

# 另开终端：启动前端 dev server（5173，自动代理 /api → 8000）
cd frontend
npm install
npm run dev

# 或使用命令行扫描
python main.py scan example.com
```

## 开源协议

本项目基于 [Apache License 2.0](LICENSE) 开源。

```
Copyright 2024-2026 lium1128

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
