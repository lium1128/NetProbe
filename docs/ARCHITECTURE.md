# NetProbe 架构概览

> 版本: v3.8 | 这是一份**架构概览**，不是详细设计文档。字段定义、代码细节请直接看源码。

---

## 1. 架构概览

NetProbe 采用前后端分离 + 独立扫描引擎的三层架构：

```
┌──────────────────────────────────────────────────────────┐
│                    用户浏览器                              │
│          Vue 3 + TypeScript + Element Plus                │
│   Dashboard │ Tasks │ Assets │ ASM │ Plugins │ RBAC       │
│          Pinia · Vue Router · vue-i18n · ECharts          │
└────────────────────────┬─────────────────────────────────┘
                         │ Axios (REST) / EventSource (SSE)
                         │  Bearer JWT + RBAC (4角色×9权限)
                         ▼
┌──────────────────────────────────────────────────────────┐
│              FastAPI (REST API + JWT 中间件 + RBAC)        │
│   routers/ (19个)  →  services/ (15个)  →  models/ (16张表) │
│                         │                                │
│  APScheduler │ Playwright │ Plugin Registry │ Report Gen   │
│                         │                                │
│                         └──→  netprobe/ (扫描引擎包)      │
├──────────────────────────────────────────────────────────┤
│   PostgreSQL / SQLite (双后端，环境变量切换)               │
│   外部工具: nmap / masscan / rustscan / subfinder / nuclei │
└──────────────────────────────────────────────────────────┘
```

**核心设计原则：**

- **三层后端** — `routers/`（路由 + 参数校验）→ `services/`（业务编排）→ `models/`（ORM）+ `netprobe/`（扫描引擎）
- **引擎解耦** — `netprobe/` 是独立扫描包，不依赖 FastAPI / DB，CLI 与 Web 共用同一套扫描逻辑
- **结果双写** — 扫描结果同时写内存（供 SSE 实时推送）与 DB（持久化供历史/资产查询）
- **同步线程** — 扫描在 `threading.Thread` 中执行（netprobe 引擎是同步的），FastAPI 本身保持 async
- **插件化** — 13 个检测模块通过插件注册中心统一调度，支持社区扩展
- **双后端** — PostgreSQL（生产）或 SQLite（开发），通过 `DATABASE_URL` 环境变量切换

---

## 2. 项目结构

```
NetProbe/
├── server/                     # ── FastAPI 后端 ──
│   ├── __init__.py             # create_app() + JWT中间件 + 启动钩子
│   ├── main.py                 # uvicorn 启动入口
│   ├── config.py               # 路径/密钥/JWT/DB_URL 配置
│   ├── db.py                   # SQLAlchemy engine + SessionLocal + 迁移
│   ├── models/                 # ORM 模型（16 张表）
│   │   ├── user.py             # 用户 + RBAC 角色/权限定义
│   │   ├── scan.py             # 扫描任务
│   │   ├── host.py             # 主机/端口/Banner
│   │   ├── web.py              # WebInfo/漏洞/敏感路径/JS/WHOIS
│   │   ├── scan_engine.py      # 扫描引擎配置
│   │   ├── schedule.py         # 定时任务
│   │   ├── alert.py            # 告警规则/事件
│   │   └── asset_tag.py        # 资产标签
│   ├── schemas/                # Pydantic 请求/响应模型
│   ├── routers/                # API 路由（19 个模块）
│   │   ├── auth.py             # 登录/用户CRUD/角色
│   │   ├── scan.py             # 启动扫描/SSE流
│   │   ├── tasks.py            # 任务管理
│   │   ├── assets.py           # 资产列表
│   │   ├── plugins.py          # 插件管理
│   │   ├── vulnerabilities.py  # 漏洞生命周期
│   │   ├── result.py           # 结果/报告下载
│   │   ├── asm.py              # ASM总览
│   │   └── ...                 # 其余 11 个路由
│   └── services/               # 业务逻辑层（15 个）
│       ├── scan_service.py     # 扫描调度+进度日志缓冲
│       ├── auth_service.py     # JWT+bcrypt+RBAC权限
│       ├── asset_service.py    # 资产聚合(N+1消除)
│       ├── stats_service.py    # 资产详情聚合
│       ├── history_service.py  # 扫描历史
│       ├── diff_service.py     # 变更检测Diff
│       └── ...
│
├── frontend/                   # ── Vue 3 前端（Vite）──
│   └── src/
│       ├── views/              # 页面（18 个）
│       │   ├── Dashboard.vue   # 仪表盘
│       │   ├── Tasks.vue       # 任务管理
│       │   ├── Assets.vue      # 资产清单+漏洞管理
│       │   ├── ASM.vue         # 攻击面管理
│       │   ├── Plugins.vue     # 插件管理
│       │   ├── Users.vue       # 用户管理(RBAC)
│       │   ├── ScanDiff.vue    # 左右分栏对比
│       │   ├── TaskDetail.vue  # 任务详情+报告导出
│       │   └── ...
│       ├── stores/             # Pinia 状态（auth含RBAC）
│       ├── composables/        # 分页/页面配置
│       ├── router/             # 路由表+权限守卫
│       └── i18n/               # 中英双语
│
├── netprobe/                   # ── 核心扫描引擎 ──
│   ├── engine.py               # 统一扫描流水线编排
│   ├── risk.py                 # 6维风险评分+CVE关联
│   ├── fingerprint.py          # 指纹识别(9876条)
│   ├── plugins/                # ── 插件系统 ──
│   │   ├── base.py             # Plugin 抽象基类
│   │   ├── registry.py         # 注册中心+自动发现
│   │   └── builtin.py          # 13个内置插件注册
│   ├── cve_match.py            # CVE关联(OSV+NVD+缓存)
│   ├── ssl_check.py            # SSL/TLS深度检测
│   ├── mail_security.py        # 邮件安全基线
│   ├── unauth_scan.py          # 未授权接口枚举
│   ├── waf_detect.py           # WAF识别
│   ├── cors_check.py           # CORS检测
│   ├── security_headers.py     # 安全响应头
│   ├── brute_force.py          # 弱口令爆破
│   ├── origin_ip.py            # CDN真实IP
│   ├── admin_detect.py         # 管理后台识别
│   ├── takeover_detect.py      # 子域名接管
│   ├── robots_sitemap.py       # robots解析
│   ├── js_analyzer.py          # JS分析
│   ├── web_probe.py            # Web探测+SSL采集
│   ├── formatter.py            # 专业报告生成(PDF/HTML)
│   ├── tools/                  # 外部工具适配
│   └── data/                   # 规则数据
│       ├── fingerprints.json   # 9876条指纹
│       ├── sensitive_paths.json# 566条敏感路径
│       ├── cve_cache.json      # CVE查询缓存
│       └── plugin_states.json  # 插件启用状态
│
├── data/                       # 运行时数据
│   ├── netprobe.db             # SQLite(未配PG时)
│   ├── screenshots/            # Web截图
│   └── plugins/                # 社区插件目录
├── scripts/                    # 工具脚本
│   ├── migrate_sqlite_to_pg.py # SQLite→PG迁移
│   └── import_*.py             # 指纹库导入器
├── main.py                     # CLI入口
├── Dockerfile                  # 多阶段构建
└── docker-compose.yml          # PG + NetProbe 一键部署
```

---

## 3. 数据流（扫描管道）

一次完整扫描经历以下阶段，每个阶段可由扫描引擎配置开关：

```
目标解析
  │
  ├─ 1. 被动情报收集 (crt.sh / FOFA / Hunter)
  ├─ 2. 子域名枚举 (subfinder + DNS爆破)
  ├─ 3. 端口扫描 (nmap / masscan / rustscan 三引擎)
  ├─ 4. Web探测 (httpx + SSL + 编码识别)
  ├─ 5. 指纹识别 (9876规则三库融合 + 版本提取)
  │
  ├─ 6. 敏感路径探测 (566条规则)
  ├─ 7. 插件系统: sensitive阶段
  │     ├─ 管理后台识别
  │     └─ robots.txt/sitemap解析
  ├─ 8. 漏洞扫描 (nuclei v3)
  ├─ 9. 插件系统: vuln阶段
  │     ├─ WAF识别 (20+厂商)
  │     ├─ 安全响应头检查
  │     ├─ CORS配置检测
  │     ├─ SSL/TLS深度检测
  │     ├─ 未授权接口枚举 (40+路径)
  │     ├─ 弱口令爆破 (SSH/MySQL/Redis/FTP/PG)
  │     └─ CDN真实IP发现
  ├─ 10. 插件系统: web阶段
  │      └─ 邮件安全基线 (SPF/DKIM/DMARC/MTA-STS)
  │
  ├─ 11. WHOIS/RDAP + DNS记录收集
  ├─ 12. 风险评分
  │      └─ CVE关联 (指纹版本→OSV/NVD→CVE+CVSS)
  ├─ 13. 截图 (Playwright, 可选)
  └─ 14. 种子扩展 (IP→ASN→网段→更多域名)
  │
  ▼
结果落库 + 告警检查 + 报告生成
```

> 全程通过 SSE（`text/event-stream`，心跳保活）向前端推送进度。
> 插件系统通过 `run_plugins_for_stage(stage, hosts, options, emit)` 按阶段批量执行。

---

## 4. 插件系统

### 架构

```
netprobe/plugins/
├── base.py         # Plugin 抽象基类
│   属性: name, display_name, description, category, stage, icon
│   方法: run(hosts, options, emit) → int
│         is_available() → bool
│
├── registry.py     # 注册中心
│   register()          — 注册插件实例/类
│   get_all_plugins()   — 列出全部
│   is_enabled(name)    — 检查启用状态(持久化到 plugin_states.json)
│   run_plugins_for_stage(stage, hosts, options, emit) — 按阶段批量执行
│   _discover_external_plugins() — 扫描 data/plugins/*.py 自动加载
│
└── builtin.py       # 13 个内置插件(薄包装原有检测模块)
```

### 插件与引擎的关系

引擎（`engine.py`）的扫描管道在特定阶段调用 `run_plugins_for_stage()`：

| 引擎调用点 | 阶段 | 执行的插件 |
|-----------|------|-----------|
| 敏感路径后 | `sensitive` | 管理后台、robots解析 |
| 漏洞扫描后 | `vuln` | WAF、安全头、CORS、SSL、未授权接口、弱口令 |
| DNS收集后 | `web` | 邮件安全 |
| 风险评分内 | `_engine_managed` | CVE关联、CDN真实IP（特殊逻辑，非插件调度）|

### 社区插件开发

```python
# data/plugins/my_plugin.py
from netprobe.plugins.base import Plugin

class MyPlugin(Plugin):
    name = 'my_plugin'
    display_name = '我的检测插件'
    category = 'vuln'
    stage = 'vuln'
    icon = '🔬'
    is_builtin = False

    def run(self, hosts, options, emit=None):
        for host in hosts:
            # 检测逻辑...
            host.setdefault('vulnerabilities', []).append({...})
        return findings_count
```

放入 `data/plugins/` 即自动注册，前端插件管理页可启用/禁用。

---

## 5. 数据库

### 双后端

| 后端 | 配置 | 场景 |
|------|------|------|
| **PostgreSQL** | `DATABASE_URL=postgresql://...` | 生产（并发读写性能好）|
| **SQLite** | 不设 `DATABASE_URL`（默认） | 开发（零配置）|

`server/db.py` 根据 `IS_SQLITE` 标志条件化：
- SQLite: `check_same_thread=False` + WAL 模式 + busy_timeout
- PostgreSQL: `pool_pre_ping=True` + 连接池

### 表结构（16 张表）

| 模块 | 表 | 说明 |
|------|----|------|
| **扫描** | `scans` | 扫描任务（状态/统计/进度日志）|
| | `hosts` | 主机（域名/IP/OS/风险分/风险因子）|
| | `ports` | 端口（协议/状态/服务/版本/CPE）|
| | `banners` | 服务 Banner |
| **Web** | `web_info` | Web站点（标题/状态码/技术栈/SSL/截图/favicon/CDN）|
| | `sensitive_paths` | 敏感路径（分级/状态码）|
| | `js_findings` | JS分析（API端点+密钥泄露）|
| | `whois_records` | WHOIS/RDAP/DNS记录 |
| | `vulnerabilities` | 漏洞（nuclei+CVE关联+安全检测，含状态/备注）|
| **调度** | `schedules` | 定时扫描（cron）|
| **告警** | `alerts` | 告警规则 |
| | `alert_events` | 告警触发历史 |
| **配置** | `scan_engines` | 扫描引擎（6预设+自定义）|
| | `asset_tags` | 资产标签 |
| **用户** | `users` | 用户（用户名/密码哈希/角色）|

**约定：** 嵌套数据（技术栈、SSL、headers、风险因子等）用 JSON 列存储。表间通过 `scan_id` / `host_id` 外键关联，`ON DELETE CASCADE`。

### 迁移

`server/db.py` 的 `ensure_schema()` 提供幂等迁移（无 Alembic）：
- 启动时检查列是否存在，缺列则 `ALTER TABLE ADD COLUMN`
- SQLite→PG 迁移用 `scripts/migrate_sqlite_to_pg.py`（含序列同步）

---

## 6. 认证与权限（RBAC）

### 4 角色 × 9 权限

| 角色 | 权限 |
|------|------|
| **admin**（管理员）| 全部权限 |
| **scanner**（扫描员）| scan, view, edit, download_report, manage_vulns |
| **auditor**（审计员）| view, download_report, manage_vulns |
| **viewer**（只读）| view |

**权限定义**在 `server/models/user.py` 的 `ROLE_PERMISSIONS`。
**检查方式**：`auth_service.has_permission(user, permission)`。
**前端联动**：侧边栏菜单按权限过滤，路由守卫检查 admin 角色。

### 认证流程

```
POST /api/auth/login
  → bcrypt 校验密码
  → 签发 JWT (7天, 含 role)
  → 返回 {token, user{role}}

GET /api/...(受保护路由)
  Header: Authorization: Bearer <token>
  → JWT 中间件解析 token
  → get_current_user() 验证
  → 路由内按需调 require_permission(user, perm)
```

> SSE (`/api/stream/`) 和下载 (`/api/download/`) 用 `?token=xxx` query 参数鉴权
> （浏览器 EventSource / window.open 无法设 Authorization 头）。

---

## 7. 漏洞生命周期

7 状态流转（`server/routers/vulnerabilities.py`）：

```
open ──→ confirmed ──→ fixing ──→ fixed ──→ verified ──→ closed
  │           │
  └───────────┴──→ false_positive (误报)

任意状态可回到 open（重新打开）
```

- **DB 字段**：`vulnerabilities.status` + `note` + `updated_at`
- **API**：`PATCH /api/vulnerabilities/{id}/status`
- **前端**：资产详情漏洞行内联状态选择器
- **ASM 仪表盘**：状态分布 + 严重性统计

---

## 8. 专业报告

`netprobe/formatter.py` 生成 PDF/HTML 渗透报告：

```
封面（目标/日期/风险评级）
  │
  ├─ 执行摘要（统计卡片：风险分/严重/高危/中危/敏感路径）
  ├─ 风险矩阵（5 级严重性分布条）
  ├─ 漏洞详情（按严重性排序，含 CVE/CVSS/修复建议）
  │   修复建议库：11 种漏洞分类的针对性指导
  └─ 资产清单（主机/端口/Web站点/技术栈）
```

PDF 通过 Playwright HTML→PDF 生成。API：`GET /api/download/{scan_id}/{fmt}`。

---

## 9. 性能优化

| 优化 | 说明 |
|------|------|
| **N+1 消除** | `asset_service.list_assets` 从 143 次查询降至 3 次（单次 JOIN 聚合）|
| **preview 预聚合** | 后端 `list_assets` 直接返回站点/技术栈/端口预览，前端零预取 |
| **进度日志缓冲** | `_append_progress_log` 内存缓冲，每 3 秒/20 条批量写 DB（避免写锁）|
| **SQLite WAL** | `PRAGMA journal_mode=WAL`，读写不互斥 |
| **CVE 缓存** | OSV/NVD 查询结果缓存到 `data/cve_cache.json`（TTL 7 天）|
| **漏洞数一致性** | 列表与详情按相同 `(name,cve,category)` 去重逻辑 |
| **僵尸任务修正** | 内存中不存在的 running 任务自动标为 error |

---

## 10. API 概览

所有路由前缀 `/api`，需 Bearer JWT 认证（登录/SSE/下载豁免）。

| 路由模块 | 主要端点 | 说明 |
|----------|---------|------|
| `auth` | login / me / roles / 用户CRUD | 认证 + RBAC |
| `scan` | POST /scan / GET /stream/{id} | 启动扫描 / SSE 进度 |
| `tasks` | GET /tasks / cancel / delete | 任务管理 |
| `result` | GET /result/{id} / download/{id}/{fmt} | 结果 / 报告下载 |
| `history` | GET /history / 详情 / 删除 | 扫描历史 |
| `assets` | GET /assets | 跨扫描资产汇总 |
| `asset_tags` | 标签 CRUD | 资产分组 |
| `plugins` | GET /plugins / PATCH toggle | 插件管理 |
| `vulnerabilities` | PATCH status / GET stats | 漏洞生命周期 |
| `scan_engines` | 引擎 CRUD | 6 预设 + 自定义 |
| `schedules` | 定时任务 CRUD | APScheduler |
| `alerts` | 告警规则 / 事件 | 告警配置与历史 |
| `asm` | GET /asm/overview | ASM 总览 |
| `correlations` | 关联查询 + 图谱 | 资产关联 |
| `stats` | 统计 + 资产详情 | 分布 / 详情 |
| `search` | 反向搜索 | IP/favicon/github |
| `settings` | GET/PUT | API Key / 通知 |
| `tools` | GET /tools | 工具可用性 |
| `scan_engines` | 引擎 CRUD | 预设+自定义 |

> 通用约定：JSON 格式、错误 `{detail: "..."}` + HTTP 状态码、分页 `?page=&per_page=`。

---

## 11. 部署

详细步骤见 **[README.md](../README.md)**。

**Docker（推荐）：**

```bash
docker compose up -d      # PG + NetProbe，访问 http://localhost:8000
```

**手动开发：**

```bash
# 后端（SQLite 零配置，或设 DATABASE_URL 连 PG）
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

# 前端（5173 代理 /api → 8000）
cd frontend && npm run dev
```

**SQLite → PostgreSQL 迁移：**

```bash
export DATABASE_URL=postgresql://netprobe:netprobe123@localhost:5432/netprobe
python scripts/migrate_sqlite_to_pg.py
```
