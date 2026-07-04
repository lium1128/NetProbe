# NetProbe 功能对比与可追加清单

> 2026-07-04 ｜ 基于 reNgine 2.x / Nemo / 灵珑 / 商业 ASM / nuclei 生态调研
> 聚焦：功能细节对比 + 可落地追加项（不重复 COMPETITIVE_ANALYSIS.md 的能力矩阵）

---

## 一、功能细节对比（NetProbe 已有 vs 竞品独有）

### vs reNgine 2.x

| 功能 | reNgine | NetProbe | 差距 |
|------|---------|----------|------|
| 漏洞结果展示 | CVSS+CWE+CVE+GPT 描述结构化 | 仅 severity/name/cve | ⚠️ 缺分类标签和结构化 |
| GPT 报告生成 | 漏洞 JSON→GPT→描述+修复建议→PDF | 无 | 🔴 中等差距 |
| 目标管理仪表盘 | 每目标独立空间（子域/端点/漏洞统计） | 按扫描任务组织 | ⚠️ 缺目标维度聚合 |
| 通知内容差异化 | 子域变化/新端口/新漏洞/完成 各不同文案 | 仅完成通知 | ⚠️ 可优化 |
| 重扫单子域 | 子域详情页"Initiate Scan" | 仅整任务扫描 | ⚠️ 缺单资产触发 |
| 风险评分 | ❌ 无 | ✅ 六维加权 | **NetProbe 领先** |
| 变更检测 | ❌ 无 | ✅ 六维 diff | **NetProbe 领先** |

### vs Nemo / 灵珑（国产）

| 功能 | 国产工具 | NetProbe | 差距 |
|------|---------|----------|------|
| 端口弱口令爆破 | hydra 集成（SSH/MySQL/Redis/FTP/MSSQL/RDP） | 无 | 🔴 核心缺口 |
| 巡航模式 | masscan+nmap 无限循环发现新增资产 | 仅手动/定时扫描 | ⚠️ 缺自动闭环 |
| Xray POC 兼容 | YAML POC（类 nuclei）并行执行 | 仅 nuclei | ⚠️ POC 覆盖可扩 |
| 管理后台识别 | title/favicon/正文关键词三重判定 | 敏感路径表覆盖 | ⚠️ 可增强 |
| 可视化 | 简单 | ECharts 图谱+趋势 | **NetProbe 领先** |

### vs 商业 ASM（不抄商业模式，抄功能点）

| 功能 | 商业工具 | NetProbe | 差距 |
|------|---------|----------|------|
| 证书透明度监控 | 持续拉 CT 日志发现新签发证书→新子域 | 仅扫描时拉 crt.sh | 🔴 缺持续监控 |
| DNS 记录变更监控 | A/CNAME 历史快照，漂移告警 | 无 | 🔴 缺 DNS 历史 |
| 子域到期提醒 | WHOIS Expiration Date 提前 N 天告警 | WHOIS 查询有，到期提醒无 | ⚠️ 小缺口 |
| 代码仓库泄露 | GitHub Code Search 按公司名+敏感词 | 无 | 🔴 高价值缺口 |
| 云资产公开暴露 | S3/Azure bucket 枚举匿名访问 | 无 | ⚠️ 中等缺口 |
| WAF/CDN 真实 IP | 历史 DNS+CT SAN+favicon hash 多法组合 | CDN 检测有，溯源无 | ⚠️ 可增强 |

### nuclei 生态（已有集成，可深度利用）

| 功能 | nuclei 能力 | NetProbe 现状 | 差距 |
|------|------------|--------------|------|
| 模板分类 | exposures/default-logins/takeovers/cves | 结果平铺无分类 | ⚠️ 缺分类标签 |
| OAST 带外检测 | interactsh 回连确认盲 SSRF/XXE/Log4j | 未启用 | 🔴 高价值缺口 |
| workflows 编排 | 按指纹触发 POC 链 | 无 | ⚠️ 可优化扫描精度 |
| 模板自动更新 | 每月新模板 | 手动更新 | ⚠️ 可加定时 |

### 资产测绘实用小功能（容易遗漏）

| 功能 | 说明 | NetProbe | 难度 |
|------|------|----------|:---:|
| HTTP 安全头检查 | HSTS/CSP/X-Frame 等 6 项缺失评级 | 无 | 小 |
| CORS 配置检测 | 发特殊 Origin 测反射/通配 | 无 | 小 |
| 子域泛解析检测 | 随机子域判定泛解析，过滤假子域 | 无 | 小 |
| robots.txt/sitemap 解析 | Disallow+sitemap URL 并入爆破字典 | 无 | 小 |
| Wappalyzer implies 推断 | 检测 A 自动推断 B | 无 | 小 |
| DNS 全类型展示 | A/MX/TXT/NS/CAA + SPF/DMARC 检查 | 部分有 | 小 |

---

## 二、可追加功能清单（按 难度×价值 排序）

### 第一批：小难度×高价值（建议立即做）

| # | 功能 | 难度 | 价值 | 实现方式 |
|---|------|:---:|:---:|------|
| 1 | **HTTP 安全头检查** | 小 | 高 | 解析响应头逐项查 HSTS/CSP/X-Frame 等 6 项缺失，输出评级入漏洞表 |
| 2 | **CORS 配置检测** | 小 | 高 | 发 3 种 Origin 请求，检测反射/通配/正则不严，判高危入漏洞表 |
| 3 | **子域泛解析检测** | 小 | 高 | 解析随机长串子域判定泛解析，枚举结果过滤假子域 |
| 4 | **robots.txt/sitemap 解析** | 小 | 高 | 解析 Disallow + sitemap URL，并入路径检测和爆破字典 |
| 5 | **nuclei 结果分类标签** | 小 | 高 | 按 template path 打 category（exposures/logins/takeovers），前端分类展示 |
| 6 | **nuclei 结果结构化** | 小 | 高 | 解析 classification 字段（CVSS/CVE/CWE），详情页严重度配色 |
| 7 | **Interactsh/OAST 带外检测** | 中 | 高 | 配置 nuclei 启用 interactsh，结果标「OOB 确认」 |

### 第二批：小难度×中价值

| # | 功能 | 难度 | 价值 | 实现方式 |
|---|------|:---:|:---:|------|
| 8 | DNS 全类型记录展示 | 小 | 中 | 按域名聚合 A/MX/TXT/NS/CAA，标 SPF/DMARC 缺失 |
| 9 | WHOIS 到期提醒 | 小 | 中 | 解析 Expiration Date，<30 天告警 |
| 10 | Wappalyzer implies 推断 | 小 | 中 | 指纹库加 implies 字段，传递闭包扩展技术栈 |
| 11 | nuclei 模板自动更新 | 小 | 中 | cron 每周 `nuclei -ut` |
| 12 | 通知内容差异化 | 小 | 中 | 新子域/新端口/新漏洞/完成 4 种事件模板 |
| 13 | 管理后台专项识别 | 小 | 中 | title+favicon+正文关键词三重判定 |
| 14 | favicon hash 指纹反查 | 小 | 中 | mmh3 hash 对接 fofa/Shodan 找关联 |

### 第三批：中难度×高价值

| # | 功能 | 难度 | 价值 | 实现方式 |
|---|------|:---:|:---:|------|
| 15 | **证书透明度监控** | 中 | 高 | 定时拉 crt.sh API，diff 新子域入库告警 |
| 16 | **DNS 记录变更监控** | 中 | 高 | 存 DNS 快照历史，diff A/CNAME 变化告警 |
| 17 | **端口弱口令爆破** | 中 | 高 | 集成 hydra，按端口→协议映射自动触发 |
| 18 | **GitHub 代码泄露监控** | 中 | 高 | GitHub Code Search API 按公司名+敏感词 |
| 19 | **巡航模式** | 中 | 高 | cron 周期全扫，diff 新资产自动触发专项 |
| 20 | **CDN 真实 IP 发现** | 中 | 高 | crt.sh SAN+历史 DNS+favicon hash 聚合 |

### 第四批：大难度（长期项）

| # | 功能 | 难度 | 价值 |
|---|------|:---:|:---:|
| 21 | GPT 报告生成 | 中 | 中 |
| 22 | 云存储桶公开检查 | 中 | 中 |
| 23 | xray POC 格式兼容 | 中 | 中 |
| 24 | 指纹工作流编排 | 中 | 中 |
| 25 | 被动 DNS 反查（外部 API） | 大 | 中 |
| 26 | 资产标签/分组 | 大 | 中 |

---

## 三、推荐执行路径

**Phase A（快速增益，1-3 天/个）**：#1-6 安全头/CORS/泛解析/robots/nuclei分类/nuclei结构化
→ 补齐 Web 安全检测基础项，漏报率显著下降

**Phase B（监控闭环）**：#15-16 证书监控/DNS变更 + #19 巡航模式
→ 从"扫描器"升级为"持续监控平台"

**Phase C（深度检测）**：#17 弱口令 + #18 代码泄露 + #20 真实IP
→ 攻击面覆盖完整性

**Phase D（生态扩展）**：#7 OAST + #24 工作流 + #21 GPT报告
→ 专业度提升
