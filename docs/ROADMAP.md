# NetProbe Roadmap

参考 [OneForAll](https://github.com/shmilylty/OneForAll)、[Amass](https://github.com/owasp-amass/amass)、[SpiderFoot](https://github.com/smicallef/spiderfoot)、[Shodan](https://www.shodan.io/)、[Censys](https://censys.io/)、[Recon-ng](https://github.com/lanmaster53/recon-ng) 等竞品，规划以下功能。

> 优先级可能根据社区反馈调整，欢迎在 [Issue](https://github.com/lium1128/NetProbe/issues) 中投票或提交建议。

---

## v2.1 — 任务控制与持久化

- [ ] **扫描任务管理** — 支持暂停 / 恢复 / 取消正在运行的扫描任务
- [ ] **扫描历史记录** — 结果持久化存储（SQLite），支持查看、搜索、对比历史扫描
- [ ] **定时扫描** — cron 表达式调度周期性扫描任务，自动检测资产变化
- [ ] **结果对比** — 同一目标多次扫描结果 diff，高亮新增/消失的子域名、端口、服务

## v2.2 — 情报源扩展

- [ ] **更多被动情报源** — 集成 VirusTotal、SecurityTrails、AlienVault OTX、DNSlytics 等 API
- [ ] **子域名接管检测** — 检测 CNAME 指向未注册的 SaaS/Cloud 服务的 dangling DNS 记录
- [ ] **WHOIS 查询** — 域名注册信息、注册商、过期时间、反查关联域名
- [ ] **DNS 区域传送** — 尝试 AXFR 获取完整 DNS 记录

## v2.3 — 可视化与报告

- [ ] **Web 截图** — 对探测到的 Web 站点自动截图，直观展示页面内容
- [ ] **交互式图表** — 端口分布、技术栈统计、资产拓扑图（D3.js / ECharts）
- [ ] **PDF 报告生成** — 一键生成专业的渗透测试报告（参考 Dradis/Faraday）
- [ ] **HTML 报告** — 独立可分享的 HTML 格式报告，无需依赖服务端

## v2.4 — 告警与集成

- [ ] **多渠道通知** — 扫描完成后通过邮件、Slack、企业微信、钉钉、Webhook 推送结果
- [ ] **告警规则** — 自定义告警条件（新开放端口、新子域名、高危敏感路径、证书即将过期等）
- [ ] **REST API 完善** — 完整的 CRUD API，支持外部系统集成（SIEM/SOAR）
- [ ] **Webhook 回调** — 扫描完成后 POST 结果到指定 URL

## v3.0 — 协作与高级功能

- [ ] **多用户支持** — 用户认证、权限管理、团队协作（参考 SpiderFoot）
- [ ] **资产关联图谱** — 域名 → IP → ASN → 组织的关联关系图（参考 Amass Graph）
- [ ] **攻击面管理** — 持续监控模式，自动发现和追踪互联网暴露资产（参考 Censys ASM）
- [ ] **插件系统** — 模块化架构，支持社区贡献的扫描模块和情报源（参考 Recon-ng）
- [ ] **Docker 部署** — 一键 docker-compose 启动，含数据库和定时任务
