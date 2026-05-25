# NetProbe Roadmap

参考 [OneForAll](https://github.com/shmilylty/OneForAll)、[Amass](https://github.com/owasp-amass/amass)、[SpiderFoot](https://github.com/smicallef/spiderfoot)、[Shodan](https://www.shodan.io/)、[Censys](https://censys.io/)、[FOFA](https://fofa.info/)、[ARL](https://github.com/TophantTechnology/ARL)、[Recon-ng](https://github.com/lanmaster53/recon-ng)、[Nuclei](https://github.com/projectdiscovery/nuclei)、[Wappalyzer](https://github.com/wappalyzer/wappalyzer) 等竞品，规划以下功能。

> 优先级可能根据社区反馈调整，欢迎在 [Issue](https://github.com/lium1128/NetProbe/issues) 中投票或提交建议。

---

## v2.1 — 资产指纹增强

- [ ] **Favicon 哈希指纹** — 计算站点 favicon 的 MMH3 哈希（参考 FOFA `icon_hash`），用于精准识别 Web 应用产品
- [ ] **指纹版本提取** — 从 Banner、HTTP 头、HTML 内容中提取组件具体版本号（如 `nginx/1.24.0`、`WordPress 6.4`），而不仅仅是名称
- [ ] **扩展协议 Banner 解析** — 新增 RDP、SMB、VNC、Telnet、MQTT、Memcached、Elasticsearch、Docker API、K8s API 等 10+ 协议识别（参考 Shodan 深度协议检测）
- [ ] **CDN / WAF / 云平台检测** — 识别 Cloudflare、AWS CloudFront、Akamai、宝塔、安全狗等 CDN 和 WAF 产品（参考 Censys、Wappalyzer）
- [ ] **指纹置信度评分** — 为每条指纹匹配结果附加置信度百分比（参考 Wappalyzer），减少误报
- [ ] **社区指纹规则扩展** — 兼容 Wappalyzer JSON 指纹格式，支持导入社区指纹库（覆盖数千种技术）

## v2.2 — 任务控制与持久化

- [ ] **扫描任务管理** — 支持暂停 / 恢复 / 取消正在运行的扫描任务
- [ ] **扫描历史记录** — 结果持久化存储（SQLite），支持查看、搜索、对比历史扫描
- [ ] **定时扫描** — cron 表达式调度周期性扫描任务，自动检测资产变化
- [ ] **结果对比 (Diff)** — 同一目标多次扫描结果 diff，高亮新增/消失的子域名、端口、服务、技术栈变化（参考 Shodan Monitor、Censys ASM）

## v2.3 — 资产关联与线索追踪

- [ ] **跨资产关联引擎** — 自动关联：同 IP 多域名、同证书多域名、同 CNAME 多服务、同 Banner 模式多主机（参考 SpiderFoot 关联引擎）
- [ ] **基于证书的资产发现** — 从 SSL 证书 SAN / Subject 中提取关联域名，扩展资产范围（参考 Censys、Amass）
- [ ] **种子扩展 (Pivot)** — 从一个域名 → IP → ASN → 网段 → 更多域名，自动扩展攻击面（参考 Amass Graph）
- [ ] **反向搜索** — 给定 IP，反查所有关联域名、证书、历史记录（参考 Shodan、FOFA）
- [ ] **IOC / APT 线索追踪** — 根据 Banner 特征、证书指纹、Favicon 哈希等指标追踪基础设施（参考 FOFA 5.0 APT 追踪）
- [ ] **WHOIS 查询与反查** — 域名注册信息、注册商、过期时间、反查关联域名（参考 Amass、SpiderFoot）
- [ ] **DNS 区域传送** — 尝试 AXFR 获取完整 DNS 记录

## v2.4 — 可视化与报告

- [ ] **资产关系图谱** — 域名 ↔ IP ↔ 证书 ↔ ASN ↔ 组织的关联关系可视化（参考 Amass Graph、SpiderFoot）
- [ ] **交互式统计图表** — 端口分布、技术栈统计、资产拓扑图（ECharts / D3.js）
- [ ] **Web 截图** — 对探测到的 Web 站点自动截图，直观展示页面内容
- [ ] **HTML 报告** — 独立可分享的 HTML 格式报告，无需依赖服务端

## v2.5 — 告警与集成

- [ ] **多渠道通知** — 扫描完成后通过邮件、Slack、企业微信、钉钉、Webhook 推送结果
- [ ] **告警规则** — 自定义告警条件（新开放端口、新子域名、高危敏感路径、证书即将过期、技术栈变化等）
- [ ] **REST API 完善** — 完整的 CRUD API，支持外部系统集成（SIEM / SOAR）
- [ ] **子域名接管检测** — 检测 CNAME 指向未注册的 SaaS / Cloud 服务的 dangling DNS 记录

## v3.0 — 协作与高级功能

- [ ] **多用户支持** — 用户认证、权限管理、团队协作（参考 SpiderFoot）
- [ ] **攻击面管理** — 持续监控模式，自动发现和追踪互联网暴露资产（参考 Censys ASM）
- [ ] **技术到漏洞映射** — 检测到技术栈后自动匹配已知 CVE 和漏洞（参考 Nuclei `-as` 自动扫描模式）
- [ ] **插件系统** — 模块化架构，支持社区贡献的扫描模块和情报源（参考 Recon-ng）
- [ ] **Docker 部署** — 一键 docker-compose 启动，含数据库和定时任务
