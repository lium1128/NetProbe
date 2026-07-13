"""内置插件注册 — 将现有 14 个检测模块包装为插件。

每个插件类是对原有检测函数的薄包装，不修改原有逻辑。
通过 @register_plugin 装饰器自动注册到 registry。
"""
from .base import Plugin
from .registry import register


@register
class SSLCheckPlugin(Plugin):
    name = 'ssl_check'
    display_name = 'SSL/TLS 深度检测'
    description = '检测弱协议版本、弱加密套件、证书过期/自签名/域名不匹配'
    category = 'vuln'
    stage = 'vuln'
    icon = '🔒'

    def run(self, hosts, options, emit=None):
        from ..ssl_check import check_ssl_for_hosts
        return check_ssl_for_hosts(hosts)


@register
class CORSPlugin(Plugin):
    name = 'cors_check'
    display_name = 'CORS 配置检测'
    description = '检测跨域资源共享(CORS)配置缺陷，识别允许任意来源的危险配置'
    category = 'vuln'
    stage = 'vuln'
    icon = '🌐'

    def run(self, hosts, options, emit=None):
        from ..cors_check import check_cors_for_hosts
        check_cors_for_hosts(hosts)
        return sum(len(h.get('_cors_findings', [])) for h in hosts)


@register
class SecurityHeadersPlugin(Plugin):
    name = 'security_headers'
    display_name = 'HTTP 安全响应头检测'
    description = '检测缺失的 HSTS / X-Frame-Options / X-Content-Type-Options 等安全头'
    category = 'vuln'
    stage = 'vuln'
    icon = '🛡'

    def run(self, hosts, options, emit=None):
        from ..security_headers import check_security_headers_for_hosts
        check_security_headers_for_hosts(hosts)
        return sum(len(h.get('_security_findings', [])) for h in hosts)


@register
class UnauthScanPlugin(Plugin):
    name = 'unauth_scan'
    display_name = '未授权接口枚举'
    description = '检测 Swagger / actuator / phpinfo / .env / Druid 等 40+ 未授权暴露接口'
    category = 'vuln'
    stage = 'vuln'
    icon = '🔓'

    def run(self, hosts, options, emit=None):
        from ..unauth_scan import scan_unauth_for_hosts
        return scan_unauth_for_hosts(hosts)


@register
class BruteForcePlugin(Plugin):
    name = 'brute_force'
    display_name = '端口弱口令爆破'
    description = '对 SSH / MySQL / Redis / FTP / PostgreSQL 进行弱口令检测'
    category = 'vuln'
    stage = 'vuln'
    icon = '🔑'

    def run(self, hosts, options, emit=None):
        from ..brute_force import brute_force_for_hosts
        brute_force_for_hosts(hosts, options)
        return sum(len(h.get('_brute_findings', [])) for h in hosts)


@register
class WAFDetectPlugin(Plugin):
    name = 'waf_detect'
    display_name = 'WAF/防护层识别'
    description = '识别 Cloudflare / 阿里云 / 腾讯云 / 360 等 20+ WAF 厂商'
    category = 'info'
    stage = 'vuln'
    icon = '🧱'

    def run(self, hosts, options, emit=None):
        from ..waf_detect import detect_waf_for_hosts
        return detect_waf_for_hosts(hosts)


@register
class MailSecurityPlugin(Plugin):
    name = 'mail_security'
    display_name = '邮件安全基线'
    description = '检测 SPF / DKIM / DMARC / MTA-STS 邮件安全配置完整性'
    category = 'vuln'
    stage = 'web'
    icon = '📧'

    def run(self, hosts, options, emit=None):
        from ..mail_security import check_mail_security_for_hosts
        return check_mail_security_for_hosts(hosts)


@register
class AdminDetectPlugin(Plugin):
    name = 'admin_detect'
    display_name = '管理后台识别'
    description = '通过 title / URL / 正文关键词三重判定识别管理后台'
    category = 'recon'
    stage = 'sensitive'
    icon = '⚙'

    def run(self, hosts, options, emit=None):
        from ..admin_detect import detect_admin_panels
        return detect_admin_panels(hosts)


@register
class RobotsSitemapPlugin(Plugin):
    name = 'robots_sitemap'
    display_name = 'robots.txt / sitemap 解析'
    description = '解析 robots.txt 和 sitemap.xml，提取路径并发现隐藏接口'
    category = 'recon'
    stage = 'sensitive'
    icon = '🗺'

    def run(self, hosts, options, emit=None):
        from ..robots_sitemap import parse_robots_for_hosts
        parse_robots_for_hosts(hosts)
        return sum(len(h.get('_robots_findings', [])) for h in hosts)


@register
class DirBrutePlugin(Plugin):
    name = 'dir_brute'
    display_name = '目录爆破'
    description = '基于字典的目录/文件枚举（114 词表）'
    category = 'recon'
    stage = 'dir_brute'
    icon = '📂'

    def run(self, hosts, options, emit=None):
        from ..dir_brute import brute_for_hosts
        brute_for_hosts(hosts)
        return sum(len(h.get('_dir_findings', [])) for h in hosts)


@register
class TakeoverDetectPlugin(Plugin):
    name = 'takeover_detect'
    display_name = '子域名接管检测'
    description = '检测 CNAME 指向未注册 SaaS 的 dangling DNS（10 种 SaaS 指纹）'
    category = 'vuln'
    stage = 'takeover'
    icon = '⚠'

    def run(self, hosts, options, emit=None):
        from ..takeover_detect import detect_takeover_for_hosts
        return detect_takeover_for_hosts(hosts)


@register
class OriginIPPlugin(Plugin):
    name = 'origin_ip'
    display_name = 'CDN 真实 IP 发现'
    description = '通过历史 DNS / 证书 / favicon_hash 发现 CDN 背后的源站 IP（由引擎直接调度）'
    category = 'recon'
    stage = '_engine_managed'  # 不由插件系统自动调用（引擎有特殊 DB 写入逻辑）
    icon = '📍'

    def run(self, hosts, options, emit=None):
        # 引擎层直接调用 origin_ip，插件只做展示
        return 0


@register
class CVEMatchPlugin(Plugin):
    name = 'cve_match'
    display_name = 'CVE 关联与漏洞优先级'
    description = '指纹版本 → OSV/NVD 关联已知 CVE（含 CVSS 评分，由风险评分模块内部调用）'
    category = 'vuln'
    stage = '_engine_managed'  # 不由插件系统自动调用（risk.py 内部调度）
    icon = '🔴'

    def run(self, hosts, options, emit=None):
        """CVE 关联在 risk.py 内部调用，这里不重复执行。
        注册为插件是为了在前端展示和可配置。"""
        return 0
