import csv
import html
import json
from datetime import datetime


def display_results(hosts: list[dict], base_domain: str) -> None:
    """在终端打印完整探测结果。每个 host 包含 hostname, ip, ports, web_info。"""
    width = 70
    total_ports = sum(len(h.get('ports', [])) for h in hosts)
    total_web = sum(len(h.get('web_info', [])) for h in hosts)

    print('=' * width)
    print(f'  域名探测结果 - {base_domain}')
    print(f'  主机数: {len(hosts)} | 开放端口: {total_ports} | Web站点: {total_web}')
    print('=' * width)

    if not hosts:
        print('  未发现主机')
        print('=' * width)
        return

    for i, host in enumerate(hosts, 1):
        hostname = host.get('hostname', '')
        ip = host.get('ip', '')
        print()
        print(f'  [{i}] {hostname or ip}')
        print(f'      IP: {ip}')

        # 操作系统
        os_info = host.get('os', '')
        if os_info:
            print(f'      操作系统: {os_info}')

        # 端口信息
        ports = host.get('ports', [])
        if ports:
            print(f'      开放端口:')
            for p in ports:
                svc = _format_service(p)
                print(f'        - {p["port"]}/{p["proto"]:<4} {svc}')
        else:
            print(f'      开放端口: 无')

        # Banner 信息
        banners = host.get('banners', [])
        if banners:
            print(f'      Banner:')
            for b in banners:
                print(f'        - {b["port"]}/{b["service"]}: {b["banner"][:120]}')

        # Web 信息
        web_info = host.get('web_info', [])
        if web_info:
            print(f'      Web站点:')
            for w in web_info:
                title = w.get('title', '')
                status = w.get('status', '')
                url = w.get('url', '')
                redirect = w.get('redirect', '')
                line = f'        - {url} [{status}]'
                if title:
                    line += f' "{title}"'
                if redirect:
                    line += f' -> {redirect}'
                print(line)
                # SSL 信息
                ssl = w.get('ssl')
                if ssl and ssl.get('subject'):
                    expired = ' [已过期]' if ssl.get('expired') else ''
                    print(f'          SSL: {ssl.get("subject")} | 颁发: {ssl.get("issuer")} | {ssl.get("protocol")}{expired}')
                # HTTP 指纹
                hdrs = w.get('headers', {})
                if hdrs:
                    fp = [v for v in [hdrs.get('server'), hdrs.get('powered_by'), hdrs.get('framework'), hdrs.get('cms')] if v]
                    if fp:
                        print(f'          指纹: {", ".join(fp)}')

    print()
    print('=' * width)


def _format_service(port_info: dict) -> str:
    """格式化服务信息。"""
    parts = []
    service = port_info.get('service', '')
    product = port_info.get('product', '')
    version = port_info.get('version', '')

    if service:
        parts.append(service)
    if product:
        parts.append(product)
    if version:
        parts.append(version)
    return ' '.join(parts) if parts else 'unknown'


def save_results(
    hosts: list[dict],
    filepath: str,
    fmt: str,
    base_domain: str,
) -> None:
    fmt = fmt.lower()
    if fmt == 'csv':
        save_to_csv(hosts, filepath)
    elif fmt == 'json':
        save_to_json(hosts, filepath, base_domain)
    elif fmt == 'pdf':
        save_to_pdf(hosts, filepath, base_domain)
    elif fmt == 'html':
        save_to_html(hosts, filepath, base_domain)
    else:
        save_to_txt(hosts, filepath, base_domain)


def save_to_txt(hosts: list[dict], filepath: str, base_domain: str) -> None:
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f'# 域名探测结果 - {base_domain}\n')
        f.write(f'# 生成时间: {now}\n')
        f.write(f'# 主机数: {len(hosts)}\n\n')
        for host in hosts:
            f.write(f"主机: {host.get('hostname', 'N/A')}\n")
            f.write(f"IP: {host.get('ip', 'N/A')}\n")
            os_info = host.get('os', '')
            if os_info:
                f.write(f"操作系统: {os_info}\n")
            for p in host.get('ports', []):
                svc = _format_service(p)
                f.write(f"  端口: {p['port']}/{p['proto']} {svc}\n")
            for b in host.get('banners', []):
                f.write(f"  Banner: {b['port']}/{b['service']} {b['banner'][:200]}\n")
            for w in host.get('web_info', []):
                f.write(f"  Web: {w.get('url', '')} [{w.get('status', '')}] \"{w.get('title', '')}\"\n")
                ssl = w.get('ssl')
                if ssl and ssl.get('subject'):
                    f.write(f"  SSL: {ssl.get('subject')} | {ssl.get('issuer')} | {ssl.get('protocol')}\n")
                hdrs = w.get('headers', {})
                if hdrs:
                    fp = [v for v in [hdrs.get('server'), hdrs.get('powered_by'), hdrs.get('framework'), hdrs.get('cms')] if v]
                    if fp:
                        f.write(f"  指纹: {', '.join(fp)}\n")
            f.write('\n')


def save_to_csv(hosts: list[dict], filepath: str) -> None:
    with open(filepath, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['hostname', 'ip', 'os', 'port', 'proto', 'state', 'service',
                         'product', 'version', 'banner', 'web_url', 'web_status', 'web_title',
                         'ssl_subject', 'ssl_issuer', 'ssl_protocol', 'http_fingerprint'])
        for host in hosts:
            hostname = host.get('hostname', '')
            ip = host.get('ip', '')
            os_info = host.get('os', '')
            ports = host.get('ports', [])
            web_info = host.get('web_info', [])
            banners = host.get('banners', [])

            banner_by_port = {b['port']: b['banner'][:200] for b in banners}

            if not ports and not web_info:
                writer.writerow([hostname, ip, os_info, '', '', '', '', '', '', '', '', '', '', '', '', '', ''])
                continue

            for p in ports:
                web_url, web_status, web_title = '', '', ''
                ssl_subject, ssl_issuer, ssl_protocol, http_fp = '', '', '', ''
                for w in web_info:
                    if w.get('port') == p['port']:
                        web_url = w.get('url', '')
                        web_status = w.get('status', '')
                        web_title = w.get('title', '')
                        ssl = w.get('ssl') or {}
                        ssl_subject = ssl.get('subject', '')
                        ssl_issuer = ssl.get('issuer', '')
                        ssl_protocol = ssl.get('protocol', '')
                        hdrs = w.get('headers', {})
                        fp = [v for v in [hdrs.get('server'), hdrs.get('powered_by'), hdrs.get('framework'), hdrs.get('cms')] if v]
                        http_fp = ', '.join(fp)
                        break
                writer.writerow([
                    hostname, ip, os_info,
                    p['port'], p['proto'], p.get('state', ''),
                    p.get('service', ''), p.get('product', ''), p.get('version', ''),
                    banner_by_port.get(p['port'], ''),
                    web_url, web_status, web_title,
                    ssl_subject, ssl_issuer, ssl_protocol, http_fp,
                ])
            # Web entries without matching port
            web_ports = {w.get('port') for w in web_info}
            for w in web_info:
                if w.get('port') not in {p['port'] for p in ports}:
                    ssl = w.get('ssl') or {}
                    hdrs = w.get('headers', {})
                    fp = [v for v in [hdrs.get('server'), hdrs.get('powered_by'), hdrs.get('framework'), hdrs.get('cms')] if v]
                    writer.writerow([
                        hostname, ip, os_info, '', '', '', '', '', '',
                        banner_by_port.get(w.get('port', 0), ''),
                        w.get('url', ''), w.get('status', ''), w.get('title', ''),
                        ssl.get('subject', ''), ssl.get('issuer', ''), ssl.get('protocol', ''),
                        ', '.join(fp),
                    ])


def save_to_json(hosts: list[dict], filepath: str, base_domain: str) -> None:
    data = {
        'domain': base_domain,
        'scan_date': datetime.now().isoformat(),
        'total_hosts': len(hosts),
        'hosts': hosts,
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


# ── PDF 导出 (HTML → Playwright) ───────────────────────

def _build_report_html(hosts: list[dict], base_domain: str) -> str:
    """生成专业渗透测试报告 HTML。

    包含:
    1. 封面（标题/目标/日期/统计）
    2. 执行摘要（风险评级/统计概览/关键发现）
    3. 风险矩阵（漏洞严重性分布）
    4. 漏洞详情（按严重性排序，含修复建议）
    5. 资产清单（主机/端口/Web站点/技术栈）
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_ports = sum(len(h.get('ports', [])) for h in hosts)
    total_web = sum(len(h.get('web_info', [])) for h in hosts)
    total_sensitive = sum(len(h.get('sensitive', [])) for h in hosts)

    # 收集所有漏洞（跨主机）
    all_vulns = []
    for h in hosts:
        for v in h.get('vulnerabilities', []):
            v['_hostname'] = h.get('hostname', '')
            v['_ip'] = h.get('ip', '')
            all_vulns.append(v)
    # 按严重性排序
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_vulns.sort(key=lambda v: sev_order.get((v.get('severity') or 'info').lower(), 5))

    # 风险评级
    risk_score = max((h.get('risk_score', 0) for h in hosts), default=0)
    if risk_score >= 70:
        risk_level, risk_color, risk_desc = '高危', '#dc2626', '存在严重安全风险，建议立即整改'
    elif risk_score >= 40:
        risk_level, risk_color, risk_desc = '中危', '#d97706', '存在中等安全风险，建议尽快修复'
    elif risk_score >= 20:
        risk_level, risk_color, risk_desc = '低危', '#2563eb', '存在少量安全问题，建议关注'
    else:
        risk_level, risk_color, risk_desc = '安全', '#10b981', '未发现重大安全问题'

    # 漏洞统计
    vuln_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in all_vulns:
        sev = (v.get('severity') or 'info').lower()
        vuln_stats[sev] = vuln_stats.get(sev, 0) + 1

    # 修复建议库
    fix_suggestions = _get_fix_suggestions(all_vulns)

    parts = [f'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<style>
@page {{ size: A4; margin: 15mm 12mm; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: "Microsoft YaHei","PingFang SC","Noto Sans SC","Segoe UI",sans-serif;
       color: #1e293b; font-size: 10pt; line-height: 1.6; }}

/* 封面 */
.cover {{ text-align: center; padding-top: 120px; page-break-after: always; }}
.cover h1 {{ font-size: 36pt; color: #2563eb; margin-bottom: 4px; letter-spacing: 2px; }}
.cover .subtitle {{ font-size: 14pt; color: #64748b; margin-bottom: 32px; }}
.cover h2 {{ font-size: 18pt; color: #1e293b; font-weight: 600; margin-bottom: 16px; }}
.cover .meta {{ font-size: 11pt; color: #64748b; line-height: 2; }}
.cover .badge {{ display: inline-block; padding: 6px 20px; border-radius: 20px;
                font-size: 14pt; font-weight: 700; color: #fff; margin-top: 16px;
                background: {risk_color}; }}

/* 章节标题 */
h2.section {{ font-size: 16pt; color: #1e293b; border-bottom: 2px solid #2563eb;
              padding-bottom: 6px; margin: 24px 0 12px 0; }}
h3.subsection {{ font-size: 12pt; color: #334155; margin: 16px 0 8px 0;
                 border-left: 3px solid #2563eb; padding-left: 8px; }}

/* 统计卡片 */
.stats-grid {{ display: flex; gap: 12px; margin: 12px 0; }}
.stat-card {{ flex: 1; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; text-align: center; }}
.stat-card .num {{ font-size: 22pt; font-weight: 700; }}
.stat-card .lbl {{ font-size: 9pt; color: #64748b; margin-top: 2px; }}

/* 风险矩阵 */
.risk-matrix {{ display: flex; gap: 8px; margin: 12px 0; }}
.risk-bar {{ flex: 1; border-radius: 6px; padding: 8px; text-align: center; color: #fff; }}
.risk-bar .count {{ font-size: 18pt; font-weight: 700; }}
.risk-bar .label {{ font-size: 9pt; }}

/* 表格 */
table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 9pt; }}
th {{ background: #1e293b; color: #fff; padding: 6px 8px; text-align: left; font-weight: 600; }}
td {{ padding: 5px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; word-break: break-all; }}
tr:nth-child(even) td {{ background: #f8fafc; }}

/* 漏洞条目 */
.vuln-item {{ border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px;
             page-break-inside: avoid; }}
.vuln-item-head {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
.vuln-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 8pt;
               font-weight: 700; color: #fff; }}
.vuln-badge.critical {{ background: #dc2626; }}
.vuln-badge.high {{ background: #ea580c; }}
.vuln-badge.medium {{ background: #d97706; }}
.vuln-badge.low {{ background: #2563eb; }}
.vuln-badge.info {{ background: #64748b; }}
.vuln-name {{ font-weight: 600; font-size: 10pt; flex: 1; }}
.vuln-host {{ font-size: 9pt; color: #64748b; font-family: "Consolas",monospace; }}
.vuln-fix {{ margin-top: 6px; padding: 6px 10px; background: #f0fdf4; border-radius: 4px;
             font-size: 9pt; color: #166534; border-left: 3px solid #10b981; }}
.vuln-cve {{ font-family: "Consolas",monospace; font-size: 9pt; color: #2563eb; }}

/* 通用 */
.mono {{ font-family: "Cascadia Code","Consolas","Courier New",monospace; font-size: 8.5pt; }}
.tag {{ display: inline-block; background: #eff6ff; color: #2563eb; border-radius: 3px;
        padding: 1px 6px; margin: 1px 2px; font-size: 8pt; }}
.host-block {{ page-break-before: always; }}
.host-block:first-of-type {{ page-break-before: auto; }}
.host-header {{ border-bottom: 2px solid #2563eb; padding-bottom: 6px; margin-bottom: 12px; }}
.host-header h3 {{ font-size: 14pt; color: #1e293b; }}
</style></head><body>

<!-- 封面 -->
<div class="cover">
  <h1>NetProbe</h1>
  <div class="subtitle">攻击面安全评估报告</div>
  <h2>{html.escape(base_domain)}</h2>
  <div class="meta">
    <p>报告日期: {now}</p>
    <p>主机数: {len(hosts)} &nbsp;|&nbsp; 端口: {total_ports} &nbsp;|&nbsp; Web站点: {total_web}</p>
  </div>
  <div class="badge">{risk_level}（{risk_score}分）</div>
  <p class="meta" style="margin-top:12px;font-size:10pt">{risk_desc}</p>
</div>

<!-- 执行摘要 -->
<h2 class="section">一、执行摘要</h2>
<p>本次安全评估对目标 <b>{html.escape(base_domain)}</b> 进行了全面的攻击面扫描，
共发现 <b>{len(hosts)}</b> 台主机、<b>{total_ports}</b> 个开放端口、<b>{total_web}</b> 个 Web 站点。</p>

<div class="stats-grid">
  <div class="stat-card"><div class="num" style="color:{risk_color}">{risk_score}</div><div class="lbl">风险评分</div></div>
  <div class="stat-card"><div class="num" style="color:#dc2626">{vuln_stats['critical']}</div><div class="lbl">严重漏洞</div></div>
  <div class="stat-card"><div class="num" style="color:#ea580c">{vuln_stats['high']}</div><div class="lbl">高危漏洞</div></div>
  <div class="stat-card"><div class="num" style="color:#d97706">{vuln_stats['medium']}</div><div class="lbl">中危漏洞</div></div>
  <div class="stat-card"><div class="num">{total_sensitive}</div><div class="lbl">敏感路径</div></div>
</div>

<!-- 风险矩阵 -->
<h2 class="section">二、风险矩阵</h2>
<div class="risk-matrix">
  <div class="risk-bar" style="background:#dc2626"><div class="count">{vuln_stats['critical']}</div><div class="label">严重 Critical</div></div>
  <div class="risk-bar" style="background:#ea580c"><div class="count">{vuln_stats['high']}</div><div class="label">高危 High</div></div>
  <div class="risk-bar" style="background:#d97706"><div class="count">{vuln_stats['medium']}</div><div class="label">中危 Medium</div></div>
  <div class="risk-bar" style="background:#2563eb"><div class="count">{vuln_stats['low']}</div><div class="label">低危 Low</div></div>
  <div class="risk-bar" style="background:#64748b"><div class="count">{vuln_stats['info']}</div><div class="label">信息 Info</div></div>
</div>
''']

    # 漏洞详情
    if all_vulns:
        parts.append('<h2 class="section">三、漏洞详情</h2>')
        for v in all_vulns[:50]:  # 最多 50 条
            sev = (v.get('severity') or 'info').lower()
            name = html.escape(v.get('name', '未知漏洞'))
            cve = v.get('cve', '')
            cvss = v.get('cvss_score', '')
            hostname = html.escape(v.get('_hostname', ''))
            category = v.get('category', '')
            fix = fix_suggestions.get(category, fix_suggestions.get('_default', ''))

            parts.append('<div class="vuln-item">')
            parts.append(f'<div class="vuln-item-head">')
            parts.append(f'<span class="vuln-badge {sev}">{sev.upper()}</span>')
            parts.append(f'<span class="vuln-name">{name}</span>')
            if cve:
                parts.append(f'<span class="vuln-cve">{html.escape(cve)}</span>')
            if cvss:
                parts.append(f'<span class="vuln-cve">CVSS {html.escape(str(cvss))}</span>')
            parts.append('</div>')
            parts.append(f'<div class="vuln-host">主机: {hostname}')
            if category:
                parts.append(f' &nbsp;|&nbsp; 类型: {html.escape(category)}')
            parts.append('</div>')
            if fix:
                parts.append(f'<div class="vuln-fix">💡 <b>修复建议:</b> {html.escape(fix)}</div>')
            parts.append('</div>')

    # 资产清单
    parts.append('<h2 class="section">四、资产清单</h2>')
    for idx, host in enumerate(hosts, 1):
        hostname = html.escape(host.get('hostname', 'N/A'))
        ip = html.escape(host.get('ip', 'N/A'))
        host_risk = host.get('risk_score', 0)

        parts.append(f'<div class="host-block">')
        parts.append(f'<div class="host-header"><h3>[{idx}] {hostname}</h3>')
        parts.append(f'<div style="font-size:10pt;color:#64748b">IP: {ip}')
        if host_risk:
            parts.append(f' &nbsp;|&nbsp; 风险分: <b>{host_risk}</b>')
        parts.append('</div></div>')

        # 端口表格
        ports = host.get('ports', [])
        if ports:
            parts.append('<h3 class="subsection">端口服务</h3><table>')
            parts.append('<tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product</th></tr>')
            for p in ports:
                svc = html.escape(_format_service(p))
                product = html.escape(f'{p.get("product","")} {p.get("version","")}'.strip())
                parts.append(f'<tr><td class="mono">{p.get("port","")}</td>'
                             f'<td>{p.get("proto","")}</td><td>{p.get("state","")}</td>'
                             f'<td>{svc}</td><td>{product}</td></tr>')
            parts.append('</table>')

        # Web 站点
        web_info = host.get('web_info', [])
        if web_info:
            parts.append('<h3 class="subsection">Web 站点</h3><table>')
            parts.append('<tr><th style="width:50%">URL</th><th>Status</th><th>Title</th><th>Tech</th></tr>')
            for w in web_info:
                url = html.escape(w.get('url', ''))
                status = html.escape(str(w.get('status', '')))
                title = html.escape(w.get('title', '')[:40])
                tech_tags = ''.join(f'<span class="tag">{html.escape(t.get("name",""))}</span>'
                                    for t in (w.get('tech') or [])[:8])
                parts.append(f'<tr><td class="mono">{url}</td><td>{status}</td>'
                             f'<td>{title}</td><td>{tech_tags}</td></tr>')
            parts.append('</table>')

        # 技术栈
        all_tech = set()
        for w in web_info:
            for t in w.get('tech', []):
                name = t.get('name', '')
                ver = t.get('version', '')
                all_tech.add(f'{name} {ver}'.strip() if ver else name)
        if all_tech:
            parts.append('<h3 class="subsection">技术栈</h3>')
            parts.append('<div>' + ''.join(f'<span class="tag">{html.escape(t)}</span>' for t in sorted(all_tech)) + '</div>')

        parts.append('</div>')  # host-block

    parts.append('</body></html>')
    return '\n'.join(parts)


def _get_fix_suggestions(vulns: list[dict]) -> dict:
    """根据漏洞分类生成修复建议。"""
    suggestions = {
        'cve_fingerprint': '升级到安全版本，关注厂商安全公告，及时应用补丁修复已知 CVE。',
        'ssl_tls': '使用 TLS 1.2+ 协议，禁用弱加密套件（RC4/DES/3DES），及时更新即将过期的证书，使用 Let\'s Encrypt 自动续期。',
        'mail_security': '配置完整的 SPF + DMARC（p=reject）+ DKIM 三重邮件认证，添加 MTA-STS 策略强制 SMTP 加密传输。',
        'unauth_access': '限制管理接口的访问来源（IP 白名单/内网），禁用生产环境的调试端点（actuator/phpinfo/.env），配置访问认证。',
        'security_header': '配置 HSTS、X-Frame-Options、X-Content-Type-Options、Content-Security-Policy 等安全响应头。',
        'cors': '限制 CORS 允许的 Origin 为可信域名，禁止使用通配符 *，特别是带 credentials 的跨域。',
        'weak_password': '修改默认密码，使用强密码策略（12位+大小写+数字+特殊字符），启用密钥认证（SSH），限制登录失败次数。',
        'admin_panel': '限制管理后台访问来源，配置多因素认证，更改默认管理路径。',
        'origin_ip': '确保 CDN/WAF 配置正确不泄露源站 IP，防火墙只允许 CDN 回源 IP 访问。',
        'robots': '检查 robots.txt 是否泄露了敏感路径信息，避免暴露后台/管理接口路径。',
        '_default': '评估漏洞影响范围，根据业务优先级安排修复，关注厂商安全公告。',
    }
    # 按实际出现的 category 收集
    result = {v.get('category', '_default') for v in vulns if v.get('category')}
    return {cat: suggestions.get(cat, suggestions['_default']) for cat in result}
    total_ports = sum(len(h.get('ports', [])) for h in hosts)
    total_web = sum(len(h.get('web_info', [])) for h in hosts)
    total_sensitive = sum(len(h.get('sensitive', [])) for h in hosts)

    parts = [f'''<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<style>
@page {{ size: A4; margin: 15mm 12mm; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: "Microsoft YaHei","PingFang SC","Noto Sans SC","Segoe UI",sans-serif;
       color: #1e293b; font-size: 10pt; line-height: 1.5; }}
.cover {{ text-align: center; padding-top: 140px; page-break-after: always; }}
.cover h1 {{ font-size: 32pt; color: #2563eb; margin-bottom: 8px; }}
.cover h2 {{ font-size: 16pt; color: #475569; font-weight: 400; margin-bottom: 24px; }}
.cover .meta {{ font-size: 11pt; color: #64748b; }}
.cover .stats {{ margin-top: 16px; font-size: 11pt; color: #64748b; }}
.host {{ page-break-before: always; padding-top: 4px; }}
.host:first-of-type {{ page-break-before: auto; }}
.host-header {{ border-bottom: 2px solid #2563eb; padding-bottom: 6px; margin-bottom: 12px; }}
.host-header h3 {{ font-size: 14pt; color: #1e293b; }}
.host-header .sub {{ font-size: 10pt; color: #64748b; margin-top: 2px; }}
.section-title {{ font-size: 11pt; font-weight: 700; color: #334155; margin: 14px 0 6px 0;
                  border-left: 3px solid #2563eb; padding-left: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 9pt; }}
th {{ background: #1e293b; color: #fff; padding: 5px 8px; text-align: left; font-weight: 600; }}
td {{ padding: 5px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top;
     word-break: break-all; }}
tr:nth-child(even) td {{ background: #f8fafc; }}
.risk-high {{ color: #dc2626; font-weight: 700; }}
.risk-medium {{ color: #d97706; font-weight: 700; }}
.risk-low, .risk-info {{ color: #64748b; }}
.mono {{ font-family: "Cascadia Code","Consolas","Courier New",monospace; font-size: 8.5pt; }}
.info-line {{ font-size: 9pt; color: #64748b; padding: 1px 0; }}
.tag {{ display: inline-block; background: #eff6ff; color: #2563eb; border-radius: 3px;
        padding: 1px 6px; margin: 1px 2px; font-size: 8pt; }}
</style></head><body>

<div class="cover">
  <h1>NetProbe</h1>
  <h2>{html.escape(base_domain)}</h2>
  <p class="meta">Scan Date: {now}</p>
  <p class="stats">Hosts: {len(hosts)} &nbsp;|&nbsp; Ports: {total_ports} &nbsp;|&nbsp;
                    Web: {total_web} &nbsp;|&nbsp; Sensitive: {total_sensitive}</p>
</div>
''']

    for idx, host in enumerate(hosts, 1):
        hostname = html.escape(host.get('hostname', 'N/A'))
        ip = html.escape(host.get('ip', 'N/A'))
        os_info = host.get('os', '')

        parts.append(f'<div class="host">')
        parts.append(f'<div class="host-header"><h3>[{idx}] {hostname}</h3>')
        parts.append(f'<div class="sub">IP: {ip}')
        if os_info:
            parts.append(f' &nbsp;|&nbsp; OS: {html.escape(os_info)}')
        parts.append('</div></div>')

        # 端口表格
        ports = host.get('ports', [])
        if ports:
            parts.append('<div class="section-title">Ports</div><table>')
            parts.append('<tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr>')
            for p in ports:
                svc = html.escape(_format_service(p))
                parts.append(f'<tr><td class="mono">{p.get("port","")}</td>'
                             f'<td>{p.get("proto","")}</td><td>{p.get("state","")}</td>'
                             f'<td>{svc}</td></tr>')
            parts.append('</table>')

        # Web 站点
        web_info = host.get('web_info', [])
        if web_info:
            parts.append('<div class="section-title">Web Sites</div><table>')
            parts.append('<tr><th style="width:55%">URL / Info</th><th>Status</th>'
                         '<th style="width:25%">Tech</th></tr>')
            for w in web_info:
                url = html.escape(w.get('url', ''))
                status = html.escape(str(w.get('status', '')))
                title = html.escape(w.get('title', ''))
                redirect = html.escape(w.get('redirect', ''))
                tech_tags = ''.join(f'<span class="tag">{html.escape(t.get("name",""))}</span>'
                                    for t in w.get('tech', []))

                info = f'<b>{url}</b>'
                if title:
                    info += f'<br><span class="info-line">Title: {title}</span>'

                ssl = w.get('ssl')
                if ssl and ssl.get('subject'):
                    expired = ' <span class="risk-high">[EXPIRED]</span>' if ssl.get('expired') else ''
                    info += (f'<br><span class="info-line">SSL: {html.escape(ssl["subject"])} | '
                             f'Issuer: {html.escape(ssl.get("issuer",""))} | '
                             f'{html.escape(ssl.get("protocol",""))}{expired}</span>')

                hdrs = w.get('headers', {})
                fp = [v for v in [hdrs.get('server'), hdrs.get('powered_by'),
                                  hdrs.get('framework'), hdrs.get('cms')] if v]
                if fp:
                    info += f'<br><span class="info-line">Fingerprint: {html.escape(", ".join(fp))}</span>'

                if redirect:
                    info += f'<br><span class="info-line">Redirect: {redirect}</span>'

                parts.append(f'<tr><td>{info}</td><td>{status}</td><td>{tech_tags}</td></tr>')
            parts.append('</table>')

        # 敏感路径
        sensitive = host.get('sensitive', [])
        if sensitive:
            parts.append('<div class="section-title">Sensitive Paths</div><table>')
            parts.append('<tr><th>Path</th><th>Description</th><th>Status</th><th>Risk</th></tr>')
            for s in sensitive:
                sev = s.get('severity', '').lower()
                risk_cls = f'risk-{sev}' if sev in ('high', 'medium', 'low', 'info') else ''
                parts.append(f'<tr><td class="mono">{html.escape(s.get("path",""))}</td>'
                             f'<td>{html.escape(s.get("description",""))}</td>'
                             f'<td>{s.get("status","")}</td>'
                             f'<td class="{risk_cls}">{html.escape(sev.upper())}</td></tr>')
            parts.append('</table>')

        # JS 分析
        js_findings = host.get('js_findings', [])
        if js_findings:
            parts.append('<div class="section-title">JS Analysis</div><table>')
            parts.append('<tr><th style="width:35%">JS File</th><th>API Endpoints</th>'
                         '<th>Leaks</th></tr>')
            for j in js_findings:
                apis = '<br>'.join(html.escape(a) for a in j.get('api_endpoints', [])[:10]) or '-'
                secrets = '<br>'.join(
                    f'<span class="risk-{s.get("severity","").lower()}">'
                    f'[{html.escape(s.get("severity","").upper())}] '
                    f'{html.escape(s.get("type",""))}: {html.escape(s.get("match",""))}</span>'
                    for s in j.get('secrets', [])
                ) or '-'
                parts.append(f'<tr><td class="mono">{html.escape(j.get("js_url",""))}</td>'
                             f'<td class="mono">{apis}</td><td class="mono">{secrets}</td></tr>')
            parts.append('</table>')

        # Banner
        banners = host.get('banners', [])
        if banners:
            parts.append('<div class="section-title">Banners</div><table>')
            parts.append('<tr><th>Port</th><th>Service</th><th>Banner</th></tr>')
            for b in banners:
                parts.append(f'<tr><td>{b.get("port","")}</td><td>{html.escape(b.get("service",""))}</td>'
                             f'<td class="mono">{html.escape(b.get("banner","")[:200])}</td></tr>')
            parts.append('</table>')

        parts.append('</div>')

    parts.append('</body></html>')
    return '\n'.join(parts)


def save_to_pdf(hosts: list[dict], filepath: str, base_domain: str) -> None:
    from playwright.sync_api import sync_playwright

    html_content = _build_report_html(hosts, base_domain)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_content(html_content, wait_until='networkidle')
        page.pdf(path=filepath, format='A4',
                 margin={'top': '15mm', 'bottom': '15mm', 'left': '12mm', 'right': '12mm'})
        browser.close()


def save_to_html(hosts: list[dict], filepath: str, base_domain: str) -> None:
    """导出独立可分享的 HTML 报告（复用 PDF 的 HTML 模板，不转 PDF）。"""
    html_content = _build_report_html(hosts, base_domain)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)
