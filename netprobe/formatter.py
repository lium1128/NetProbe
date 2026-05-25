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
    """生成 PDF 报告用的完整 HTML。"""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
