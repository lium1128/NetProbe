import csv
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

        # 端口信息
        ports = host.get('ports', [])
        if ports:
            print(f'      开放端口:')
            for p in ports:
                svc = _format_service(p)
                print(f'        - {p["port"]}/{p["proto"]:<4} {svc}')
        else:
            print(f'      开放端口: 无')

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
            for p in host.get('ports', []):
                svc = _format_service(p)
                f.write(f"  端口: {p['port']}/{p['proto']} {svc}\n")
            for w in host.get('web_info', []):
                f.write(f"  Web: {w.get('url', '')} [{w.get('status', '')}] \"{w.get('title', '')}\"\n")
            f.write('\n')


def save_to_csv(hosts: list[dict], filepath: str) -> None:
    with open(filepath, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['hostname', 'ip', 'port', 'proto', 'state', 'service', 'product', 'version', 'web_url', 'web_status', 'web_title'])
        for host in hosts:
            hostname = host.get('hostname', '')
            ip = host.get('ip', '')
            ports = host.get('ports', [])
            web_info = host.get('web_info', [])

            if not ports and not web_info:
                writer.writerow([hostname, ip, '', '', '', '', '', '', '', '', ''])
                continue

            for p in ports:
                web_url, web_status, web_title = '', '', ''
                # 匹配该端口的 web 信息
                for w in web_info:
                    if w.get('port') == p['port']:
                        web_url = w.get('url', '')
                        web_status = w.get('status', '')
                        web_title = w.get('title', '')
                        break
                writer.writerow([
                    hostname, ip,
                    p['port'], p['proto'], p.get('state', ''),
                    p.get('service', ''), p.get('product', ''), p.get('version', ''),
                    web_url, web_status, web_title,
                ])
            # 没有 port 匹配的 web 信息
            web_ports = {w.get('port') for w in web_info}
            for w in web_info:
                if w.get('port') not in {p['port'] for p in ports}:
                    writer.writerow([
                        hostname, ip, '', '', '', '', '', '',
                        w.get('url', ''), w.get('status', ''), w.get('title', ''),
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
