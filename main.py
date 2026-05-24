import argparse
import os
import sys
import time

import requests

from dns_utils import filter_results, resolve_a_record, reverse_dns_lookup
from formatter import display_results, save_results
from scanner import check_nmap_available, run_dns_brute, run_port_scan
from utils import extract_root_domain, is_ip_address, validate_input
from web_probe import probe_web_for_host
from wordlist import get_default_wordlist_path, load_external_wordlist


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='域名综合探测工具 (子域名发现 + 端口扫描 + Web探测)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='示例:\n'
               '  python main.py example.com\n'
               '  python main.py 93.184.216.34\n'
               '  python main.py example.com -o result.json -f json\n'
               '  python main.py example.com --no-dns-brute\n'
               '  python main.py example.com -w custom_wordlist.txt\n',
    )
    parser.add_argument('targets', nargs='+', help='目标域名或 IP，多个用空格分隔')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument(
        '-f', '--format',
        choices=['txt', 'csv', 'json'],
        default='txt',
        help='输出格式 (默认: txt)',
    )
    parser.add_argument('-w', '--wordlist', help='外部子域名字典文件')
    parser.add_argument(
        '--no-validate',
        action='store_true',
        help='跳过 DNS 解析验证',
    )
    parser.add_argument(
        '--no-dns-brute',
        action='store_true',
        help='跳过子域名枚举，只探测主域名',
    )
    parser.add_argument(
        '--no-web',
        action='store_true',
        help='跳过 Web 站点探测',
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='nmap 扫描超时秒数 (默认: 300)',
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='显示详细过程',
    )
    return parser


def log(msg: str) -> None:
    print(f'[*] {msg}')


def main() -> None:
    # 禁用 requests 的 InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )

    parser = build_parser()
    args = parser.parse_args()

    # 1. 校验输入
    targets = []
    for t in args.targets:
        try:
            targets.append(validate_input(t))
        except ValueError as e:
            print(f'[!] 输入错误: {e}')
            sys.exit(1)

    # 2. 检查 nmap
    log('检查 nmap 是否可用...')
    if not check_nmap_available():
        print('[!] nmap 未安装或不在 PATH 中')
        print('    请从 https://nmap.org/download.html 下载安装')
        print('    Windows 安装时勾选 "Add to PATH"')
        sys.exit(1)

    log(f'共 {len(targets)} 个目标: {", ".join(targets)}')
    print()

    # 3. 逐个目标扫描
    all_hosts = []
    domain_labels = []

    try:
        for ti, target in enumerate(targets, 1):
            print(f'━━━ 目标 [{ti}/{len(targets)}] {target} ━━━')

            # 解析域名/IP
            if is_ip_address(target):
                log(f'检测到 IP 地址输入: {target}')
                hostname = reverse_dns_lookup(target)
                if hostname:
                    base_domain = extract_root_domain(hostname)
                    log(f'反向 DNS: {target} -> {hostname} -> {base_domain}')
                else:
                    print(f'[!] 无法通过反向 DNS 解析 IP: {target}，跳过')
                    continue
                main_ip = target
                main_hostname = hostname
            else:
                base_domain = target.lower().rstrip('.')
                ips = resolve_a_record(base_domain)
                if ips:
                    main_ip = ips[0]
                    log(f'主域名 {base_domain} -> {main_ip}')
                else:
                    print(f'[!] 无法解析域名: {base_domain}，跳过')
                    continue
                main_hostname = base_domain

            # 子域名枚举
            wordlist_path = None
            use_temp = False
            subdomains = []

            if not args.no_dns_brute:
                if args.wordlist:
                    wordlist_path = load_external_wordlist(args.wordlist)
                else:
                    wordlist_path = get_default_wordlist_path()
                    use_temp = True

                log('子域名枚举 (dns-brute)...')
                start = time.time()
                raw_results = run_dns_brute(base_domain, wordlist_path, args.timeout)
                elapsed = time.time() - start
                log(f'枚举耗时: {elapsed:.1f}s, 原始结果: {len(raw_results)} 条')

                subdomains = filter_results(
                    raw_results,
                    base_domain,
                    validate_dns=not args.no_validate,
                )
                log(f'有效子域名: {len(subdomains)} 个')
                print()

                if use_temp and wordlist_path and os.path.exists(wordlist_path):
                    try:
                        os.remove(wordlist_path)
                    except OSError:
                        pass
                    wordlist_path = None
            else:
                log('跳过子域名枚举 (--no-dns-brute)')
                print()

            # 构建主机列表
            hosts = [{'hostname': main_hostname, 'ip': main_ip}]
            for sub in subdomains:
                hosts.append({'hostname': sub['hostname'], 'ip': sub['ip']})

            # 端口扫描
            log(f'端口扫描 + 服务检测 ({len(hosts)} 个主机)...')
            start = time.time()
            scan_targets = [h['ip'] for h in hosts]
            scan_results = run_port_scan(scan_targets, timeout=args.timeout)
            elapsed = time.time() - start
            log(f'端口扫描耗时: {elapsed:.1f}s')

            for host in hosts:
                ip = host['ip']
                if ip in scan_results:
                    host['ports'] = scan_results[ip]['ports']
                else:
                    host['ports'] = []
            print()

            # Web 探测
            if not args.no_web:
                log(f'Web 站点探测...')
                for host in hosts:
                    open_ports = [p['port'] for p in host.get('ports', [])]
                    host['web_info'] = probe_web_for_host(
                        host['hostname'], host['ip'], open_ports,
                    )
                print()
            else:
                for host in hosts:
                    host['web_info'] = []
                log('跳过 Web 探测 (--no-web)')
                print()

            display_results(hosts, base_domain)
            all_hosts.extend(hosts)
            domain_labels.append(main_hostname)

        # 保存结果
        if not all_hosts:
            print('[!] 所有目标均未获取到结果')
            sys.exit(1)

        label = '+'.join(domain_labels[:3])
        if len(domain_labels) > 3:
            label += f'+{len(domain_labels)-3}more'

        from datetime import datetime
        date_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        fmt = args.format
        output_path = args.output if args.output else f'{label}_{date_str}.{fmt}'
        try:
            save_results(all_hosts, output_path, fmt, label)
            print(f'\n[*] 结果已保存到: {output_path}')
        except OSError as e:
            print(f'\n[!] 保存文件失败: {e}')

    except RuntimeError as e:
        print(f'\n[!] 扫描错误: {e}')
        sys.exit(1)
    except KeyboardInterrupt:
        print('\n[!] 用户中断')
        sys.exit(130)


if __name__ == '__main__':
    main()
