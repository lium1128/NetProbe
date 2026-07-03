import socket

import dns.resolver
import dns.reversename
import dns.query
import dns.zone
import dns.rdatatype


def reverse_dns_lookup(ip_address: str) -> str | None:
    """反向 DNS 查询，返回主机名或 None。"""
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        if answers:
            hostname = str(answers[0]).rstrip('.')
            return hostname
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.exception.DNSException):
        pass
    return None


def resolve_a_record(hostname: str) -> list[str]:
    """查询 A 记录，返回 IP 列表。解析失败返回空列表。"""
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        return [rdata.address for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers,
            dns.exception.DNSException):
        pass
    # dnspython 失败时，用系统 DNS fallback
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        ips = list({r[4][0] for r in results})
        return ips
    except socket.gaierror:
        return []


def is_subdomain_of(hostname: str, base_domain: str) -> bool:
    """判断 hostname 是否属于 base_domain 或其子域名。"""
    h = hostname.rstrip('.').lower()
    b = base_domain.rstrip('.').lower()
    return h == b or h.endswith('.' + b)


def filter_results(
    results: list[dict],
    base_domain: str,
    validate_dns: bool = True,
) -> list[dict]:
    """过滤结果：后缀匹配 + 可选的 DNS 解析验证。"""
    filtered = []
    seen = set()
    for item in results:
        hostname = item.get('hostname', '').strip()
        ip = item.get('ip', '').strip()
        if not hostname or hostname in seen:
            continue
        if not is_subdomain_of(hostname, base_domain):
            continue
        if validate_dns:
            ips = resolve_a_record(hostname)
            if not ips:
                continue
            # 用实际解析到的 IP 替换/补充
            if not ip:
                ip = ips[0]
        seen.add(hostname)
        filtered.append({'hostname': hostname, 'ip': ip})
    return filtered


# ── DNS 多记录查询 + 区域传送（v2.3）────────────────────────────

def resolve_dns_records(name: str, rtype: str = 'CNAME') -> list[str]:
    """通用 DNS 记录查询，支持 CNAME/MX/NS/TXT/SOA 等任意类型。

    返回字符串列表（rdata 的文本表示）。失败返回空列表。
    """
    try:
        answers = dns.resolver.resolve(name, rtype)
        records = []
        for rdata in answers:
            records.append(str(rdata).rstrip('.'))
        return records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.Timeout, dns.resolver.NoNameservers,
            dns.exception.DNSException):
        return []


def get_nameservers(domain: str) -> list[str]:
    """查询域名的权威 NS 记录，返回 NS 主机名列表。"""
    return resolve_dns_records(domain, 'NS')


def try_zone_transfer(domain: str, timeout: int = 10) -> dict | None:
    """尝试 DNS 区域传送（AXFR）获取完整 zone 记录。

    流程: 查 NS → 解析 NS 的 IP → 对每个 NS 尝试 AXFR。
    绝大多数域名会拒绝 AXFR（返回 None），这是正常的。
    成功返回 {'ns', 'records': [{'name','type','value'}], 'count'}。
    """
    ns_list = get_nameservers(domain)
    if not ns_list:
        return None

    for ns_hostname in ns_list:
        # 解析 NS 的 IP（AXFR 需要连 IP）
        ns_ips = resolve_a_record(ns_hostname)
        if not ns_ips:
            continue

        for ns_ip in ns_ips:
            try:
                xfr = dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout)
                zone = dns.zone.from_xfr(xfr)
                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        rtype = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            records.append({
                                'name': str(name) if str(name) != '@' else domain,
                                'type': rtype,
                                'value': str(rdata).rstrip('.'),
                            })
                if records:
                    return {
                        'ns': ns_hostname,
                        'records': records,
                        'count': len(records),
                    }
            except (dns.exception.DNSException, OSError, TimeoutError):
                continue

    return None
