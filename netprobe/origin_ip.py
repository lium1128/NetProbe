"""CDN 真实 IP 发现 — 多源聚合发现 CDN/WAF 背后的源站 IP。

组合多种被动情报方法，规避 CDN 直接解析的误导：
  1. crt.sh 证书透明度日志的 SAN（含 IP 关联域名）
  2. 历史 DNS 记录（ViewDNS / SecurityTrails，需 key 则用，无则跳过）
  3. 子域名直接 A 记录解析（绕 CDN，扫子域 A 记录找非 CDN IP）
  4. favicon hash → FOFA/Shodan 反查（复用现有，需 key）

容错策略：所有外部 API 失败返回空候选列表，不抛出。
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .dns_utils import resolve_a_record
from .tools.crtsh import query_crtsh

REQUEST_TIMEOUT = 15
_MAX_WORKERS = 8

# ── CDN/云服务商常见 IP 段前缀（粗筛可剔除的回源目标）──
# 仅做粗粒度过滤；命中这些前缀的候选会降权而非完全剔除（避免误删真实源站）
_CDN_IP_PREFIXES = (
    # Cloudflare
    '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '172.64.',
    '172.67.', '162.159.', '188.114.', '173.245.', '103.21.', '103.22.',
    # CloudFront
    '13.224.', '13.225.', '13.32.', '13.33.', '99.84.', '205.251.',
    # Akamai
    '23.', '72.', '184.', '88.221.',
    # 阿里云 CDN / 腾讯云 CDN（粗筛）
    '47.246.', '120.241.', '203.107.',
)


def _is_cdn_ip(ip: str) -> bool:
    """粗略判断 IP 是否属于 CDN/云加速段（用于过滤候选，非精确）。"""
    if not ip:
        return False
    return any(ip.startswith(prefix) for prefix in _CDN_IP_PREFIXES)


def _is_valid_public_ip(ip: str) -> bool:
    """判断是否为合法公网 IPv4（剔除空/内网/格式错误）。"""
    if not ip or not isinstance(ip, str):
        return False
    try:
        socket.inet_aton(ip)
    except OSError:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    first = int(parts[0])
    # 剔除内网/环回/组播
    if first in (10, 127) or first == 0:
        return False
    if first == 172 and 16 <= int(parts[1]) <= 31:
        return False
    if first == 192 and parts[1] == '168':
        return False
    return True


# ── 方法 1: crt.sh 证书 SAN → 解析子域 IP ─────────────────────

def _find_via_crtsh(domain: str) -> list[dict]:
    """通过 crt.sh 证书透明度日志获取子域名，再解析非 CDN 的 A 记录。

    crt.sh 返回的是 hostname，需进一步解析为 IP。
    """
    candidates: list[dict] = []
    try:
        subdomains = query_crtsh(domain, timeout=REQUEST_TIMEOUT)
    except Exception:
        subdomains = []

    hostnames = list({s.get('hostname', '') for s in subdomains if s.get('hostname')})
    if not hostnames:
        return candidates

    def _resolve_one(name):
        try:
            ips = resolve_a_record(name)
            return name, ips
        except Exception:
            return name, []

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [pool.submit(_resolve_one, name) for name in hostnames]
        for future in as_completed(futures):
            name, ips = future.result()
            for ip in (ips or []):
                if _is_valid_public_ip(ip) and not _is_cdn_ip(ip):
                    candidates.append({
                        'ip': ip, 'source': 'crt.sh',
                        'evidence': f'证书透明度子域 {name} 的 A 记录',
                    })
    return candidates


# ── 方法 2: 历史 DNS（ViewDNS，无需 key）─────────────────────

def _find_via_viewdns_history(domain: str) -> list[dict]:
    """通过 ViewDNS 历史记录 API 获取域名历史解析 IP（无需 key）。"""
    candidates: list[dict] = []
    try:
        resp = requests.get(
            'https://api.viewdns.info/iphistory/',
            params={'domain': domain, 'output': 'json'},
            timeout=REQUEST_TIMEOUT, verify=False,
        )
        if resp.status_code != 200:
            return candidates
        data = resp.json()
    except (requests.RequestException, ValueError):
        return candidates

    for rec in data.get('response', {}).get('records', []):
        ip = (rec.get('ip') or '').strip()
        if ip and _is_valid_public_ip(ip) and not _is_cdn_ip(ip):
            candidates.append({
                'ip': ip, 'source': 'viewdns_history',
                'evidence': f'历史 DNS 记录 ({rec.get("lastresolved", "")})',
            })
    return candidates


# ── 方法 3: 子域直接 A 记录解析（绕 CDN）──────────────────────

def _find_via_subdomains(hosts: list[dict]) -> list[dict]:
    """对扫描结果里所有子域名做 A 记录解析，挑出非 CDN 的 IP。"""
    candidates: list[dict] = []
    hostnames = list({
        h.get('hostname', '') for h in hosts
        if h.get('hostname') and h.get('ip')
    })
    if not hostnames:
        return candidates

    def _resolve_one(name):
        try:
            ips = resolve_a_record(name)
            return name, ips
        except Exception:
            return name, []

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = [pool.submit(_resolve_one, name) for name in hostnames]
        for future in as_completed(futures):
            name, ips = future.result()
            for ip in (ips or []):
                if _is_valid_public_ip(ip) and not _is_cdn_ip(ip):
                    candidates.append({
                        'ip': ip, 'source': 'subdomain_resolve',
                        'evidence': f'子域 {name} 直接 A 记录（非 CDN）',
                    })
    return candidates


# ── 方法 4: favicon hash → FOFA/Shodan 反查 ───────────────────

def _find_via_favicon(favicon_hash: str) -> list[dict]:
    """用 favicon hash 调 FOFA/Shodan 反查可能暴露真实 IP 的资产。需 key。

    复用 correlation_service.search_by_favicon_external；为避免 server 层耦合，
    这里用延迟导入（仅在 server 上下文可用）。
    """
    candidates: list[dict] = []
    if not favicon_hash:
        return candidates
    try:
        from server.services.correlation_service import search_by_favicon_external
    except Exception:
        return candidates

    for source in ('fofa', 'shodan'):
        try:
            res = search_by_favicon_external(favicon_hash, source)
        except Exception:
            continue
        for item in res.get('results', []):
            ip = (item.get('ip') or '').strip()
            if ip and _is_valid_public_ip(ip) and not _is_cdn_ip(ip):
                candidates.append({
                    'ip': ip, 'source': f'favicon_{source}',
                    'evidence': f'favicon hash {favicon_hash} 反查',
                })
    return candidates


# ── 聚合入口 ──────────────────────────────────────────────────

def find_origin_ips(domain: str, favicon_hash: str = '',
                    hosts: list[dict] | None = None) -> dict:
    """聚合多源候选 IP，发现 CDN 背后的真实源站 IP。

    参数:
        domain:       目标根域名
        favicon_hash: 站点 favicon hash（可选，用于 FOFA/Shodan 反查）
        hosts:        扫描结果 hosts（可选，用于子域解析法）

    返回: {
        'candidates': [{'ip', 'source', 'evidence'}, ...],
        'confidence': 'high' | 'medium' | 'low',
    }
    confidence 规则:
      - 多源（≥2）交叉验证同一 IP → high
      - 单源但非 CDN → medium
      - 仅 CDN 段或无候选 → low
    """
    candidates: list[dict] = []

    # 并发跑各方法（任一失败返回空，不影响其他）
    methods = [
        ('crt.sh', lambda: _find_via_crtsh(domain)),
        ('viewdns', lambda: _find_via_viewdns_history(domain)),
    ]
    if hosts:
        methods.append(('subdomain', lambda: _find_via_subdomains(hosts)))
    if favicon_hash:
        methods.append(('favicon', lambda: _find_via_favicon(favicon_hash)))

    with ThreadPoolExecutor(max_workers=len(methods)) as pool:
        futures = {pool.submit(fn): name for name, fn in methods}
        for future in as_completed(futures):
            try:
                candidates.extend(future.result())
            except Exception:
                continue

    # 聚合：按 IP 统计来源数，交叉验证
    ip_sources: dict[str, set[str]] = {}
    ip_evidence: dict[str, list[str]] = {}
    for c in candidates:
        ip = c['ip']
        ip_sources.setdefault(ip, set()).add(c['source'])
        ip_evidence.setdefault(ip, []).append(c['evidence'])

    # 合并候选：按来源数降序
    merged: list[dict] = []
    for ip, sources in sorted(ip_sources.items(), key=lambda x: -len(x[1])):
        merged.append({
            'ip': ip,
            'source': ','.join(sorted(sources)),
            'source_count': len(sources),
            'evidence': ' | '.join(ip_evidence[ip][:3]),
        })

    # 置信度：任一 IP 被 ≥2 源验证 → high
    if merged and any(c['source_count'] >= 2 for c in merged):
        confidence = 'high'
    elif merged:
        confidence = 'medium'
    else:
        confidence = 'low'

    return {'candidates': merged, 'confidence': confidence}


def find_origin_for_hosts(hosts: list[dict]) -> None:
    """对所有「经过 CDN」的站点做真实 IP 发现，结果存 host['_origin_ips']。

    判定 CDN：web_info 中任一记录的 cdn 字段非空即视为该 host 受 CDN 保护。
    """
    # 按 root domain 聚合，避免对同一域名重复查询
    resolved: dict[str, dict] = {}

    for host in hosts:
        host['_origin_ips'] = []
        is_cdn = any(w.get('cdn') for w in host.get('web_info', []))
        if not is_cdn:
            continue

        hostname = host.get('hostname', '')
        if not hostname:
            continue
        # 提取根域名作为查询键
        try:
            from .utils import extract_root_domain
            root = extract_root_domain(hostname)
        except Exception:
            root = hostname
        if not root:
            continue

        if root not in resolved:
            try:
                # 取首个 favicon hash（若有）
                favicon_hash = ''
                for w in host.get('web_info', []):
                    if w.get('favicon_hash'):
                        favicon_hash = w['favicon_hash']
                        break
                resolved[root] = find_origin_ips(root, favicon_hash, hosts)
            except Exception:
                resolved[root] = {'candidates': [], 'confidence': 'low'}

        host['_origin_ips'] = resolved[root]
