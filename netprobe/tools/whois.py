"""WHOIS / RDAP 查询 — 域名注册信息 + IP 的 ASN/网段。

域名 WHOIS 走 RDAP（IETF 标准、公开免费、无需 key）:
  https://rdap.org/domain/{domain}
IP 的 ASN/网段走 ipwhois 库的 RDAP lookup。

参考 fofa.py/hunter.py 模式: 单一 query 函数 + 异常容错返回空。
"""

import json

import requests

RDAP_DOMAIN_URL = 'https://rdap.org/domain/{}'
REQUEST_TIMEOUT = 20


def query_rdap_domain(domain: str, timeout: int = 20) -> dict:
    """查询域名 RDAP 注册信息。

    返回: {'registrar', 'status', 'creation_date', 'expiration_date',
           'updated_date', 'nameservers', 'domain_name'} 或空 dict。
    """
    try:
        url = RDAP_DOMAIN_URL.format(domain)
        resp = requests.get(url, timeout=timeout, headers={
            'Accept': 'application/rdap+json',
            'User-Agent': 'NetProbe/3.0',
        })
        if resp.status_code != 200:
            return {}

        data = resp.json()
        result = {
            'domain_name': domain,
            'registrar': _extract_registrar(data),
            'status': data.get('status', []),
            'nameservers': _extract_nameservers(data),
        }

        # 日期事件（registration/expiration/last changed）
        for event in data.get('events', []):
            action = event.get('eventAction', '')
            date = event.get('eventDate', '')
            if action == 'registration':
                result['creation_date'] = date
            elif action == 'expiration':
                result['expiration_date'] = date
            elif action == 'last changed':
                result['updated_date'] = date

        return result

    except (requests.RequestException, json.JSONDecodeError, ValueError):
        return {}


def query_rdap_ip(ip: str, timeout: int = 20) -> dict:
    """查询 IP 的 ASN / 网段信息（via ipwhois RDAP）。

    返回: {'ip', 'asn', 'asn_cidr', 'asn_description', 'asn_country_code',
           'asn_registry', 'network'} 或空 dict。
    """
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        lookup = obj.lookup_rdap(rate_limit_timeout=timeout)

        network = lookup.get('network', {}) or {}
        return {
            'ip': ip,
            'asn': lookup.get('asn') or '',
            'asn_cidr': lookup.get('asn_cidr') or '',
            'asn_description': (lookup.get('asn_description') or '').strip(),
            'asn_country_code': lookup.get('asn_country_code') or '',
            'asn_registry': lookup.get('asn_registry') or '',
            'network': {
                'cidr': network.get('cidr') or '',
                'name': network.get('name') or '',
                'handle': network.get('handle') or '',
            },
        }

    except Exception:
        return {}


def _extract_registrar(data: dict) -> str:
    """从 RDAP entities 里提取 registrar（role=registrar 的实体名）。"""
    for entity in data.get('entities', []):
        roles = entity.get('roles', [])
        if 'registrar' in roles:
            vcard = entity.get('vcardArray', [])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == 'fn':
                        return item[3]
            return entity.get('handle', '')
    return ''


def _extract_nameservers(data: dict) -> list[str]:
    """提取 NS 主机名列表。"""
    nameservers = data.get('nameservers', []) or []
    result = []
    for ns in nameservers:
        ldh = ns.get('ldhName') or ns.get('unicodeName') or ''
        if ldh:
            result.append(ldh.lower().rstrip('.'))
    return result
