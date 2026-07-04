"""API 端点发现 — 从 Web 站点主动发现 REST/GraphQL/OpenAPI 端点。

复用 JS 分析的 js_findings 表（结果合并到 api_endpoints）。
"""

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests

_REQUEST_TIMEOUT = 8
_MAX_WORKERS = 6

# 第三方 CDN 域名，跳过分析以减少噪音（与 js_analyzer 保持一致）
_SKIP_DOMAINS = {
    'googleapis.com', 'google-analytics.com', 'googletagmanager.com',
    'cloudflare.com', 'cdn.jsdelivr.net', 'ajax.googleapis.com',
    'cdnjs.cloudflare.com', 'stackpath.bootstrapcdn.com',
    'cdn.bootcss.com', 'unpkg.com', 'polyfill.io', 'assets.adobedtm.com',
}

# ── HTML 链接提取规则 ──────────────────────────────────

_LINK_PATTERNS = [
    # <a href="...">
    re.compile(r'''<a[^>]+href=["']([^"']+)["']''', re.IGNORECASE),
    # <form action="...">
    re.compile(r'''<form[^>]+action=["']([^"']+)["']''', re.IGNORECASE),
]

# 命中以下片段的路径视为 API 端点
_API_HINTS = ('/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/graphql/')
# 显式的 API 路径前缀（开头匹配）
_API_PREFIXES = ('/api', '/v1', '/v2', '/v3', '/graphql', '/rest')

# 常见 API 文档/规范路径
_OPENAPI_PATHS = ['/openapi.json', '/swagger.json', '/swagger/v1/swagger.json',
                  '/api/openapi.json', '/api/swagger.json']
_DOC_PATHS = ['/api-docs', '/v1/api-docs', '/swagger-ui/', '/swagger-ui.html',
              '/swagger', '/api-docs/']
_GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql']

# GraphQL 内省查询
_GRAPHQL_INTROSPECT = {"query": "{__schema{types{name}}}"}


def _is_api_path(path: str) -> bool:
    """判断一个路径是否像 API 端点。"""
    if not path or path.startswith(('javascript:', 'mailto:', 'tel:', '#')):
        return False
    # 静态资源不算
    if path.endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                      '.ico', '.woff', '.woff2', '.html', '.htm', '.pdf')):
        return False
    low = path.lower()
    if any(hint in low for hint in _API_HINTS):
        return True
    return any(low.startswith(p) for p in _API_PREFIXES)


def _extract_links(html: str) -> list[str]:
    """从 HTML 中提取 <a href> 和 <form action> 链接。"""
    links = []
    for pattern in _LINK_PATTERNS:
        for m in pattern.finditer(html):
            href = m.group(1).strip()
            if href:
                links.append(href)
    return links


def _probe_openapi(base: str, spec_path: str) -> list[str]:
    """GET 一个 OpenAPI/Swagger 规范文件，解析其中的 paths 作为 API 端点。

    返回提取到的 path 列表（解析失败返回空列表）。
    """
    url = base + spec_path
    try:
        resp = requests.get(url, timeout=_REQUEST_TIMEOUT, verify=False)
    except requests.RequestException:
        return []
    if resp.status_code != 200:
        return []
    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict) or 'paths' not in data:
        return []
    paths = data.get('paths')
    if not isinstance(paths, dict):
        return []
    return [p for p in paths.keys() if isinstance(p, str)]


def _probe_graphql(base: str, gql_path: str) -> bool:
    """POST 内省查询探测 GraphQL 端点。

    200 响应且正文包含 __schema 即视为 GraphQL 端点。
    """
    url = base + gql_path
    try:
        resp = requests.post(
            url,
            json=_GRAPHQL_INTROSPECT,
            timeout=_REQUEST_TIMEOUT,
            verify=False,
            headers={'Content-Type': 'application/json'},
        )
    except requests.RequestException:
        return False
    if resp.status_code != 200:
        return False
    return '__schema' in resp.text


def discover_apis(url: str, html: str = '') -> list[str]:
    """从 Web 站点主动发现 API 端点。

    参数:
        url: 站点 URL（用于计算 origin 和拼接路径）
        html: 页面 HTML（为空时会自动抓取）

    返回: 发现的 API 端点路径列表（去重、排序）
    """
    if not url:
        return []
    parsed = urlparse(url)
    base = f'{parsed.scheme}://{parsed.netloc}'

    # 去掉第三方 CDN
    if any(d in parsed.netloc for d in _SKIP_DOMAINS):
        return []

    endpoints: set[str] = set()

    # ── 1. 解析 HTML 链接 ──
    if not html:
        try:
            resp = requests.get(url, timeout=_REQUEST_TIMEOUT, verify=False)
            if resp.status_code == 200:
                html = resp.text
        except requests.RequestException:
            html = ''

    if html:
        for href in _extract_links(html):
            if _is_api_path(href):
                # 解析为绝对路径再取 path
                full = urljoin(base, href)
                path = urlparse(full).path
                if path and path != '/':
                    endpoints.add(path)

    # ── 2. 探测 API 文档路径（GET）──
    doc_candidates = _OPENAPI_PATHS + _DOC_PATHS

    def _check_doc(path: str) -> list[str]:
        url_full = base + path
        try:
            resp = requests.get(url_full, timeout=_REQUEST_TIMEOUT, verify=False,
                                allow_redirects=True)
        except requests.RequestException:
            return []
        if resp.status_code != 200:
            return []
        # 命中文档即把该 path 本身记为端点
        found = [path]
        # 若返回 JSON 且含 paths，按 OpenAPI 解析
        ctype = resp.headers.get('Content-Type', '').lower()
        if 'json' in ctype or path.endswith('.json'):
            try:
                data = resp.json()
                if isinstance(data, dict) and isinstance(data.get('paths'), dict):
                    found.extend(p for p in data['paths'].keys() if isinstance(p, str))
            except (ValueError, json.JSONDecodeError):
                pass
        return found

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(_check_doc, p): p for p in doc_candidates}
        for future in as_completed(futures):
            try:
                for ep in future.result():
                    if ep:
                        endpoints.add(ep)
            except Exception:
                continue

    # ── 3. OpenAPI 规范独立探测（兜底，确保覆盖）──
    # （上面 _check_doc 已对 .json 做 OpenAPI 解析，这里不再重复）

    # ── 4. GraphQL 内省探测（POST）──
    for gql_path in _GRAPHQL_PATHS:
        if _probe_graphql(base, gql_path):
            endpoints.add(gql_path)
            break  # 命中一个即可

    return sorted(endpoints)


def discover_apis_for_hosts(hosts: list[dict]) -> None:
    """对所有主机的 Web 站点批量进行 API 端点发现。

    结果写入 host['_api_findings']（list[str]，格式同 js_findings 的 api_endpoints）。
    """
    for host in hosts:
        web_info = host.get('web_info', [])
        findings: list[str] = []
        seen_urls: set[str] = set()

        for w in web_info:
            url = w.get('url', '')
            if not url:
                continue
            # 每个 origin 只探测一次
            parsed = urlparse(url)
            origin = f'{parsed.scheme}://{parsed.netloc}'
            if origin in seen_urls:
                continue
            seen_urls.add(origin)

            try:
                eps = discover_apis(url)
            except Exception:
                eps = []
            if eps:
                findings.extend(eps)

        # 去重保序
        deduped: list[str] = []
        seen: set[str] = set()
        for ep in findings:
            if ep not in seen:
                seen.add(ep)
                deduped.append(ep)

        host['_api_findings'] = deduped
