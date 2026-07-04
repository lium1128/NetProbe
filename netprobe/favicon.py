"""Favicon 哈希指纹 — FOFA icon_hash 同款算法。

下载 favicon → base64 编码 → mmh3.hash()，返回与 FOFA icon_hash 一致的值，
可用于跨资产关联（相同产品/框架常共享相同 favicon）。

优先从 HTML 的 <link rel="icon"> 解析自定义 favicon 路径，回退 /favicon.ico。
"""

import base64
import re
from urllib.parse import urljoin

import mmh3
import requests

REQUEST_TIMEOUT = 8

# 匹配 <link rel="icon" ... href="..."> / <link rel="shortcut icon" ...>
# 兼容 rel 在 href 前后、单双引号、属性顺序多变的情况
_LINK_ICON_RE = re.compile(
    r'<link\b[^>]*\brel=["\'](?:shortcut\s+icon|icon|apple-touch-icon|mask-icon)["\'][^>]*>',
    re.IGNORECASE,
)
_HREF_RE = re.compile(r'\bhref=["\']([^"\']+)["\']', re.IGNORECASE)


def compute_favicon_hash(url: str, html: str = '', timeout: int = REQUEST_TIMEOUT) -> str:
    """计算站点 favicon 的 mmh3 哈希（FOFA icon_hash 同款算法）。

    参数:
        url: 站点 URL（如 https://example.com）
        html: 首页 HTML（可选，用于解析 <link rel="icon"> 自定义路径）
    返回: 哈希字符串，下载失败返回空串。
    """
    base_url = _normalize_base(url)
    if not base_url:
        return ''

    # 优先解析 HTML 里声明的 favicon 路径，回退默认 /favicon.ico
    favicon_url = _extract_favicon_url(html, base_url) or (base_url.rstrip('/') + '/favicon.ico')
    try:
        resp = requests.get(
            favicon_url, timeout=timeout,
            verify=False, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'},
        )
        if resp.status_code != 200 or not resp.content:
            # 自定义路径失败时，回退默认 /favicon.ico 再试一次
            if not favicon_url.endswith('/favicon.ico'):
                resp = requests.get(
                    base_url.rstrip('/') + '/favicon.ico', timeout=timeout,
                    verify=False, allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0'},
                )
                if resp.status_code != 200 or not resp.content:
                    return ''
            else:
                return ''
        # FOFA 算法: base64 编码后再 mmh3.hash
        b64 = base64.encodebytes(resp.content)
        return str(mmh3.hash(b64))
    except (requests.RequestException, ValueError, OSError):
        return ''


def _extract_favicon_url(html: str, base_url: str) -> str:
    """从 HTML 解析 <link rel="icon"> 的 href，返回绝对 URL 或空串。"""
    if not html:
        return ''
    for link_tag in _LINK_ICON_RE.findall(html):
        href_match = _HREF_RE.search(link_tag)
        if href_match:
            href = href_match.group(1).strip()
            if href and not href.startswith('data:'):
                # 相对路径 → 绝对 URL
                return urljoin(base_url, href)
    return ''


def _normalize_base(url: str) -> str:
    """从 URL 提取 scheme://host[:port] 部分。"""
    if not url:
        return ''
    # 已有 scheme
    if '://' in url:
        parts = url.split('/', 3)
        return parts[0] + '//' + parts[2] if len(parts) >= 3 else url
    return ''
