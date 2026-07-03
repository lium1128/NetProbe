"""Favicon 哈希指纹 — FOFA icon_hash 同款算法。

下载 /favicon.ico → base64 编码 → mmh3.hash()，返回与 FOFA icon_hash 一致的值，
可用于跨资产关联（相同产品/框架常共享相同 favicon）。
"""

import base64

import mmh3
import requests

REQUEST_TIMEOUT = 8


def compute_favicon_hash(url: str, timeout: int = REQUEST_TIMEOUT) -> str:
    """计算站点 favicon 的 mmh3 哈希（FOFA icon_hash 同款算法）。

    参数:
        url: 站点 URL（如 https://example.com），自动拼接 /favicon.ico
    返回: 哈希字符串，下载失败返回空串。
    """
    # 规范化：取 scheme://host[:port] + /favicon.ico
    base_url = _normalize_base(url)
    if not base_url:
        return ''

    favicon_url = base_url.rstrip('/') + '/favicon.ico'
    try:
        resp = requests.get(
            favicon_url, timeout=timeout,
            verify=False, allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'},
        )
        if resp.status_code != 200 or not resp.content:
            return ''
        # FOFA 算法: base64 编码后再 mmh3.hash
        b64 = base64.encodebytes(resp.content)
        return str(mmh3.hash(b64))
    except (requests.RequestException, ValueError, OSError):
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
