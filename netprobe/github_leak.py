"""GitHub 代码泄露监控 — 调 GitHub Code Search API 搜索公司名+敏感词组合。

用于发现仓库中泄露的内部域名 / 密码 / 密钥。需要 GitHub Personal Access Token
（无 token 受严重 rate limit，仅匿名少量请求可用），Token 从 settings.json 的
api_keys.github_token 或环境变量 GITHUB_TOKEN 读取。

容错策略：无 token / 速率限制 / 网络异常均返回空列表并打印提示，不抛出。
"""

from __future__ import annotations

import os

import requests

GITHUB_CODE_SEARCH_API = 'https://api.github.com/search/code'
REQUEST_TIMEOUT = 15

# 敏感词组合：与关键词配对搜索，提高命中率
_SENSITIVE_TERMS = ('password', 'secret', 'apikey', 'token', 'private_key')

# 单次请求返回条数上限（GitHub Code Search 上限 1000 条，per_page 上限 100）
_PER_PAGE = 20


def _load_github_token(explicit: str = '') -> str:
    """获取 GitHub Token：优先显式传入 > 环境变量。"""
    if explicit:
        return explicit.strip()
    return os.environ.get('GITHUB_TOKEN', '').strip()


def search_github_leaks(keyword: str, github_token: str = '') -> list[dict]:
    """搜索 GitHub 上包含 keyword+敏感词 的代码泄露。

    参数:
        keyword:     关键词（公司名/域名/产品名）
        github_token: GitHub PAT（为空则尝试环境变量；仍为空则返回空列表）

    返回: [{'repo', 'file', 'url', 'keyword'}, ...]（去重，按 repo+file）
    """
    if not keyword or not keyword.strip():
        return []
    keyword = keyword.strip()
    token = _load_github_token(github_token)
    if not token:
        print('[github_leak] 未配置 GitHub Token，跳过搜索（设置 GITHUB_TOKEN 环境变量或 '
              'settings.json 的 api_keys.github_token）')
        return []

    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28',
    }

    results: list[dict] = []
    seen: set[str] = set()

    for term in _SENSITIVE_TERMS:
        query = f'{keyword} {term}'
        params = {'q': query, 'per_page': _PER_PAGE}
        try:
            resp = requests.get(
                GITHUB_CODE_SEARCH_API, headers=headers, params=params,
                timeout=REQUEST_TIMEOUT, verify=False,
            )
        except requests.RequestException as e:
            print(f'[github_leak] 请求失败 ({query}): {e}')
            continue

        if resp.status_code == 403:
            # rate limit / 次级速率限制
            print(f'[github_leak] 触发速率限制（HTTP 403），停止后续查询')
            break
        if resp.status_code == 422:
            # 搜索语法不合法 / 关键词无效，跳过该 term
            continue
        if resp.status_code != 200:
            print(f'[github_leak] 查询返回 {resp.status_code}: {resp.text[:120]}')
            continue

        try:
            data = resp.json()
        except ValueError:
            continue

        for item in data.get('items', []):
            repo_obj = item.get('repository', {})
            repo_name = repo_obj.get('full_name', '')
            file_path = item.get('path', '')
            html_url = item.get('html_url', '')
            dedup_key = f'{repo_name}:{file_path}'
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            results.append({
                'repo': repo_name,
                'file': file_path,
                'url': html_url,
                'keyword': keyword,
            })

    return results


def search_github_for_domains(domains: list[str], token: str = '') -> list[dict]:
    """对多个域名批量搜索 GitHub 泄露（每个域名搜 password / secret 组合）。

    参数:
        domains: 域名列表
        token:   GitHub PAT（空则用环境变量）

    返回: 合并后的 [{'domain', 'repo', 'file', 'url', 'keyword'}, ...]
    """
    if not domains:
        return []

    all_results: list[dict] = []
    seen: set[str] = set()
    for domain in domains:
        domain = (domain or '').strip()
        if not domain:
            continue
        leaks = search_github_leaks(domain, token)
        for item in leaks:
            dedup = f'{domain}:{item.get("repo")}:{item.get("file")}'
            if dedup in seen:
                continue
            seen.add(dedup)
            all_results.append({
                'domain': domain,
                'repo': item.get('repo', ''),
                'file': item.get('file', ''),
                'url': item.get('url', ''),
                'keyword': item.get('keyword', ''),
            })
    return all_results
