"""目录/文件爆破 — 基于词表发现隐藏路径。

复用 sensitive_probe 的并发框架，但使用内置动态词表。
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT = 5
_MAX_WORKERS = 12

# 视为存在的状态码（403 表示受保护但仍是有价值的发现）
_HIT_STATUS = {200, 301, 302, 401, 403}

# 默认扩展名：'' 表示无后缀（探测目录/无后缀文件）
_DEFAULT_EXTENSIONS = ['', '.php', '.bak', '.txt']

# ── 内置目录词表（约 80 条，参考 dirsearch 常见字典） ──
COMMON_DIRS = [
    # 管理后台 / 登录
    'admin', 'administrator', 'admin.php', 'login', 'manage', 'manager',
    'wp-admin', 'wp-login.php', 'backend', 'dashboard', 'cp', 'console',
    # API / 接口
    'api', 'api/v1', 'api/v2', 'rest', 'graphql', 'swagger', 'swagger-ui',
    'swagger-ui.html', 'openapi.json', 'swagger.json', 'api-docs',
    # 配置 / 备份
    'config', 'configuration', 'conf', 'backup', 'backups', 'bak', 'old',
    'db', 'database', 'sql', 'dump', 'data', 'archive', 'temp', 'tmp',
    # 版本控制 / 泄露
    '.git', '.git/config', '.env', '.svn', '.svn/entries', '.hg', '.bzr',
    'CVS', '.DS_Store', 'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
    # 测试 / 调试
    'test', 'tests', 'testing', 'debug', 'debugger', 'dev', 'development',
    'staging', 'demo', 'sandbox', 'phpinfo.php', 'info.php', 'test.php',
    # 部署 / 运维
    'actuator', 'actuator/health', 'metrics', 'health', 'status', 'monitor',
    'jmx-console', 'jenkins', 'manager/html', 'solr', 'elasticsearch',
    # 文档 / 帮助
    'docs', 'documentation', 'doc', 'help', 'readme', 'README.md', 'CHANGELOG',
    # 上传 / 静态资源
    'upload', 'uploads', 'files', 'file', 'images', 'img', 'static', 'assets',
    'media', 'public', 'resources',
    # 框架 / 系统
    'phpmyadmin', 'pma', 'mysql', 'adminer', 'wp-content', 'wp-includes',
    'cgi-bin', 'scripts', 'bin', 'logs', 'log', 'cache',
    # 其他常见
    'old', 'new', 'src', 'dist', 'build', 'vendor', 'node_modules',
    'server-status', 'server-info', '.well-known', 'graphql',
]

# 去重保序（词表里个别重复项兜底）
_seen: set = set()
COMMON_DIRS = [x for x in COMMON_DIRS if not (x in _seen or _seen.add(x))]


def _check_path(base: str, word: str, extension: str) -> dict | None:
    """探测单个 path，命中返回 {path, status, size}，否则 None。

    优先 HEAD（轻量），失败回退 GET。
    """
    path = '/' + word + extension
    url = base + path
    try:
        resp = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=False,
        )
        # 很多服务器对 HEAD 返回 405/501，回退到 GET
        if resp.status_code in (405, 501):
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
    except requests.RequestException:
        # HEAD 异常也尝试 GET 兜底
        try:
            resp = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
        except requests.RequestException:
            return None

    if resp.status_code not in _HIT_STATUS:
        return None

    # 取响应体大小：HEAD 用 Content-Length 声明值，GET 回退用实际长度
    size = 0
    try:
        size = int(resp.headers.get('Content-Length', 0) or 0)
    except (ValueError, TypeError):
        size = 0
    if size == 0:
        try:
            size = len(resp.content)
        except Exception:
            size = 0

    return {
        'path': path,
        'status': resp.status_code,
        'size': size,
    }


def brute_directories(
    base_url: str,
    wordlist: list[str] | None = None,
    extensions: list[str] | None = None,
) -> list[dict]:
    """对 base_url 进行目录/文件爆破。

    参数:
        base_url: 基础 URL（如 https://example.com）
        wordlist: 自定义词表，默认用 COMMON_DIRS
        extensions: 扩展名列表，默认 ['', '.php', '.bak', '.txt']

    返回: [{'path', 'status', 'size'}, ...]
    """
    words = wordlist if wordlist is not None else COMMON_DIRS
    exts = extensions if extensions is not None else _DEFAULT_EXTENSIONS
    base = base_url.rstrip('/')

    results: list[dict] = []
    # 构造所有 (word, ext) 组合
    targets = [(w, e) for w in words for e in exts]

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(_check_path, base, w, e): (w, e) for w, e in targets}
        for future in as_completed(futures):
            try:
                result = future.result()
            except Exception:
                result = None
            if result:
                results.append(result)

    # 按 path 排序，便于阅读
    results.sort(key=lambda r: r['path'])
    return results


def brute_for_hosts(hosts: list[dict]) -> None:
    """对所有主机的 Web 站点批量进行目录爆破。

    结果写入 host['_dir_findings']（[{path, status, size}, ...]）。
    """
    for host in hosts:
        web_info = host.get('web_info', [])
        findings: list[dict] = []
        seen_origins: set[str] = set()

        for w in web_info:
            url = w.get('url', '')
            if not url:
                continue
            # 每个 origin 只爆破一次
            parsed = urlparse(url)
            origin = f'{parsed.scheme}://{parsed.netloc}'
            if origin in seen_origins:
                continue
            seen_origins.add(origin)

            try:
                found = brute_directories(origin)
            except Exception:
                found = []
            if found:
                findings.extend(found)

        # 按 path 去重（不同扩展名可能重复，保留首个）
        deduped: list[dict] = []
        seen_paths: set[str] = set()
        for f in findings:
            if f['path'] not in seen_paths:
                seen_paths.add(f['path'])
                deduped.append(f)

        host['_dir_findings'] = deduped
