"""Web 站点截图 — 复用 Playwright chromium 对探测到的站点截图。

仅在深度扫描模式（options['screenshot']=True）下触发，避免拖慢常规扫描。
截图存 data/screenshots/ 目录，返回相对路径供 DB 持久化。
"""

import os

# 截图存储目录
_SCREENSHOT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'data', 'screenshots'
)


def capture_screenshot(url: str, name_hint: str = '') -> str:
    """对指定 URL 截取全页截图。

    参数:
        url: 站点 URL（如 https://example.com）
        name_hint: 文件名提示（如 hostname_port）
    返回: 截图相对路径（相对 data/），失败返回空串。
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return ''

    os.makedirs(_SCREENSHOT_DIR, exist_ok=True)

    # 生成安全文件名
    safe_name = ''.join(c if c.isalnum() or c in '-_.' else '_' for c in (name_hint or url))[:60]
    filepath = os.path.join(_SCREENSHOT_DIR, f'{safe_name}.png')

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={'width': 1280, 'height': 800})
            page.goto(url, wait_until='domcontentloaded', timeout=15000)
            page.wait_for_timeout(1000)  # 等待渲染
            page.screenshot(path=filepath, full_page=True)
            browser.close()
        # 返回相对 data/ 的路径（供 Web 静态服务）
        return os.path.relpath(filepath, os.path.dirname(_SCREENSHOT_DIR))
    except Exception:
        return ''
