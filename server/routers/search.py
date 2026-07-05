"""反向搜索 API — 给定 IP 反查所有关联域名、证书、端口、技术栈。"""

from fastapi import APIRouter, HTTPException

from ..services.asset_service import get_asset_by_ip
from ..services.correlation_service import search_by_favicon_external

router = APIRouter(tags=["search"])


def _load_github_token() -> str:
    """从 settings.json 的 api_keys.github_token 读取 GitHub Token。

    读取失败或未配置时返回空字符串（由调用方决定是否降级处理）。
    """
    try:
        from .settings import _load as _load_settings  # type: ignore
        data = _load_settings()
        return (data.get("api_keys", {}) or {}).get("github_token", "") or ""
    except Exception:
        return ""


@router.get("/search/reverse")
def reverse_search(ip: str):
    """反向搜索：给定 IP，返回该 IP 在所有扫描中的关联资产。

    参数: ?ip=1.2.3.4
    """
    if not ip or not ip.strip():
        raise HTTPException(400, "query param 'ip' is required")
    result = get_asset_by_ip(ip.strip())
    if result is None:
        raise HTTPException(404, "no assets found for this IP")
    return result


@router.get("/search/favicon")
def search_favicon(hash: str, source: str = "fofa"):
    """用 favicon hash 对接外部空间搜索引擎（FOFA/Shodan）反查同源资产。

    参数:
      hash:   mmh3 favicon hash（FOFA icon_hash 同款）
      source: 'fofa'（默认）或 'shodan'

    返回: {source, query, count, results}。无 API key 时 count=0。
    """
    if not hash or not hash.strip():
        raise HTTPException(400, "query param 'hash' is required")
    src = (source or "fofa").strip().lower()
    if src not in ("fofa", "shodan"):
        raise HTTPException(400, "source must be 'fofa' or 'shodan'")
    return search_by_favicon_external(hash.strip(), src)


@router.get("/search/github")
def search_github(q: str):
    """GitHub 代码泄露搜索：搜索包含关键词+敏感词（password/secret/...）的公开代码。

    参数: ?q=公司名/域名/产品名

    返回: {query, count, results: [{repo, file, url, keyword}, ...]}
    无 GitHub Token（settings.json 的 api_keys.github_token 或 GITHUB_TOKEN 环境变量）时
    返回 count=0 并带提示信息。
    """
    if not q or not q.strip():
        raise HTTPException(400, "query param 'q' is required")
    keyword = q.strip()

    # 优先用 settings.json 中的 token，回退到环境变量（由 search_github_leaks 内部处理）
    token = _load_github_token()

    try:
        # netprobe.github_leak 可独立导入，不依赖 server 数据库
        from netprobe.github_leak import search_github_leaks
        results = search_github_leaks(keyword, token)
    except Exception as e:
        raise HTTPException(500, f"github search failed: {e}")

    return {
        "query": keyword,
        "count": len(results),
        "results": results,
        "note": "" if results or token else (
            "未配置 GitHub Token，搜索被跳过。请在设置中填写 api_keys.github_token "
            "或设置 GITHUB_TOKEN 环境变量。"
        ),
    }
