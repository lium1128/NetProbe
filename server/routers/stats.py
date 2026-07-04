"""统计 API — 仪表盘全局概览。"""

from fastapi import APIRouter, HTTPException

from ..services.stats_service import get_overview_stats, get_asset_detail

router = APIRouter(tags=["stats"])


@router.get("/stats")
def get_stats():
    """返回仪表盘全局概览统计。"""
    return get_overview_stats()


@router.get("/stats/asset")
def get_asset_stats(hostname: str, ip: str):
    """返回单个资产的完整详情（资产清单展开行）。"""
    result = get_asset_detail(hostname, ip)
    if result is None:
        raise HTTPException(404, "asset not found")
    return result
