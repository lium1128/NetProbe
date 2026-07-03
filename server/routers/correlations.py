"""资产关联 API — 跨扫描按维度聚合发现共基础设施的资产簇。"""

from fastapi import APIRouter

from ..services.correlation_service import list_correlations, build_graph

router = APIRouter(tags=["correlations"])


@router.get("/correlations")
def get_correlations(type: str | None = None):
    """返回关联簇。可选 ?type=ip|cert|tech|service 筛选单一类型。"""
    return list_correlations(type)


@router.get("/correlations/graph")
def get_correlation_graph():
    """返回关系图谱数据（ECharts 力导向图 nodes+links）。"""
    return build_graph()


@router.get("/correlations/{corr_type}")
def get_correlations_by_type(corr_type: str):
    """按类型返回单一关联簇列表。"""
    return list_correlations(corr_type)
