"""扫描引擎 API — CRUD + 预设种子。

扫描引擎定义了扫描的阶段开关、工具选择、参数配置。
预设引擎（is_preset）开箱即用不可删，用户可创建自定义引擎。
"""

import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..db import SessionLocal
from ..models import ScanEngine

router = APIRouter(tags=["scan-engines"])

# ── 预设引擎（首次启动种入）──────────────────────────────────
_PRESETS = [
    {
        "name": "快速",
        "description": "只扫子域名 + 端口，跳过 Web/漏洞，最快出结果",
        "config": {
            "stages": {"subdomain": True, "port": True, "web": False, "fingerprint": False,
                       "sensitive": False, "takeover": False, "js": False, "vuln": False,
                       "screenshot": False, "banner": True},
            "subdomain_tool": "auto", "portscan_tool": "auto", "dns_tool": "auto",
            "port_preset": "common", "timeout": 180,
        },
    },
    {
        "name": "标准",
        "description": "默认全流程：子域名→端口→Web→指纹→敏感路径→JS→Banner（不含漏洞扫描）",
        "config": {
            "stages": {"subdomain": True, "port": True, "web": True, "fingerprint": True,
                       "sensitive": True, "takeover": True, "js": True, "vuln": False,
                       "screenshot": False, "banner": True},
            "subdomain_tool": "auto", "portscan_tool": "auto", "web_tool": "auto", "dns_tool": "auto",
            "port_preset": "common", "timeout": 300,
        },
    },
    {
        "name": "深度",
        "description": "全流程 + 漏洞扫描（nuclei）+ 截图，最全面但最慢",
        "config": {
            "stages": {"subdomain": True, "port": True, "web": True, "fingerprint": True,
                       "sensitive": True, "takeover": True, "js": True, "vuln": True,
                       "screenshot": True, "banner": True},
            "subdomain_tool": "auto", "portscan_tool": "auto", "web_tool": "auto", "dns_tool": "auto",
            "port_preset": "top1000", "timeout": 900,
            "nuclei_severity": "critical,high,medium,low",
        },
    },
    {
        "name": "仅端口",
        "description": "跳过子域名，只对目标 IP/域名做端口扫描",
        "config": {
            "stages": {"subdomain": False, "port": True, "web": False, "fingerprint": False,
                       "sensitive": False, "takeover": False, "js": False, "vuln": False,
                       "screenshot": False, "banner": False},
            "portscan_tool": "auto", "port_preset": "top1000", "timeout": 300,
        },
    },
    {
        "name": "仅 Web",
        "description": "跳过端口扫描，只对已知 Web 端口做探测+指纹+敏感路径",
        "config": {
            "stages": {"subdomain": False, "port": False, "web": True, "fingerprint": True,
                       "sensitive": True, "takeover": False, "js": True, "vuln": False,
                       "screenshot": False, "banner": False},
            "web_tool": "auto", "timeout": 300,
        },
    },
    {
        "name": "漏洞专项",
        "description": "只跑 nuclei 漏洞扫描（需先有 Web 站点），适合资产已知补漏",
        "config": {
            "stages": {"subdomain": False, "port": False, "web": True, "fingerprint": False,
                       "sensitive": False, "takeover": False, "js": False, "vuln": True,
                       "screenshot": False, "banner": False},
            "web_tool": "auto", "timeout": 600,
            "nuclei_severity": "critical,high,medium,low",
        },
    },
]


def _ensure_presets():
    """首次启动种入预设引擎（已存在则跳过）。"""
    db = SessionLocal()
    try:
        for preset in _PRESETS:
            exists = db.query(ScanEngine).filter(ScanEngine.name == preset["name"]).first()
            if not exists:
                db.add(ScanEngine(
                    name=preset["name"],
                    description=preset["description"],
                    config_json=json.dumps(preset["config"], ensure_ascii=False),
                    is_preset=1,
                ))
        db.commit()
    finally:
        db.close()


def _serialize(engine: ScanEngine) -> dict:
    return {
        "id": engine.id,
        "name": engine.name,
        "description": engine.description,
        "config": json.loads(engine.config_json) if engine.config_json else {},
        "is_preset": bool(engine.is_preset),
        "created_at": engine.created_at.isoformat() + "Z" if engine.created_at else None,
    }


class EngineCreate(BaseModel):
    name: str
    description: str = ""
    config: dict


class EngineUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    config: dict | None = None


@router.get("/scan-engines")
def list_engines():
    """列出所有扫描引擎（预设 + 自定义）。"""
    _ensure_presets()
    db = SessionLocal()
    try:
        engines = db.query(ScanEngine).order_by(ScanEngine.is_preset.desc(), ScanEngine.id).all()
        return {"items": [_serialize(e) for e in engines], "total": len(engines)}
    finally:
        db.close()


@router.post("/scan-engines")
def create_engine(req: EngineCreate):
    """创建自定义扫描引擎。"""
    db = SessionLocal()
    try:
        if db.query(ScanEngine).filter(ScanEngine.name == req.name).first():
            raise HTTPException(400, f"引擎名 '{req.name}' 已存在")
        engine = ScanEngine(
            name=req.name,
            description=req.description,
            config_json=json.dumps(req.config, ensure_ascii=False),
            is_preset=0,
        )
        db.add(engine)
        db.commit()
        db.refresh(engine)
        return _serialize(engine)
    finally:
        db.close()


@router.put("/scan-engines/{engine_id}")
def update_engine(engine_id: int, req: EngineUpdate):
    """更新扫描引擎（预设引擎也可改配置，但不改 is_preset 标志）。"""
    db = SessionLocal()
    try:
        engine = db.query(ScanEngine).filter(ScanEngine.id == engine_id).first()
        if not engine:
            raise HTTPException(404, "引擎不存在")
        if req.name is not None:
            engine.name = req.name
        if req.description is not None:
            engine.description = req.description
        if req.config is not None:
            engine.config_json = json.dumps(req.config, ensure_ascii=False)
        db.commit()
        db.refresh(engine)
        return _serialize(engine)
    finally:
        db.close()


@router.delete("/scan-engines/{engine_id}")
def delete_engine(engine_id: int):
    """删除扫描引擎（预设引擎不可删）。"""
    db = SessionLocal()
    try:
        engine = db.query(ScanEngine).filter(ScanEngine.id == engine_id).first()
        if not engine:
            raise HTTPException(404, "引擎不存在")
        if engine.is_preset:
            raise HTTPException(400, "预设引擎不可删除")
        db.delete(engine)
        db.commit()
        return {"success": True}
    finally:
        db.close()
