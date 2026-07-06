"""资产标签 API — 给资产打标签/备注，按 hostname+ip 关联。"""

import json
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..db import SessionLocal
from ..models import AssetTag

router = APIRouter(tags=["asset-tags"])


class TagUpdate(BaseModel):
    hostname: str = ""
    ip: str = ""
    tags: list[str] = []
    notes: str = ""


class TagBatchUpdate(BaseModel):
    items: list[TagUpdate] = []


# 预设标签（前端快捷选择）
PRESET_TAGS = ["重要资产", "影子资产", "废弃资产", "核心业务", "测试环境", "已确认", "待跟进"]


@router.get("/asset-tags")
def get_tags(hostname: str = "", ip: str = ""):
    """获取资产标签。传 hostname+ip 查单个，不传查全部。"""
    db = SessionLocal()
    try:
        query = db.query(AssetTag)
        if hostname:
            query = query.filter(AssetTag.hostname == hostname)
        if ip:
            query = query.filter(AssetTag.ip == ip)
        rows = query.all()
        return {
            "items": [{
                "id": r.id,
                "hostname": r.hostname,
                "ip": r.ip,
                "tags": json.loads(r.tags) if r.tags else [],
                "notes": r.notes or "",
            } for r in rows],
            "presets": PRESET_TAGS,
        }
    finally:
        db.close()


@router.put("/asset-tags")
def update_tag(req: TagUpdate):
    """设置资产标签（有则更新，无则创建）。"""
    db = SessionLocal()
    try:
        tag = db.query(AssetTag).filter(
            AssetTag.hostname == req.hostname,
            AssetTag.ip == req.ip,
        ).first()

        if tag:
            tag.tags = json.dumps(req.tags, ensure_ascii=False)
            tag.notes = req.notes
            tag.updated_at = datetime.utcnow()
        else:
            tag = AssetTag(
                hostname=req.hostname,
                ip=req.ip,
                tags=json.dumps(req.tags, ensure_ascii=False),
                notes=req.notes,
            )
            db.add(tag)
        db.commit()
        return {"success": True, "id": tag.id}
    finally:
        db.close()


@router.delete("/asset-tags/{tag_id}")
def delete_tag(tag_id: int):
    """删除资产标签。"""
    db = SessionLocal()
    try:
        tag = db.query(AssetTag).filter(AssetTag.id == tag_id).first()
        if not tag:
            raise HTTPException(404, "标签不存在")
        db.delete(tag)
        db.commit()
        return {"success": True}
    finally:
        db.close()
