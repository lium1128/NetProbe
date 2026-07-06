"""资产标签 — 给资产打标签（重要/影子/废弃等），按 hostname+ip 关联。

标签是资产维度的（跨扫描），不是每条 Host 记录的。
"""

from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime

from ..db import Base


class AssetTag(Base):
    __tablename__ = "asset_tags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), default="", index=True)
    ip = Column(String(64), default="", index=True)
    tags = Column(Text, default="[]")  # JSON 数组，如 ["重要", "影子资产"]
    notes = Column(Text, default="")   # 备注
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
