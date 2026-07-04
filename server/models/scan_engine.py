"""扫描引擎模型 — 用户可自定义的扫描阶段/工具/参数配置。

预设引擎（is_preset=True）开箱即用，用户可基于预设克隆修改。
config_json 结构:
{
  "stages": {subdomain, port, web, fingerprint, sensitive, takeover, js, vuln, screenshot, banner},
  "subdomain_tool": "auto", "portscan_tool": "auto", "web_tool": "auto", "dns_tool": "auto",
  "port_preset": "common", "custom_ports": "",
  "nuclei_severity": "critical,high,medium", "nuclei_tags": "cve,vuln,misconfig",
  "timeout": 300
}
"""

from sqlalchemy import Column, DateTime, Integer, String, Text
from datetime import datetime

from ..db import Base


class ScanEngine(Base):
    __tablename__ = "scan_engines"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False, unique=True, index=True)
    description = Column(String(255), default="")
    config_json = Column(Text, default="{}")
    is_preset = Column(Integer, default=0)  # 0=用户自定义, 1=系统预设（不可删）
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
