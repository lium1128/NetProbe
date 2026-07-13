"""用户模型 — JWT 认证 + RBAC 角色权限。"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Boolean

from ..db import Base

# 角色定义
ROLES = {
    'admin': '管理员',
    'scanner': '扫描员',
    'auditor': '审计员',
    'viewer': '只读用户',
}

# 角色 → 权限映射
ROLE_PERMISSIONS = {
    'admin': {
        'scan', 'view', 'edit', 'delete', 'manage_users', 'manage_system',
        'manage_plugins', 'download_report', 'manage_vulns',
    },
    'scanner': {
        'scan', 'view', 'edit', 'download_report', 'manage_vulns',
    },
    'auditor': {
        'view', 'download_report', 'manage_vulns',
    },
    'viewer': {
        'view',
    },
}


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    role = Column(String(32), default="viewer")  # admin/scanner/auditor/viewer
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
