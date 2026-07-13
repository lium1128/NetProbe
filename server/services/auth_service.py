"""认证服务 — JWT 签发/验证 + 密码哈希 + 用户管理。

首次启动自动创建默认管理员（admin/admin），登录后建议改密码。
"""

from datetime import datetime, timedelta

import jwt
import bcrypt
from fastapi import HTTPException, status

from ..config import SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_DAYS
from ..db import SessionLocal
from ..models import User


def hash_password(plain: str) -> str:
    """bcrypt 哈希密码。"""
    pwd_bytes = plain.encode("utf-8")[:72]
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """校验密码。"""
    pwd_bytes = plain.encode("utf-8")[:72]
    return bcrypt.checkpw(pwd_bytes, hashed.encode("utf-8"))


def create_token(user: User) -> str:
    """签发 JWT token（有效期 7 天）。"""
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "is_admin": user.is_admin,
        "role": user.role or ("admin" if user.is_admin else "viewer"),
        "exp": datetime.utcnow() + timedelta(days=JWT_EXPIRE_DAYS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def has_permission(user: User, permission: str) -> bool:
    """检查用户是否有指定权限。

    权限: scan / view / edit / delete / manage_users / manage_system /
          manage_plugins / download_report / manage_vulns
    """
    from ..models.user import ROLE_PERMISSIONS
    # admin 兼容（旧版只有 is_admin 布尔）
    if user.is_admin and not user.role:
        return True
    role = user.role or ("admin" if user.is_admin else "viewer")
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms


def require_permission(user: User, permission: str):
    """检查权限，不通过则抛 403。"""
    from fastapi import HTTPException
    if not has_permission(user, permission):
        raise HTTPException(403, f"权限不足，需要 '{permission}' 权限")


def get_current_user(token: str) -> User:
    """解析 JWT token，返回用户对象。token 无效则抛 401。"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="token 无效或已过期",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        user_id = int(payload.get("sub", 0))
        if not user_id:
            raise credentials_exception
    except (jwt.InvalidTokenError, ValueError):
        raise credentials_exception

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise credentials_exception
        return user
    finally:
        db.close()


def login(username: str, password: str) -> dict:
    """用户登录，返回 {token, user}。失败抛 401。"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        # 更新最后登录时间
        user.last_login = datetime.utcnow()
        db.commit()
        token = create_token(user)
        return {
            "token": token,
            "user": {
                "id": user.id, "username": user.username,
                "is_admin": user.is_admin,
                "role": user.role or ("admin" if user.is_admin else "viewer"),
            },
        }
    finally:
        db.close()


def change_password(user_id: int, old_password: str, new_password: str) -> bool:
    """修改密码。旧密码不匹配返回 False。"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user or not verify_password(old_password, user.password_hash):
            return False
        user.password_hash = hash_password(new_password)
        db.commit()
        return True
    finally:
        db.close()


def create_user(username: str, password: str, is_admin: bool = False, role: str = "") -> User:
    """创建新用户。用户名已存在则抛 400。"""
    from ..models.user import ROLES
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            raise HTTPException(status_code=400, detail="用户名已存在")
        # role 优先于 is_admin
        if not role:
            role = "admin" if is_admin else "viewer"
        if role not in ROLES:
            raise HTTPException(status_code=400, detail=f"无效角色，可选: {', '.join(ROLES.keys())}")
        user = User(
            username=username, password_hash=hash_password(password),
            is_admin=(role == "admin"), role=role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def list_users() -> list[dict]:
    """列出所有用户。"""
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.id).all()
        return [{
            "id": u.id, "username": u.username, "is_admin": u.is_admin,
            "role": u.role or ("admin" if u.is_admin else "viewer"),
            "created_at": u.created_at.isoformat() + "Z" if u.created_at else None,
            "last_login": u.last_login.isoformat() + "Z" if u.last_login else None,
        } for u in users]
    finally:
        db.close()


def update_user(user_id: int, password: str | None = None, is_admin: bool | None = None,
                role: str | None = None) -> bool:
    """更新用户（改密码/角色）。用户不存在返回 False。"""
    from ..models.user import ROLES
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        if password:
            user.password_hash = hash_password(password)
        if role is not None:
            if role not in ROLES:
                raise HTTPException(status_code=400, detail=f"无效角色: {role}")
            user.role = role
            user.is_admin = (role == "admin")
        elif is_admin is not None:
            user.is_admin = is_admin
            if is_admin and not user.role:
                user.role = "admin"
        db.commit()
        return True
    finally:
        db.close()


def delete_user(user_id: int, current_user_id: int) -> bool:
    """删除用户。不能删自己，不能删最后一个管理员。"""
    if user_id == current_user_id:
        raise HTTPException(status_code=400, detail="不能删除自己")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        # 如果要删的是管理员，检查是否最后一个
        if user.is_admin:
            admin_count = db.query(User).filter(User.is_admin == True).count()  # noqa: E712
            if admin_count <= 1:
                raise HTTPException(status_code=400, detail="不能删除最后一个管理员")
        db.delete(user)
        db.commit()
        return True
    finally:
        db.close()


def init_admin():
    """首次启动时自动创建默认管理员（admin/admin）。

    在 app startup 调用，如果 users 表为空则创建。
    同时迁移旧用户：is_admin=True 但 role 为空的设为 admin。
    """
    db = SessionLocal()
    try:
        # 迁移旧用户：给 is_admin=True 的补 role=admin，其余补 role=viewer
        for u in db.query(User).all():
            if not u.role:
                u.role = "admin" if u.is_admin else "viewer"
        db.commit()

        count = db.query(User).count()
        if count == 0:
            admin = User(
                username="admin",
                password_hash=hash_password("admin"),
                is_admin=True,
                role="admin",
            )
            db.add(admin)
            db.commit()
            print("[*] 已创建默认管理员: admin/admin（请尽快修改密码）")
    finally:
        db.close()
