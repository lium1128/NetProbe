"""设置 API — GET/PUT /api/settings."""

import json
import os

from fastapi import APIRouter
from pydantic import BaseModel

from ..config import DATA_DIR
from ..services.notify_service import send_notification

router = APIRouter(tags=["settings"])

_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

_DEFAULTS = {
    "layout": "sidebar",  # sidebar | topnav
    "theme": "light",  # light | dark
    "api_keys": {
        "shodan": "",
        "fofa_email": "",
        "fofa_key": "",
        "hunter_key": "",
        "censys_id": "",
        "censys_secret": "",
    },
    "notifications": {
        "webhook": {
            "url": "",
            "headers": {},
        },
        "dingtalk": {
            "access_token": "",  # 钉钉群机器人的 access_token
            "secret": "",        # 加签密钥（可选，启用签名校验）
        },
        "wecom": {
            "key": "",  # 企业微信群机器人 key
        },
        "feishu": {
            "webhook": "",  # 飞书群机器人完整 webhook 地址
            "secret": "",    # 签名校验密钥（可选）
        },
        "telegram": {
            "bot_token": "",  # Telegram Bot API token
            "chat_id": "",    # 目标 chat id（群/频道/用户）
        },
        "email": {
            "smtp_host": "",
            "smtp_port": 465,
            "username": "",
            "password": "",
            "from_addr": "",
            "to_addrs": [],  # 收件人列表
            "use_ssl": True,
        },
    },
}


def _load() -> dict:
    if os.path.isfile(_SETTINGS_FILE):
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 补齐缺失的默认字段
        for k, v in _DEFAULTS.items():
            if k not in data:
                data[k] = v
        return data
    return dict(_DEFAULTS)


def _save(data: dict):
    with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class SettingsUpdate(BaseModel):
    layout: str | None = None
    theme: str | None = None
    api_keys: dict | None = None
    notifications: dict | None = None


@router.get("/settings")
def get_settings():
    """获取系统设置。"""
    return _load()


@router.put("/settings")
def update_settings(body: SettingsUpdate):
    """更新系统设置。"""
    data = _load()
    updates = body.model_dump(exclude_unset=True)
    data.update(updates)
    _save(data)
    return data


@router.post("/settings/test-notification")
def test_notification():
    """发送测试通知，验证通知渠道配置是否正确。"""
    result = send_notification(
        title="NetProbe 测试通知",
        message="这是一条来自 NetProbe 的测试通知。如果你收到了，说明通知渠道配置正确。",
        details={"type": "test"},
    )
    return result

