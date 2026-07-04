"""服务层通用工具。"""

from datetime import datetime


def to_iso_z(dt: datetime | None) -> str | None:
    """把 naive datetime（UTC）序列化为带 Z 后缀的 ISO 字符串。

    问题: DB 用 datetime.utcnow() 存 UTC 时间，但 .isoformat() 不带时区标记，
    浏览器 new Date() 会误当本地时间，导致前端耗时计算差几个时区小时。
    本函数统一加 Z 后缀，明确告知这是 UTC 时间。
    """
    if dt is None:
        return None
    # naive datetime 直接加 Z；aware datetime 转 UTC 再加 Z
    iso = dt.isoformat()
    if iso.endswith("+00:00"):
        return iso.replace("+00:00", "Z")
    if "T" in iso and not (iso.endswith("Z") or "+" in iso[10:]):
        return iso + "Z"
    return iso
