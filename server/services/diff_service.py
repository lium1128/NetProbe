"""扫描结果对比服务 — 对比同一目标的两次扫描，高亮新增/消失/变化的资产。

对齐键与 asset_service 一致：主机用 (hostname, ip)，hostname 为空时 fallback 到 ip。
数据源复用 routers.result.get_result（内存优先 + DB 回退 + JSON 已反序列化）。

注意：get_result 定义在 routers.result，这里用函数内延迟 import 避免循环依赖
（result.py 在模块级 import 本模块的 compute_diff）。
"""

from fastapi import HTTPException


def _host_key(host: dict) -> tuple[str, str]:
    """主机对齐键：(hostname, ip)，hostname 为空则用 ip 兜底。"""
    hostname = (host.get("hostname") or "").strip()
    ip = (host.get("ip") or "").strip()
    return (hostname or ip, ip)


def _port_key(p: dict) -> tuple[int, str]:
    return (p.get("port", 0), p.get("proto", "tcp"))


def _web_key(w: dict) -> tuple[int, str]:
    # 用 url 做主键更精确，url 为空时回退 (port,)
    url = (w.get("url") or "").strip()
    if url:
        return ("__url__", url)
    return ("__port__", str(w.get("port", 0)))


def _banner_key(b: dict) -> tuple[int, str]:
    return (b.get("port", 0), b.get("service") or b.get("banner") or "")


def _tech_names(web_info_list: list[dict]) -> set[str]:
    """从一组 web_info 提取全部技术栈 name 集合。"""
    names: set[str] = set()
    for w in web_info_list:
        for tech in w.get("tech") or []:
            name = (tech.get("name") or "").strip()
            if name:
                names.add(name)
    return names


def _diff_ports(ports_a: list[dict], ports_b: list[dict]) -> dict:
    """端口差异。added=B 独有，removed=A 独有，changed=共有但 service/product/version 变化。"""
    map_a = {_port_key(p): p for p in ports_a}
    map_b = {_port_key(p): p for p in ports_b}
    keys_a, keys_b = set(map_a), set(map_b)

    added = [map_b[k] for k in sorted(keys_b - keys_a)]
    removed = [map_a[k] for k in sorted(keys_a - keys_b)]

    changed = []
    for k in sorted(keys_a & keys_b):
        a, b = map_a[k], map_b[k]
        for field in ("service", "product", "version", "state"):
            if (a.get(field) or "") != (b.get(field) or ""):
                changed.append({"key": list(k), "from": a, "to": b})
                break

    return {"added": added, "removed": removed, "changed": changed}


def _diff_web(web_a: list[dict], web_b: list[dict]) -> dict:
    """Web 站点差异 + 技术栈变化。"""
    map_a = {_web_key(w): w for w in web_a}
    map_b = {_web_key(w): w for w in web_b}
    keys_a, keys_b = set(map_a), set(map_b)

    added = [map_b[k] for k in sorted(keys_b - keys_a)]
    removed = [map_a[k] for k in sorted(keys_a - keys_b)]

    changed = []
    for k in sorted(keys_a & keys_b):
        a, b = map_a[k], map_b[k]
        diffs = {}
        for field in ("title", "status", "redirect"):
            if (a.get(field) or "") != (b.get(field) or ""):
                diffs[field] = {"from": a.get(field), "to": b.get(field)}
        # 技术栈 name 集合差集
        ta = {t.get("name") for t in (a.get("tech") or []) if t.get("name")}
        tb = {t.get("name") for t in (b.get("tech") or []) if t.get("name")}
        if ta != tb:
            diffs["tech"] = {"added": sorted(tb - ta), "removed": sorted(ta - tb)}
        if diffs:
            changed.append({"url": a.get("url"), "changes": diffs})

    return {"added": added, "removed": removed, "changed": changed}


def _diff_simple(items_a: list[dict], items_b: list[dict], key_fn) -> dict:
    """通用单维度集合差集（sensitive path / js_url / banner）。"""
    set_a = {key_fn(x) for x in items_a}
    set_b = {key_fn(x) for x in items_b}
    map_b = {key_fn(x): x for x in items_b}
    map_a = {key_fn(x): x for x in items_a}
    return {
        "added": [map_b[k] for k in sorted(set_b - set_a) if k in map_b],
        "removed": [map_a[k] for k in sorted(set_a - set_b) if k in map_a],
    }


def compute_diff(scan_a: str, scan_b: str) -> dict:
    """对比两次扫描，返回结构化差异。"""
    # 延迟 import 打破与 routers.result 的循环依赖
    from ..routers.result import get_result

    try:
        result_a = get_result(scan_a)
        result_b = get_result(scan_b)
    except HTTPException:
        raise HTTPException(404, "one or both scans not found")

    hosts_a = { _host_key(h): h for h in result_a.get("hosts", []) }
    hosts_b = { _host_key(h): h for h in result_b.get("hosts", []) }
    keys_a, keys_b = set(hosts_a), set(hosts_b)

    host_diffs = []
    # 新增主机（B 有 A 无）
    for k in sorted(keys_b - keys_a):
        h = hosts_b[k]
        host_diffs.append({
            "key": list(k),
            "hostname": h.get("hostname") or k[0],
            "ip": h.get("ip") or k[1],
            "status": "added",
            "ports": _diff_ports([], h.get("ports") or []),
            "web": _diff_web([], h.get("web_info") or []),
            "sensitive": _diff_simple([], h.get("sensitive") or [], lambda s: s.get("path", "")),
            "js": _diff_simple([], h.get("js_findings") or [], lambda j: j.get("js_url", "")),
            "banners": _diff_simple([], h.get("banners") or [], _banner_key),
        })
    # 消失主机（A 有 B 无）
    for k in sorted(keys_a - keys_b):
        h = hosts_a[k]
        host_diffs.append({
            "key": list(k),
            "hostname": h.get("hostname") or k[0],
            "ip": h.get("ip") or k[1],
            "status": "removed",
            "ports": _diff_ports(h.get("ports") or [], []),
            "web": _diff_web(h.get("web_info") or [], []),
            "sensitive": _diff_simple(h.get("sensitive") or [], [], lambda s: s.get("path", "")),
            "js": _diff_simple(h.get("js_findings") or [], [], lambda j: j.get("js_url", "")),
            "banners": _diff_simple(h.get("banners") or [], [], _banner_key),
        })
    # 变化主机（共有）
    for k in sorted(keys_a & keys_b):
        ha, hb = hosts_a[k], hosts_b[k]
        port_diff = _diff_ports(ha.get("ports") or [], hb.get("ports") or [])
        web_diff = _diff_web(ha.get("web_info") or [], hb.get("web_info") or [])
        sens_diff = _diff_simple(ha.get("sensitive") or [], hb.get("sensitive") or [], lambda s: s.get("path", ""))
        js_diff = _diff_simple(ha.get("js_findings") or [], hb.get("js_findings") or [], lambda j: j.get("js_url", ""))
        banner_diff = _diff_simple(ha.get("banners") or [], hb.get("banners") or [], _banner_key)

        has_change = any([
            port_diff["added"] or port_diff["removed"] or port_diff["changed"],
            web_diff["added"] or web_diff["removed"] or web_diff["changed"],
            sens_diff["added"] or sens_diff["removed"],
            js_diff["added"] or js_diff["removed"],
            banner_diff["added"] or banner_diff["removed"],
        ])
        if has_change:
            host_diffs.append({
                "key": list(k),
                "hostname": hb.get("hostname") or k[0],
                "ip": hb.get("ip") or k[1],
                "status": "changed",
                "ports": port_diff,
                "web": web_diff,
                "sensitive": sens_diff,
                "js": js_diff,
                "banners": banner_diff,
            })

    # 汇总统计
    summary = {
        "hosts_added": sum(1 for h in host_diffs if h["status"] == "added"),
        "hosts_removed": sum(1 for h in host_diffs if h["status"] == "removed"),
        "hosts_changed": sum(1 for h in host_diffs if h["status"] == "changed"),
        "ports_added": sum(len(h["ports"].get("added", [])) for h in host_diffs),
        "ports_removed": sum(len(h["ports"].get("removed", [])) for h in host_diffs),
        "ports_changed": sum(len(h["ports"].get("changed", [])) for h in host_diffs),
        "web_added": sum(len(h["web"].get("added", [])) for h in host_diffs),
        "web_removed": sum(len(h["web"].get("removed", [])) for h in host_diffs),
        "tech_changed": sum(len(h["web"].get("changed", [])) for h in host_diffs),
    }

    return {
        "scan_a": {
            "scan_id": result_a.get("scan_id"),
            "base_domain": result_a.get("base_domain", ""),
        },
        "scan_b": {
            "scan_id": result_b.get("scan_id"),
            "base_domain": result_b.get("base_domain", ""),
        },
        "summary": summary,
        "hosts": host_diffs,
    }


def compute_timeline(base_domain: str) -> dict:
    """资产生命周期时间线：同目标多次扫描的资产新增/消失/变化趋势。

    流程: 查同 base_domain 的所有扫描按时间排序 → 相邻扫描逐对 diff → 聚合时间序列。
    返回 {target, points:[{scan_id, started_at, host_count, added, removed, changed}], summary}
    """
    from ..db import SessionLocal
    from ..models import Scan

    db = SessionLocal()
    try:
        # 查同目标的已完成扫描，按时间正序
        scans = (
            db.query(Scan)
            .filter(Scan.status == "done", Scan.base_domain.contains(base_domain))
            .order_by(Scan.started_at.asc())
            .limit(50)
            .all()
        )
    finally:
        db.close()

    if len(scans) < 2:
        return {"target": base_domain, "points": [], "summary": {"total_scans": len(scans)}}

    points = []
    prev_hosts = None
    prev_scan_id = None

    for scan in scans:
        scan_id = scan.scan_id
        started_at = scan.started_at.isoformat() if scan.started_at else ""

        # 取本次扫描的 hosts
        curr = _get_hosts_for_scan(scan_id)
        host_count = len(curr)

        if prev_hosts is None:
            # 第一次扫描，全部视为新增
            added = host_count
            removed = 0
            changed = 0
        else:
            # 与上次 diff
            added, removed, changed = _count_host_changes(prev_hosts, curr)

        points.append({
            "scan_id": scan_id,
            "started_at": started_at,
            "host_count": host_count,
            "port_count": scan.port_count or 0,
            "web_count": scan.web_count or 0,
            "added": added,
            "removed": removed,
            "changed": changed,
        })

        prev_hosts = curr
        prev_scan_id = scan_id

    summary = {
        "total_scans": len(scans),
        "total_added": sum(p["added"] for p in points),
        "total_removed": sum(p["removed"] for p in points),
        "total_changed": sum(p["changed"] for p in points),
    }

    return {"target": base_domain, "points": points, "summary": summary}


def _get_hosts_for_scan(scan_id: str) -> dict:
    """取一次扫描的 hosts，返回 {host_key: host_dict}。"""
    from ..routers.result import get_result
    try:
        result = get_result(scan_id)
        return {_host_key(h): h for h in result.get("hosts", [])}
    except Exception:
        return {}


def _count_host_changes(prev: dict, curr: dict) -> tuple[int, int, int]:
    """对比两次扫描的主机集合，返回 (added, removed, changed) 数量。"""
    prev_keys = set(prev)
    curr_keys = set(curr)
    added = len(curr_keys - prev_keys)
    removed = len(prev_keys - curr_keys)
    # 共有的但内部变化的算 changed
    common = curr_keys & prev_keys
    changed = 0
    for k in common:
        pa, pb = prev[k], curr[k]
        # 端口/Web/敏感路径任一变化即算 changed
        if (_diff_ports(pa.get("ports") or [], pb.get("ports") or [])["added"]
            or _diff_ports(pa.get("ports") or [], pb.get("ports") or [])["removed"]
            or _diff_web(pa.get("web_info") or [], pb.get("web_info") or [])["added"]
            or _diff_web(pa.get("web_info") or [], pb.get("web_info") or [])["removed"]):
            changed += 1
    return added, removed, changed
