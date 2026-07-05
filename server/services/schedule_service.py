"""定时扫描服务 — schedules 表 CRUD + APScheduler 集成。

调度器生命周期:
  init_scheduler()    在 app startup 调用，启动 BackgroundScheduler 并从表重建 enabled job
  shutdown_scheduler() 在 app shutdown 调用

每个 schedule 表行对应一个 APScheduler job（job id = schedule id）。create/update/delete
同步操作两处，保持表与内存一致。定时回调 _run_scheduled_scan 检查并发数后调用
scan_service.start_scan。

内置任务（不进 schedules 表）:
  nuclei 模板自动更新 — 每周一凌晨 3 点跑 `nuclei -update-templates -silent`，
  job id 为常量 _NUCLEI_UPDATE_JOB_ID，nuclei 未安装则静默跳过。
"""

import json
import logging
import subprocess
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from ..db import SessionLocal
from ..models import Schedule
from ..utils import to_iso_z
from .scan_service import start_scan, _tasks

logger = logging.getLogger(__name__)

# 单例调度器（模块级，init/shutdown 管理）
_scheduler: BackgroundScheduler | None = None

# 最多允许同时运行的扫描任务数（含手动与定时触发）
_MAX_CONCURRENT = 2

# 内置定时任务 job id（与 schedules 表的数字 id 区分开，避免冲突）
_NUCLEI_UPDATE_JOB_ID = "__nuclei_update_templates__"
_CT_MONITOR_JOB_ID = "__ct_certificate_monitor__"      # 证书透明度监控（每天）
_DNS_MONITOR_JOB_ID = "__dns_change_monitor__"          # DNS 变更监控（每天）
_CRUISE_JOB_ID = "__cruise_mode__"                      # 巡航模式（每小时检查待扫目标）


# ── cron 表达式校验 ──────────────────────────────────────────────

def validate_cron(expr: str) -> CronTrigger:
    """解析标准 5 段 cron 表达式，非法则抛 ValueError。"""
    try:
        return CronTrigger.from_crontab(expr)
    except ValueError as e:
        raise ValueError(f"非法 cron 表达式: {expr} ({e})")


# ── 调度器生命周期 ──────────────────────────────────────────────

def init_scheduler():
    """启动调度器并从 schedules 表重建所有 enabled job。在 app startup 调用。"""
    global _scheduler
    if _scheduler is not None:
        return  # 已启动

    _scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    _scheduler.start()

    # 从表重建 job
    db = SessionLocal()
    try:
        for sch in db.query(Schedule).filter(Schedule.enabled == True).all():  # noqa: E712
            _add_job(sch)
    finally:
        db.close()

    # 内置定时任务：每周一凌晨 3 点自动更新 nuclei 模板
    _add_nuclei_update_job()
    # #15 证书透明度监控：每天 6 点拉 crt.sh 发现新子域
    _add_ct_monitor_job()
    # #16 DNS 变更监控：每天 6:30 检查 A/CNAME 变化
    _add_dns_monitor_job()
    logger.info("scheduler started, restored jobs from schedules table")


def shutdown_scheduler():
    """关闭调度器。在 app shutdown 调用。"""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None


# ── job 操作（内部）────────────────────────────────────────────

def _job_id(schedule_id: int) -> str:
    return str(schedule_id)


def _add_job(schedule: Schedule):
    """把一条 schedule 加入调度器。"""
    if _scheduler is None:
        return
    trigger = validate_cron(schedule.cron_expr)
    _scheduler.add_job(
        _run_scheduled_scan,
        trigger=trigger,
        args=[schedule.id],
        id=_job_id(schedule.id),
        replace_existing=True,
    )
    _sync_next_run(schedule.id)


def _remove_job(schedule_id: int):
    """从调度器移除 job（若存在）。"""
    if _scheduler is None:
        return
    try:
        _scheduler.remove_job(_job_id(schedule_id))
    except Exception:
        pass  # job 不存在，忽略


def _sync_next_run(schedule_id: int):
    """把调度器里 job 的下次触发时间写回表。"""
    if _scheduler is None:
        return
    db = SessionLocal()
    try:
        sch = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not sch:
            return
        job = _scheduler.get_job(_job_id(schedule_id))
        if job and job.next_run_time:
            sch.next_run_at = job.next_run_time.replace(tzinfo=None)
            db.commit()
    finally:
        db.close()


# ── 内置任务：nuclei 模板自动更新 ────────────────────────────

def _add_nuclei_update_job():
    """注册每周一凌晨 3 点更新 nuclei 模板的内置 cron job。

    与 schedules 表无关，常驻调度器。nuclei 二进制不存在时回调内部静默跳过。
    """
    if _scheduler is None:
        return
    try:
        _scheduler.add_job(
            _update_nuclei_templates,
            trigger=CronTrigger(day_of_week="mon", hour=3, minute=0,
                                timezone="Asia/Shanghai"),
            id=_NUCLEI_UPDATE_JOB_ID,
            replace_existing=True,
        )
    except Exception as e:
        logger.warning("failed to add nuclei update job: %s", e)


def _update_nuclei_templates():
    """执行 `nuclei -update-templates -silent`，保持模板库最新。

    容错策略：nuclei 未安装 / 超时 / 任意异常均不抛出（仅记日志），
    避免影响调度器主循环与正常扫描任务。
    """
    try:
        result = subprocess.run(
            ["nuclei", "-update-templates", "-silent"],
            capture_output=True,
            text=True,
            timeout=600,  # 模板更新可能较慢，给 10 分钟
        )
        if result.returncode == 0:
            logger.info("nuclei templates updated successfully")
        else:
            logger.warning("nuclei -update-templates returned %d: %s",
                           result.returncode, (result.stderr or "").strip()[:200])
    except FileNotFoundError:
        # nuclei 未安装，静默跳过
        logger.debug("nuclei not installed, skip template update")
    except subprocess.TimeoutExpired:
        logger.warning("nuclei -update-templates timed out after 600s")
    except Exception as e:
        logger.warning("nuclei template update failed: %s", e)


# ── 定时回调 ────────────────────────────────────────────────────

def _count_running() -> int:
    """统计当前内存中 running 状态的扫描任务数。"""
    return sum(1 for t in _tasks.values() if t.get("status") == "running")


def _run_scheduled_scan(schedule_id: int):
    """定时器回调：触发一次扫描。并发超限则跳过本次。"""
    if _count_running() >= _MAX_CONCURRENT:
        logger.info("schedule %s skipped: too many running scans", schedule_id)
        return

    db = SessionLocal()
    try:
        sch = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not sch or not sch.enabled:
            return

        options = json.loads(sch.options_json) if sch.options_json else {}
        options["name"] = sch.name or f"定时扫描 {schedule_id}"
        # start_scan 内部会注入并剥离下划线字段，这里传纯配置即可
        start_scan(sch.target_raw, options)

        sch.last_run_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        logger.exception("scheduled scan %s failed: %s", schedule_id, e)
    finally:
        db.close()
    # 更新下次运行时间
    _sync_next_run(schedule_id)


# ── CRUD ────────────────────────────────────────────────────────

def list_schedules() -> list[dict]:
    """返回所有定时规则。"""
    db = SessionLocal()
    try:
        rows = db.query(Schedule).order_by(Schedule.id.desc()).all()
        return [_serialize(s) for s in rows]
    finally:
        db.close()


def create_schedule(name: str, target_raw: str, cron_expr: str,
                    options: dict, enabled: bool = True) -> dict:
    """创建定时规则。校验 cron，写表并加入调度器。"""
    validate_cron(cron_expr)  # 非法抛 ValueError
    pure_opts = {k: v for k, v in options.items() if not k.startswith("_")}
    pure_opts.pop("name", None)  # name 单独存字段，不入 options

    db = SessionLocal()
    try:
        sch = Schedule(
            name=name or "",
            target_raw=target_raw,
            cron_expr=cron_expr,
            options_json=json.dumps(pure_opts, ensure_ascii=False),
            enabled=enabled,
        )
        db.add(sch)
        db.commit()
        db.refresh(sch)
        sid = sch.id
    finally:
        db.close()

    if enabled:
        _add_job(_get_by_id(sid))
        # job 加入后 next_run_at 已回写表，重新查询返回最新值
        refreshed = _get_by_id(sid)
        if refreshed:
            return _serialize(refreshed)

    # disabled 或回退：用原数据序列化
    return _serialize(_get_by_id(sid))


def update_schedule(schedule_id: int, name: str | None = None,
                    target_raw: str | None = None, cron_expr: str | None = None,
                    options: dict | None = None) -> dict | None:
    """更新定时规则。任一改动都重建 job。"""
    if cron_expr is not None:
        validate_cron(cron_expr)

    db = SessionLocal()
    try:
        sch = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not sch:
            return None
        if name is not None:
            sch.name = name
        if target_raw is not None:
            sch.target_raw = target_raw
        if cron_expr is not None:
            sch.cron_expr = cron_expr
        if options is not None:
            pure_opts = {k: v for k, v in options.items() if not k.startswith("_")}
            pure_opts.pop("name", None)
            sch.options_json = json.dumps(pure_opts, ensure_ascii=False)
        db.commit()
        db.refresh(sch)
        was_enabled = sch.enabled
        result = _serialize(sch)
    finally:
        db.close()

    # 重建 job（保持 enabled 状态）
    if was_enabled:
        _remove_job(schedule_id)
        _add_job(_get_by_id(schedule_id))
    return result


def delete_schedule(schedule_id: int) -> bool:
    """删除定时规则。先移除 job 再删表行。"""
    _remove_job(schedule_id)
    db = SessionLocal()
    try:
        sch = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not sch:
            return False
        db.delete(sch)
        db.commit()
        return True
    finally:
        db.close()


def set_enabled(schedule_id: int, enabled: bool) -> dict | None:
    """启用/暂停切换。"""
    db = SessionLocal()
    try:
        sch = db.query(Schedule).filter(Schedule.id == schedule_id).first()
        if not sch:
            return None
        sch.enabled = enabled
        if not enabled:
            sch.next_run_at = None
        db.commit()
        db.refresh(sch)
        result = _serialize(sch)
    finally:
        db.close()

    if enabled:
        _add_job(_get_by_id(schedule_id))
    else:
        _remove_job(schedule_id)
    return result


def run_now(schedule_id: int) -> bool:
    """立即手动触发一次（不经 cron，复用同一回调）。"""
    sch = _get_by_id(schedule_id)
    if not sch:
        return False
    _run_scheduled_scan(schedule_id)
    return True


# ── 辅助 ────────────────────────────────────────────────────────

def _get_by_id(schedule_id: int) -> Schedule | None:
    """按 id 取 Schedule 实例（独立 session，调用方负责关闭——这里直接返回游离对象）。"""
    db = SessionLocal()
    try:
        return db.query(Schedule).filter(Schedule.id == schedule_id).first()
    finally:
        db.close()


def _serialize(s: Schedule) -> dict:
    return {
        "id": s.id,
        "name": s.name or "",
        "target_raw": s.target_raw,
        "cron_expr": s.cron_expr,
        "options": json.loads(s.options_json) if s.options_json else {},
        "enabled": bool(s.enabled),
        "last_run_at": to_iso_z(s.last_run_at),
        "next_run_at": to_iso_z(s.next_run_at),
        "created_at": to_iso_z(s.created_at),
    }


# ═══ 内置监控 job：证书透明度 / DNS变更（#15 #16）═══════════════

def _add_ct_monitor_job():
    """#15 证书透明度监控：每天 6:00 拉 crt.sh，diff 发现新签发证书的新子域。

    从 schedules 表扫描过的所有 base_domain 出发，对新域名入库 + 触发告警。
    """
    if _scheduler is None:
        return
    try:
        _scheduler.add_job(
            _ct_monitor_callback,
            trigger=CronTrigger(hour=6, minute=0, timezone="Asia/Shanghai"),
            id=_CT_MONITOR_JOB_ID,
            replace_existing=True,
        )
    except Exception as e:
        logger.warning("failed to add CT monitor job: %s", e)


def _ct_monitor_callback():
    """证书透明度监控回调：遍历已知域名，拉 crt.sh 发现新子域。"""
    import requests
    from ..models import Scan
    db = SessionLocal()
    try:
        # 取所有扫过的 base_domain（去重）
        domains = [r[0] for r in db.query(Scan.base_domain).distinct().all() if r[0] and '+' not in r[0]]
        # 限制最多 20 个域名（避免 API 压力）
        domains = domains[:20]
    finally:
        db.close()

    if not domains:
        return

    logger.info("CT monitor: checking %d domains", len(domains))
    for domain in domains:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = requests.get(url, timeout=20, headers={"User-Agent": "NetProbe/3.0"})
            if resp.status_code != 200:
                continue
            certs = resp.json()
            # 提取所有 common_name + name_value 里的域名
            found = set()
            for cert in certs[:100]:
                for field in ('common_name', 'name_value'):
                    val = cert.get(field, '')
                    for name in val.split('\n'):
                        name = name.strip().lower()
                        if name and name.endswith(domain) and name != domain:
                            found.add(name)
            if found:
                logger.info("CT monitor: %s found %d subdomains via CT", domain, len(found))
                # TODO: 对比已有 hosts，发现新增触发告警（复用 alert_service）
        except Exception as e:
            logger.warning("CT monitor: %s failed: %s", domain, e)


def _add_dns_monitor_job():
    """#16 DNS 变更监控：每天 6:30 检查已知域名的 A/CNAME 是否变化。

    存 DNS 快照到 whois_records（type='dns_history'），diff 变化触发告警。
    """
    if _scheduler is None:
        return
    try:
        _scheduler.add_job(
            _dns_monitor_callback,
            trigger=CronTrigger(hour=6, minute=30, timezone="Asia/Shanghai"),
            id=_DNS_MONITOR_JOB_ID,
            replace_existing=True,
        )
    except Exception as e:
        logger.warning("failed to add DNS monitor job: %s", e)


def _dns_monitor_callback():
    """DNS 变更监控回调：对比当前 DNS 和上次快照。"""
    from netprobe.dns_utils import resolve_a_record, resolve_dns_records
    from ..models import Scan, Host, WhoisRecord
    import json as _json

    db = SessionLocal()
    try:
        domains = [r[0] for r in db.query(Scan.base_domain).distinct().all() if r[0] and '+' not in r[0]]
        domains = domains[:20]
        if not domains:
            return

        logger.info("DNS monitor: checking %d domains", len(domains))
        for domain in domains:
            try:
                # 当前 A 记录
                current_a = resolve_a_record(domain)
                current_cname = resolve_dns_records(domain, 'CNAME')
                current = {'a': current_a, 'cname': current_cname}

                # 取上次快照（最近一条 type=dns_history）
                host = db.query(Host).filter(Host.hostname == domain).first()
                if host:
                    prev = db.query(WhoisRecord).filter(
                        WhoisRecord.host_id == host.host_id,
                        WhoisRecord.type == 'dns_history'
                    ).order_by(WhoisRecord.queried_at.desc()).first()
                    if prev:
                        prev_data = _json.loads(prev.data_json) if prev.data_json else {}
                        prev_a = set(prev_data.get('a', []))
                        curr_a = set(current_a)
                        if prev_a != curr_a:
                            logger.info("DNS monitor: %s A record changed: %s → %s",
                                        domain, prev_a, curr_a)
                            # TODO: 触发告警
                    # 存新快照
                    db.add(WhoisRecord(
                        host_id=host.host_id,
                        type='dns_history',
                        target=domain,
                        data_json=_json.dumps(current, ensure_ascii=False),
                    ))
                    db.commit()
            except Exception as e:
                logger.warning("DNS monitor: %s failed: %s", domain, e)
    finally:
        db.close()
