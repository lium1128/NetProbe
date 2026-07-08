#!/usr/bin/env python3
"""从 hfinger (HackAllSec/hfinger) 导入中文产品友好的 Web 指纹规则。

数据源: HackAllSec/hfinger 的 data/finger.json（约 1400 条，中文产品占 50%+）
下载: 通过 jsdelivr CDN 拉取，绕开 GitHub API 限流。

hfinger JSON 结构:
  {"finger": [{cms, method, location, logic, rule}, ...]}

字段:
  cms       产品名（中英文混合，保留中文原名）
  method    "keyword"（子串匹配）或 "faviconhash"（mmh3 哈希）
  location  "body" / "header" / "title"（faviconhash 的 location 无实际语义）
  logic     "and"（全部命中）/ "or"（任一命中）
  rule      list[str]，keyword→待匹配子串；faviconhash→哈希字符串（可负）

转换策略:
  - method=keyword + location=body    → html pattern
  - method=keyword + location=header  → header pattern
  - method=keyword + location=title   → html pattern（title 是 body 子集）
  - method=faviconhash                → favicon_hash pattern（引擎已支持）
  - logic=and: 过滤宽泛后只取 1 条最显著（避免 OR 引擎误报放大）
  - logic=or:  全部保留
  - 同名 cms 多条规则聚合为 1 个规则（多 pattern）
  - category 由名称推断（中文 NAME_CATEGORY_HINTS 表）
  - 无 version 字段（hfinger 不提供版本信息）
"""
import json
import sys
from pathlib import Path

import requests

FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"
SOURCE_URL = "https://cdn.jsdelivr.net/gh/HackAllSec/hfinger@main/data/finger.json"

# 宽泛 pattern 黑名单（与 nuclei 导入器保持一致，额外补充中文常见噪声）
VAGUE_PATTERNS = {
    # 通用 HTML 标签
    "<html", "<body", "<head", "<div", "<span", "<meta", "<title",
    "<script", "<link", "<img", "<p>", "<br", "<h1", "<h2",
    # 通用 header 值
    "text/html", "text/plain", "application/json", "application/javascript",
    "content-type", "charset", "utf-8", "gzip", "keep-alive",
    "connection:", "server:", "date:", "cache-control",
    # 通用登录/首页词（中文产品常见但太宽泛）
    "login", "登录", "系统登录", "用户登录", "密码", "username", "password",
    "welcome", "首页", "index", "home", "main",
    # 纯通用 header 名
    "content-type", "server", "set-cookie", "x-powered-by", "location",
}


def _is_vague(pattern: str) -> bool:
    """判断 pattern 是否过于宽泛。"""
    pat = str(pattern).lower().strip()
    if not pat:
        return True
    # 太短（<4 字符）基本是噪声
    if len(pat) < 4:
        return True
    # 命中宽泛集合
    for v in VAGUE_PATTERNS:
        if pat == v:
            return True
    return False


# 中文产品名称 → category 推断表
# 按优先级排列（先匹配的优先），key 是名称包含的关键词
NAME_CATEGORY_HINTS = [
    # OA / 协同办公
    ("oa", "OA"), ("协同", "OA"), ("办公", "OA"), ("seeyon", "OA"),
    ("泛微", "OA"), ("通达oa", "OA"), ("蓝凌", "OA"), ("九思", "OA"),
    ("红帆", "OA"), ("微宏", "OA"), ("万户", "OA"), ("ezoffice", "OA"),
    ("慧点", "OA"), ("金和", "OA"),
    # ERP / 财务
    ("erp", "ERP"), ("用友", "ERP"), ("金蝶", "ERP"), ("nc cloud", "ERP"),
    ("畅捷", "ERP"), ("管家婆", "ERP"), ("广联达", "ERP"), ("明源", "ERP"),
    # CRM
    ("crm", "CRM"),
    # 安全设备
    ("防火墙", "网络安全设备"), ("vpn", "网络安全设备"), ("waf", "网络安全设备"),
    ("网关", "网络安全设备"), ("深信服", "网络安全设备"), ("sangfor", "网络安全设备"),
    ("天融信", "网络安全设备"), ("topsec", "网络安全设备"), ("启明", "网络安全设备"),
    ("网御", "网络安全设备"), ("绿盟", "网络安全设备"), ("nsfocus", "网络安全设备"),
    ("山石", "网络安全设备"), ("奇安信", "网络安全设备"), ("亿赛通", "网络安全设备"),
    ("护卫神", "网络安全设备"), ("安全狗", "网络安全设备"), ("网神", "网络安全设备"),
    ("堡垒机", "网络安全设备"),
    # 网络设备
    ("路由器", "网络设备"), ("交换机", "网络设备"), ("router", "网络设备"),
    ("switch", "网络设备"), ("锐捷", "网络设备"), ("h3c", "网络设备"),
    ("华为", "网络设备"), ("tp-link", "网络设备"), ("tenda", "网络设备"),
    ("cisco", "网络设备"), ("juniper", "网络设备"), ("飞鱼星", "网络设备"),
    # 监控 / IoT
    ("摄像头", "监控设备"), ("监控", "监控设备"), ("nvr", "监控设备"),
    ("ipc", "监控设备"), ("dvr", "监控设备"), ("海康", "监控设备"),
    ("hikvision", "监控设备"), ("大华", "监控设备"), ("dahua", "监控设备"),
    ("宇视", "监控设备"), ("ivms", "监控设备"),
    # Web 服务器面板
    ("宝塔", "Web服务器面板"), ("bt panel", "Web服务器面板"),
    ("1panel", "Web服务器面板"), ("amh", "Web服务器面板"),
    ("wdcp", "Web服务器面板"), ("cpanel", "Web服务器面板"),
    ("plesk", "Web服务器面板"), ("easypanel", "Web服务器面板"),
    # 邮件
    ("webmail", "邮件系统"), ("coremail", "邮件系统"), ("fangmail", "邮件系统"),
    ("richmail", "邮件系统"), ("exmail", "邮件系统"), ("turdomail", "邮件系统"),
    ("邮局", "邮件系统"), ("企业邮箱", "邮件系统"),
    # NAS
    ("nas", "NAS"), ("群晖", "NAS"), ("synology", "NAS"), ("qnap", "NAS"),
    # Server
    ("nginx", "Server"), ("apache", "Server"), ("tomcat", "Server"),
    ("iis", "Server"), ("weblogic", "Server"), ("jboss", "Server"),
    ("boa", "Server"), ("kangle", "Server"), ("litespeed", "Server"),
    ("openresty", "Server"), ("tengine", "Server"),
    # CMS
    ("wordpress", "CMS"), ("drupal", "CMS"), ("joomla", "CMS"),
    ("dedecms", "CMS"), ("织梦", "CMS"), ("帝国", "CMS"), ("empirecms", "CMS"),
    ("pbootcms", "CMS"), ("typecho", "CMS"), ("aspcms", "CMS"),
    ("taocms", "CMS"), ("zzzcms", "CMS"), ("铭飞", "CMS"),
    # Framework
    ("thinkphp", "Framework"), ("spring", "Framework"), ("yii", "Framework"),
    ("vue", "JS库"), ("react", "JS库"), ("angular", "JS库"),
    ("element", "JS库"), ("vite", "JS库"),
    # 监控（运维面板）
    ("kibana", "监控"), ("grafana", "监控"), ("zabbix", "监控"),
    ("prometheus", "监控"), ("netdata", "监控"), ("哪吒", "监控"),
    # CDN
    ("cdn", "CDN"), ("cloudflare", "CDN"), ("akamai", "CDN"),
]


def _infer_category(name: str) -> str:
    """从产品名推断 category。"""
    nl = name.lower()
    for keyword, cat in NAME_CATEGORY_HINTS:
        if keyword in nl:
            return cat
    return "Other"


def _pick_best_rule(rules: list[str]) -> str:
    """从多条 rule 里选最显著的一条（用于 logic=and 场景）。
    策略：优先含路径分隔符 / 或产品特征的，其次最长的。
    """
    scored = []
    for r in rules:
        score = 0
        # 路径特征（/xxx/）是强信号
        if "/" in r:
            score += 10
        # 含文件扩展名
        if any(r.lower().endswith(ext) for ext in (".css", ".js", ".png", ".ico", ".jpg")):
            score += 5
        # 含产品名特征字符
        if any(c in r for c in ("=", "?", "_", "-")):
            score += 2
        # 长度越长越独特
        score += min(len(r), 20)
        scored.append((score, r))
    scored.sort(reverse=True)
    return scored[0][1] if scored else ""


def convert_entry(entry: dict) -> tuple[str, list[dict]] | None:
    """转换单条 hfinger 规则为 (name, [patterns])。

    返回 None 表示该条无法转换（method 未知等）。
    """
    name = entry.get("cms", "").strip()
    if not name:
        return None

    method = entry.get("method", "").strip()
    location = entry.get("location", "body").strip()
    logic = entry.get("logic", "or").strip()
    rules = entry.get("rule", [])
    if isinstance(rules, str):
        rules = [rules]
    if not rules:
        return None

    patterns = []

    if method == "faviconhash":
        # favicon mmh3 哈希，精确匹配
        for h in rules:
            h = str(h).strip()
            if h:
                patterns.append({"type": "favicon_hash", "pattern": h})

    elif method == "keyword":
        # location → pattern type
        if location == "header":
            ptype = "header"
        else:
            # body 和 title 都映射到 html（title 是 body 子集）
            ptype = "html"

        if logic == "and":
            # AND 逻辑：OR 引擎下必须只取最显著一条，避免误报放大
            filtered = [r for r in rules if not _is_vague(str(r))]
            if not filtered:
                return None
            best = _pick_best_rule(filtered)
            if best:
                pat = best.lower() if ptype == "html" else best.lower()
                patterns.append({"type": ptype, "pattern": pat})
        else:
            # OR 逻辑：全部保留（过滤宽泛后）
            for r in rules:
                rs = str(r)
                if _is_vague(rs):
                    continue
                patterns.append({"type": ptype, "pattern": rs.lower()})

    else:
        # 未知 method，跳过
        return None

    if not patterns:
        return None

    # 限制每条规则最多 6 个 pattern
    patterns = patterns[:6]

    return name, patterns


def aggregate(entries: list[dict]) -> list[dict]:
    """将 hfinger 条目按 cms 名称聚合成 NetProbe 规则。
    同名 cms 的多条 entry 合并为一个规则（多 pattern，按 type+pattern 去重）。
    """
    by_name = {}  # name → {patterns: [(type,pattern)], order}
    order = []
    skipped = 0

    for entry in entries:
        result = convert_entry(entry)
        if result is None:
            skipped += 1
            continue
        name, patterns = result

        if name not in by_name:
            by_name[name] = []
            order.append(name)

        existing_pats = by_name[name]
        existing_keys = {(p["type"], p["pattern"]) for p in existing_pats}
        for p in patterns:
            k = (p["type"], p["pattern"])
            if k not in existing_keys:
                existing_pats.append(p)
                existing_keys.add(k)

    rules = []
    for name in order:
        pats = by_name[name][:6]  # 聚合后再限制一次
        if not pats:
            continue
        rules.append({
            "name": name,
            "category": _infer_category(name),
            "patterns": pats,
            "source": "hfinger",
        })

    return rules, skipped


def _fingerprint_key(rule: dict) -> str:
    """生成去重 key（与 nuclei 导入器一致）。"""
    name = rule["name"].lower()
    pats = rule.get("patterns", [])
    sig = ""
    for p in pats:
        if p["type"] in ("header", "favicon_hash"):
            sig = p["pattern"]
            break
    if not sig and pats:
        sig = pats[0]["pattern"]
    return f"{name}::{sig[:40]}"


def merge(existing: list[dict], new_rules: list[dict]) -> tuple[list[dict], dict]:
    """合并去重（与 nuclei 导入器逻辑一致）。
    - 完全相同 name+signature → 跳过
    - name 相同但 signature 不同 → 合并 patterns
    - 全新 name → 追加
    """
    existing_keys = {_fingerprint_key(r) for r in existing}
    name_index = {}
    for i, r in enumerate(existing):
        name_index.setdefault(r["name"].lower(), []).append(i)

    stats = {"added": 0, "merged": 0, "skipped": 0}
    for rule in new_rules:
        key = _fingerprint_key(rule)
        if key in existing_keys:
            stats["skipped"] += 1
            continue

        nl = rule["name"].lower()
        if nl in name_index:
            # 同名规则 → 合并 patterns
            for idx in name_index[nl]:
                target = existing[idx]
                existing_pats = {(p["type"], p["pattern"]) for p in target.get("patterns", [])}
                added_any = False
                for p in rule["patterns"]:
                    pk = (p["type"], p["pattern"])
                    if pk not in existing_pats:
                        # 控制总 pattern 数不超过 8
                        if len(target.get("patterns", [])) >= 8:
                            break
                        target.setdefault("patterns", []).append(p)
                        existing_pats.add(pk)
                        added_any = True
                if added_any:
                    stats["merged"] += 1
                else:
                    stats["skipped"] += 1
                existing_keys.add(key)
                break
        else:
            existing.append(rule)
            existing_keys.add(key)
            name_index.setdefault(nl, []).append(len(existing) - 1)
            stats["added"] += 1

    return existing, stats


def main():
    import argparse
    parser = argparse.ArgumentParser(description="导入 hfinger 中文指纹")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写入")
    args = parser.parse_args()

    print(f"指纹库路径: {FP_PATH}")
    existing = json.load(open(FP_PATH, encoding="utf-8"))
    print(f"现有规则: {len(existing)} 条")

    print(f"\n下载 hfinger 数据: {SOURCE_URL}")
    r = requests.get(SOURCE_URL, timeout=30)
    if r.status_code != 200:
        print(f"✗ 下载失败: {r.status_code}")
        sys.exit(1)
    data = r.json()
    entries = data.get("finger", []) if isinstance(data, dict) else data
    print(f"hfinger 条目: {len(entries)} 条")

    print("\n转换并聚合...")
    new_rules, skipped = aggregate(entries)
    print(f"  聚合为 {len(new_rules)} 条规则（跳过 {skipped} 条无效条目）")

    # 统计中文产品
    cn_rules = sum(1 for r in new_rules if any('\u4e00' <= c <= '\u9fff' for c in r["name"]))
    print(f"  中文产品规则: {cn_rules} 条")

    # pattern type 统计
    import collections
    tc = collections.Counter()
    for r in new_rules:
        for p in r["patterns"]:
            tc[p["type"]] += 1
    print(f"  pattern 类型: {dict(tc)}")

    print("\n合并去重...")
    merged, stats = merge(existing, new_rules)
    print(f"  新增: {stats['added']}")
    print(f"  增强现有: {stats['merged']}")
    print(f"  跳过重复: {stats['skipped']}")

    if args.dry_run:
        print(f"\n[dry-run] 合并后总计 {len(merged)} 条（未写入）")
    else:
        with open(FP_PATH, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)
        print(f"\n✓ 写入完成: {len(merged)} 条 → {FP_PATH}")

    # 分类统计
    cat = collections.Counter(r.get("category", "Other") for r in merged)
    print("\n合并后分类分布 Top 15:")
    for k, v in cat.most_common(15):
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
