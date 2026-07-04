#!/usr/bin/env python3
"""Wappalyzer 指纹导入器 — 将 Wappalyzer technologies 数据转换为 NetProbe 指纹格式。

用法:
    python scripts/import_wappalyzer.py            # 从网络下载并合并
    python scripts/import_wappalyzer.py --file a.json b.json  # 从本地文件导入
    python scripts/import_wappalyzer.py --dry-run  # 只统计不写入

数据源（按优先级尝试）:
    1. 本地 --file 指定的文件
    2. projectdiscovery/wappalyzergo 镜像（Go 友好格式）
    3. wappalyzer 官方按字母分文件（a.json~z.json）

转换规则:
    Wappalyzer: {技术名: {cats:[1], headers:{K:V}, html:[""], scriptSrc:[""], cookies:{}, meta:{}}}
    NetProbe:   {name, category, patterns:[{type, pattern}]}
    category 映射: cats ID → NetProbe category 名（见 CATEGORY_MAP）
"""

import argparse
import json
import sys
from pathlib import Path

# Wappalyzer category ID → NetProbe category 名
# 完整列表见 https://github.com/wappalyzer/wappalyzer/blob/master/src/categories.json
CATEGORY_MAP = {
    1: "CMS", 2: "Forum", 3: "Database", 6: "Ecommerce", 11: "Blog",
    12: "Framework", 14: "JS库", 15: "CSS框架", 16: "Runtime",
    17: "Server", 18: "CDN", 19: "Analytics", 20: "OA", 22: "Web服务器面板",
    25: "Javascript框架", 26: "JavaScript图形库", 27: "WAF",
    30: "Web服务器面板", 31: "Build", 41: "LMS",
}

# 数据源 URL（按优先级）
SOURCES = [
    # projectdiscovery 镜像（Go 格式，含 technologies + categories）
    "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/master/wappalyzer.json",
    # Wappalyzer 官方按字母分文件（需循环 a-z）
    "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/technologies/{letter}.json",
]

# NetProbe 指纹库路径
FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"


def load_existing() -> list[dict]:
    """加载现有 NetProbe 指纹库。"""
    if FP_PATH.exists():
        with open(FP_PATH, encoding="utf-8") as f:
            return json.load(f)
    return []


def fetch_wappalyzer(urls: list[str] = None) -> dict:
    """从网络下载 Wappalyzer 技术数据。返回 {技术名: {...}} 字典。"""
    import requests

    sources = urls or SOURCES
    all_techs = {}

    for url in sources:
        try:
            if "{letter}" in url:
                # 按字母循环
                for letter in "abcdefghijklmnopqrstuvwxyz":
                    try:
                        r = requests.get(url.format(letter=letter), timeout=15)
                        if r.status_code == 200:
                            data = r.json()
                            all_techs.update(data)
                            print(f"  ✓ {letter}.json: +{len(data)} 条")
                    except (requests.RequestException, json.JSONDecodeError):
                        continue
                if all_techs:
                    return all_techs
            else:
                r = requests.get(url, timeout=15)
                if r.status_code == 200:
                    data = r.json()
                    # projectdiscovery 格式: {technologies: {...}}
                    techs = data.get("technologies", data) if isinstance(data, dict) else data
                    if isinstance(techs, dict):
                        print(f"  ✓ {url.split('/')[-1]}: +{len(techs)} 条")
                        return techs
        except Exception as e:
            print(f"  ✗ {url}: {type(e).__name__}")
            continue

    return all_techs


def convert_tech(name: str, spec: dict) -> dict | None:
    """转换单条 Wappalyzer 技术为 NetProbe 指纹格式。

    spec 结构: {cats:[1], headers:{K:V}, html:[""], scriptSrc:[""], cookies:{K:V}, meta:{K:V}, implies:[...]}
    """
    patterns = []

    # headers → header pattern
    headers = spec.get("headers", {})
    if isinstance(headers, dict):
        for hk, hv in headers.items():
            if isinstance(hv, str) and hv:
                # Wappalyzer 的 header value 可能是字符串、通配或正则
                combined = f"{hk}: {hv}" if hv not in ("", "*") else hk
                patterns.append({"type": "header", "pattern": f"re:{_to_regex(combined)}"})

    # html → html pattern
    htmls = spec.get("html", [])
    if isinstance(htmls, str):
        htmls = [htmls]
    for h in htmls:
        if h:
            patterns.append({"type": "html", "pattern": f"re:{_to_regex(h)}"})

    # scriptSrc → script_src pattern
    scripts = spec.get("scriptSrc", [])
    if isinstance(scripts, str):
        scripts = [scripts]
    for s in scripts:
        if s:
            patterns.append({"type": "script_src", "pattern": f"re:{_to_regex(s)}"})

    # cookies → cookie pattern
    cookies = spec.get("cookies", {})
    if isinstance(cookies, dict):
        for ck, cv in cookies.items():
            if cv and isinstance(cv, str):
                patterns.append({"type": "cookie", "pattern": f"re:{_to_regex(cv)}"})
            elif ck:
                patterns.append({"type": "cookie", "pattern": ck.lower()})

    # meta → meta pattern
    metas = spec.get("meta", {})
    if isinstance(metas, dict):
        for mk, mv in metas.items():
            if mv and isinstance(mv, str):
                patterns.append({"type": "meta", "pattern": f"re:{_to_regex(mv)}"})

    if not patterns:
        return None

    # 类别：取第一个能映射的 cat
    category = "Other"
    for cat_id in spec.get("cats", []):
        if cat_id in CATEGORY_MAP:
            category = CATEGORY_MAP[cat_id]
            break

    return {"name": name, "category": category, "patterns": patterns}


def _to_regex(pattern: str) -> str:
    """Wappalyzer 的字符串可能是普通匹配或正则。
    简单策略：如果含特殊正则字符且看起来像正则就原样用，否则转义。
    Wappalyzer 用 \\\\; 分隔多版本，去掉。
    """
    if not pattern:
        return ""
    # 去掉 Wappalyzer 的版本分隔
    pattern = pattern.split("\\;")[0]
    return pattern


def merge(existing: list[dict], new_techs: dict) -> list[dict]:
    """合并：按 name 去重，新规则追加，已存在的 name 跳过（保留现有规则优先）。"""
    existing_names = {fp["name"].lower() for fp in existing}
    added = 0
    for name, spec in new_techs.items():
        if name.lower() in existing_names:
            continue
        converted = convert_tech(name, spec)
        if converted:
            existing.append(converted)
            existing_names.add(name.lower())
            added += 1
    print(f"  新增 {added} 条（跳过 {len(new_techs) - added} 条已存在/无 pattern）")
    return existing


def main():
    parser = argparse.ArgumentParser(description="导入 Wappalyzer 指纹到 NetProbe")
    parser.add_argument("--file", nargs="+", help="从本地 JSON 文件导入（可多个）")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写入")
    parser.add_argument("--url", help="自定义数据源 URL")
    args = parser.parse_args()

    print(f"现有指纹库: {FP_PATH}")
    existing = load_existing()
    print(f"  当前 {len(existing)} 条")

    new_techs = {}
    if args.file:
        # 本地文件导入
        for fp in args.file:
            try:
                with open(fp, encoding="utf-8") as f:
                    data = json.load(f)
                techs = data.get("technologies", data) if isinstance(data, dict) else data
                new_techs.update(techs)
                print(f"  ✓ {fp}: +{len(techs)} 条")
            except Exception as e:
                print(f"  ✗ {fp}: {e}")
    else:
        # 网络下载
        urls = [args.url] if args.url else None
        print("从网络下载 Wappalyzer 数据...")
        new_techs = fetch_wappalyzer(urls)

    if not new_techs:
        print("✗ 未获取到任何技术数据")
        sys.exit(1)

    print(f"\n转换并合并 {len(new_techs)} 条 Wappalyzer 技术...")
    merged = merge(existing, new_techs)

    if args.dry_run:
        print(f"\n[dry-run] 合并后总计 {len(merged)} 条（未写入）")
    else:
        with open(FP_PATH, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)
        print(f"\n✓ 写入完成: {len(merged)} 条 → {FP_PATH}")


if __name__ == "__main__":
    main()
