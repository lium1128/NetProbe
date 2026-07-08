#!/usr/bin/env python3
"""从 FingerprintHub (0x727) 导入 Web 指纹规则（全量版）。

数据源: 0x727/FingerprintHub 的 web-fingerprint/*.yaml（约 3293 个文件）
下载: 通过 jsdelivr CDN 并发拉取（12 线程），绕开 GitHub API 限流。

FingerprintHub YAML 格式:
  id/name: 产品名
  http.matchers: word 匹配规则
  metadata.verified: 是否已验证

转换策略（相比旧版的改进）:
  - 去掉 800 条限制，全量处理 3293 个文件
  - 并发下载（12 线程）
  - 复用 nuclei 导入器的 merge() 逻辑（同名合并 patterns，而非简单跳过）
  - 宽泛 pattern 过滤（避免误报）
  - 加 source 字段溯源
"""
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

FP_PATH = Path(__file__).parent.parent / "netprobe" / "data" / "fingerprints.json"
API_TREE = ("https://api.github.com/repos/0x727/FingerprintHub"
            "/git/trees/main?recursive=1")
CDN_BASE = "https://cdn.jsdelivr.net/gh/0x727/FingerprintHub@main"

# 宽泛 pattern 黑名单（与 nuclei/hfinger 导入器一致）
VAGUE_PATTERNS = {
    "<html", "<body", "<head", "<div", "<span", "<meta", "<title",
    "<script", "<link", "<img", "<p>", "<br",
    "text/html", "text/plain", "application/json", "application/javascript",
    "content-type", "charset", "utf-8", "gzip", "keep-alive",
    "login", "登录", "welcome", "首页",
    "content-type", "server", "set-cookie", "x-powered-by",
}


def _is_vague(pattern: str) -> bool:
    pat = str(pattern).lower().strip()
    if not pat or len(pat) < 4:
        return True
    for v in VAGUE_PATTERNS:
        if pat == v:
            return True
    return False


def get_file_list() -> list[str]:
    """获取 web-fingerprint 目录下所有 yaml 文件相对路径。"""
    r = requests.get(API_TREE, timeout=30,
                     headers={"Accept": "application/vnd.github+json"})
    if r.status_code != 200:
        print(f"获取文件列表失败: {r.status_code}")
        return []
    data = r.json()
    files = [t["path"] for t in data.get("tree", [])
             if t["path"].startswith("web-fingerprint/")
             and t["path"].endswith(".yaml")
             and t["type"] == "blob"]
    return files


def download_yaml(rel_path: str) -> str:
    """通过 jsdelivr CDN 下载 yaml。"""
    url = f"{CDN_BASE}/{rel_path}"
    r = requests.get(url, timeout=20)
    return r.text if r.status_code == 200 else ""


def parse_yaml(text: str) -> dict:
    """简单解析 FingerprintHub YAML（正则提取关键字段）。"""
    result = {"name": "", "verified": False, "words": [], "headers": []}

    # name
    m = re.search(r"^info:\s*\n\s+name:\s*(.+)", text, re.MULTILINE)
    if m:
        result["name"] = m.group(1).strip().strip("'\"")

    if "verified: true" in text:
        result["verified"] = True

    # 提取 words（FingerprintHub 的 word 匹配默认是 response body 或 header）
    in_words = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "words:":
            in_words = True
            continue
        elif stripped.startswith(("type:", "method:", "path:", "regex:", "dsl:")):
            in_words = False
            continue
        if in_words:
            wm = re.match(r"^-\s+(.+)", stripped)
            if wm:
                word = wm.group(1).strip().strip("'\"")
                if word:
                    result["words"].append(word)

    return result


def convert(text: str) -> dict | None:
    """转换单个 YAML 为 NetProbe 指纹格式。"""
    parsed = parse_yaml(text)
    if not parsed["name"] or not parsed["words"]:
        return None

    patterns = []
    seen = set()
    for w in parsed["words"]:
        w = w.strip()
        if not w or _is_vague(w):
            continue
        wl = w.lower()
        k = ("html", wl)
        if k not in seen:
            seen.add(k)
            patterns.append({"type": "html", "pattern": wl})
        if len(patterns) >= 6:
            break

    if not patterns:
        return None

    return {
        "name": parsed["name"],
        "category": "Other",  # FingerprintHub 不分类
        "patterns": patterns,
        "source": "fingerprinthub",
        "verified": parsed["verified"],
    }


def _fingerprint_key(rule: dict) -> str:
    name = rule["name"].lower()
    pats = rule.get("patterns", [])
    sig = pats[0]["pattern"] if pats else ""
    return f"{name}::{sig[:40]}"


def merge(existing: list[dict], new_rules: list[dict]) -> tuple[list[dict], dict]:
    """合并去重（与 nuclei 导入器逻辑一致）。"""
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
            for idx in name_index[nl]:
                target = existing[idx]
                existing_pats = {(p["type"], p["pattern"]) for p in target.get("patterns", [])}
                added_any = False
                for p in rule["patterns"]:
                    pk = (p["type"], p["pattern"])
                    if pk not in existing_pats:
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
    parser = argparse.ArgumentParser(description="导入 FingerprintHub 指纹（全量）")
    parser.add_argument("--dry-run", action="store_true", help="只统计不写入")
    parser.add_argument("--limit", type=int, default=0, help="限制处理文件数（0=全部）")
    args = parser.parse_args()

    print(f"指纹库路径: {FP_PATH}")
    existing = json.load(open(FP_PATH, encoding="utf-8"))
    print(f"现有规则: {len(existing)} 条")

    print("\n获取 FingerprintHub 文件列表...")
    files = get_file_list()
    print(f"web-fingerprint 模板: {len(files)} 个")
    if args.limit:
        files = files[:args.limit]
        print(f"  (限制处理 {len(files)} 个)")

    print("\n下载并转换（并发 12 线程）...")
    new_rules = []
    failed = 0

    def _download_and_convert(rel):
        text = download_yaml(rel)
        if not text:
            return None
        return convert(text)

    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(_download_and_convert, rel): rel for rel in files}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                rule = fut.result()
            except Exception:
                rule = None
            if rule is None:
                failed += 1
            else:
                new_rules.append(rule)
            if done % 500 == 0:
                print(f"  进度 {done}/{len(files)}, 已转换 {len(new_rules)}, 失败 {failed}")

    print(f"\n转换完成: {len(new_rules)} 条新规则 (失败 {failed})")

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


if __name__ == "__main__":
    main()
