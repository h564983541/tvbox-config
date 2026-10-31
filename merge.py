#!/usr/bin/env python3
"""静态合并 TVBox 源：抓取 sources.json 里的每个源配置，合并成一份 config.json。

合并规则（对齐 Worker 聚合器的核心行为，简化版）：
- sites 按 key 去重，先到先得；缺 key/name/api 的丢弃
- 顶层 spider 取站点数最多源的 spider；其他源的站点若没自带 jar，补上其来源的 spider 作为 jar
- lives 按 (name, url) 去重；parses 按 (name, url) 去重
- flags/ads 取并集；i jk 取第一个带该字段的源
输出写入脚本同目录的 config.json，并打印统计。
"""
import json
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def normalize_url(url: str) -> str:
    """把含中文等非 ASCII 的 URL 转成可请求的形式（主机名 IDNA、路径百分号编码）。"""
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except Exception:
        host_ascii = host
    netloc = host_ascii
    if parts.port:
        netloc += f":{parts.port}"
    if parts.username:
        userinfo = parts.username
        if parts.password:
            userinfo += f":{parts.password}"
        netloc = f"{userinfo}@{netloc}"
    return urlunsplit((parts.scheme, netloc, quote(parts.path, safe="/@"), quote(parts.query, safe="=&?/%"), parts.fragment))


def fetch_json(url: str):
    req = urllib.request.Request(normalize_url(url), headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        raw = r.read().decode("utf-8", errors="replace")
    raw = raw.lstrip("\ufeff").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # 个别源带 // 注释，去掉后重试
        cleaned = re.sub(r"(?m)^\s*//.*$", "", raw)
        return json.loads(cleaned)


def main() -> int:
    sources = json.loads((HERE / "sources.json").read_text(encoding="utf-8"))
    fetched = []  # (name, cfg)
    for s in sources:
        try:
            cfg = fetch_json(s["url"])
            if isinstance(cfg, dict) and cfg.get("spider"):
                # 相对 spider（如 ./x.jar）按源地址补成绝对地址，否则合并后在新地址下会解析错位置
                cfg["spider"] = urljoin(normalize_url(s["url"]), cfg["spider"])
            if not isinstance(cfg, dict) or not isinstance(cfg.get("sites"), list):
                print(f"[skip] {s['name']}: 不是有效配置（无 sites）")
                continue
            fetched.append((s["name"], s["url"], cfg))
            print(f"[ok] {s['name']}: sites={len(cfg.get('sites', []))} lives={len(cfg.get('lives', []))} parses={len(cfg.get('parses', []))}")
        except Exception as e:
            print(f"[fail] {s['name']}: {e}")
    if not fetched:
        print("没有任何源抓取成功，放弃写出")
        return 1

    # 顶层 spider：站点数最多的源
    primary_name, _primary_url, primary_cfg = max(fetched, key=lambda t: len(t[2].get("sites", [])))
    spider = primary_cfg.get("spider") or ""
    print(f"主 spider 来自：{primary_name}")

    sites, seen_keys = [], set()
    lives, seen_lives = [], set()
    parses, seen_parses = [], set()
    flags, ads = [], []
    ijk = None
    for name, src_url, cfg in fetched:
        src_spider = cfg.get("spider") or ""
        for site in cfg.get("sites", []):
            if not isinstance(site, dict):
                continue
            key = site.get("key")
            if not key or not site.get("name") or not site.get("api"):
                continue
            if key in seen_keys:
                continue
            seen_keys.add(key)
            site = dict(site)
            if site.get("jar") and not str(site["jar"]).startswith("http"):
                # 站点自带的相对 jar 按其来源地址补成绝对地址
                site["jar"] = urljoin(normalize_url(src_url), str(site["jar"]))
            if src_spider and src_spider != spider and not site.get("jar"):
                site["jar"] = src_spider
            sites.append(site)
        for live in cfg.get("lives", []):
            if not isinstance(live, dict) or not live.get("url"):
                continue
            sig = (live.get("name", ""), live["url"])
            if sig in seen_lives:
                continue
            seen_lives.add(sig)
            lives.append(live)
        for p in cfg.get("parses", []):
            if not isinstance(p, dict) or not p.get("url"):
                continue
            sig = (p.get("name", ""), p["url"])
            if sig in seen_parses:
                continue
            seen_parses.add(sig)
            parses.append(p)
        for f in cfg.get("flags", []) or []:
            if f not in flags:
                flags.append(f)
        for a in cfg.get("ads", []) or []:
            if a not in ads:
                ads.append(a)
        if ijk is None and cfg.get("ijk"):
            ijk = cfg["ijk"]

    out = {"spider": spider, "sites": sites, "lives": lives, "parses": parses}
    if flags:
        out["flags"] = flags
    if ijk:
        out["ijk"] = ijk
    if ads:
        out["ads"] = ads

    target = HERE / "config.json"
    target.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    print(f"写出 {target}：sites={len(sites)} lives={len(lives)} parses={len(parses)} 大小={target.stat().st_size} 字节")
    return 0


if __name__ == "__main__":
    sys.exit(main())
