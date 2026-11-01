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
import socket
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
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
    # safe 里带 ':' —— 有的源地址是代理形式（路径里嵌了完整的 https:// 目标地址，如 Jsnzkpg），冒号被编码后代理会返回错误页
    return urlunsplit((parts.scheme, netloc, quote(parts.path, safe="/@:"), quote(parts.query, safe="=&?/%"), parts.fragment))


# 直播清理（2026-11-01 全量实测后定）：列表已 404/403/530、坏地址、本机地址、重复测试版 → 剔除
LIVE_DENYLIST = {
    "https://tv.tmxk.kdns.fr/yplrnuc7",  # Gather「果」列表 404
    "https://gh.927223.xyz/https://raw.githubusercontent.com/Kimentanm/aptv/master/m3u/iptv.m3u",  # 代理 403
    "https://gh.927223.xyz/https://raw.githubusercontent.com/develop202/migu_video/refs/heads/main/interface.txt",  # 代理 403
    "https://down.nigx.cn/raw.githubusercontent.com/Kimentanm/aptv/master/m3u/iptv.m3u",  # 代理 403
    "https://la1.wqwqwq.sbs/tv.m3u",  # 530 源站失效
    "https://m3u.002397.xyz/all.m3u",  # 530
    "https://m3u.002397.xyz/o_all.m3u",  # 530
    "http://home.jundie.top:81/Cat/tv/live.txt",  # 404
    "http://我不是.肥猫.live/TV/tvzb.txt",  # 404
    "https://cdn.jsdelivr.net/gh/liu673cn/box@main/lib/tv/ipv6.m3u",  # 404
    "https://https://raw.githubusercontent.com/YanG-1989/m3u/main/Gather.m3u",  # 双 scheme 坏地址且内容已失效
    "https://clun.top/lib/iptv_test.m3u",  # cluntop 的测试版，与正版重复
    "https://epg.pw/test_channels.m3u",  # 抽测 8/8 频道超时
}

# 直播排序（2026-11-01 实测质量：综合台优先、抽测存活率高的在前，V6-only 垫底）；不在表中的排其后保持原序
LIVE_RANK = [
    "https://raw.githubusercontent.com/Guovin/iptv-api/gd/output/result.m3u",
    "https://clun.top/lib/iptv.m3u",
    "https://raw.githubusercontent.com/suxuang/myIPTV/main/ipv4.m3u",
    "http://193.123.86.190:14888/TV/iptv.php",
    "https://raw.githubusercontent.com/mlzlzj/TV/main/output/result.m3u",
    "https://cdn.jsdelivr.net/gh/liu673cn/box@main/libs/tv/tvlive.txt",
    "https://raw.githubusercontent.com/Kimentanm/aptv/master/m3u/iptv.m3u",
    "https://sub.ottiptv.cc/huyayqk.m3u",
    "https://sub.ottiptv.cc/douyuyqk.m3u",
    "https://sub.ottiptv.cc/bililive.m3u",
    "https://sub.ottiptv.cc/yylunbo.m3u",
    "https://mgtv.ottiptv.cc/mglist.m3u",
    "https://raw.githubusercontent.com/gambiarras/legal-iptv/refs/heads/main/playlist.m3u",
    "https://develop202.github.io/migu_video/interface.txt",
    "https://nos.netease.com/ysf/3d75a78a0fc7ede372c03598d6d10367.m3u",
    "https://cdn.jsdelivr.net/gh/qist/tvbox@master/tvboxtv.txt",
]


def fix_jar_url(url: str) -> str:
    """jsDelivr 拒绝分发 .jar（返回 403 Forbidden），把其 gh 形式的 jar 地址改走 raw.githubusercontent。"""
    m = re.match(r"https://cdn\.jsdelivr\.net/gh/([^/]+)/([^/@]+)@([^/]+)/(.+)$", url)
    if m and ".jar" in url:
        owner, repo, branch, path = m.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    return url


# ---- “2423”型加密配置解密（Jsnzkpg 等源在用）：全文 hex，解码后形如
# $#<key>#$<AES-128-CBC 密文><13 字符 IV 串>；key/IV 都补 '0' 到 16 字节。
# 算法与 FongMi 系 App 内置解密一致（开源实现可查），下面是纯标准库的 AES-128 解密。
_AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_AES_INV_SBOX = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_v] = _i
_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _aes128_round_keys(key: bytes):
    w = list(key)
    for i in range(4, 44):
        t = w[4 * (i - 1):4 * i]
        if i % 4 == 0:
            t = [_AES_SBOX[t[1]] ^ _AES_RCON[i // 4 - 1], _AES_SBOX[t[2]], _AES_SBOX[t[3]], _AES_SBOX[t[0]]]
        w.extend(w[4 * (i - 4) + j] ^ t[j] for j in range(4))
    return [bytes(w[16 * r:16 * r + 16]) for r in range(11)]


def _aes128_decrypt_block(rks, block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, rks[10])]
    for rnd in range(9, 0, -1):
        # InvShiftRows + InvSubBytes（状态按列主序：s[r + 4c]）
        t = [0] * 16
        for r in range(4):
            for c in range(4):
                t[r + 4 * c] = _AES_INV_SBOX[s[r + 4 * ((c - r) % 4)]]
        s = [b ^ k for b, k in zip(t, rks[rnd])]
        # InvMixColumns
        t = [0] * 16
        for c in range(4):
            a = s[4 * c:4 * c + 4]
            t[4 * c + 0] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
            t[4 * c + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
            t[4 * c + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
            t[4 * c + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)
        s = t
    t = [0] * 16
    for r in range(4):
        for c in range(4):
            t[r + 4 * c] = _AES_INV_SBOX[s[r + 4 * ((c - r) % 4)]]
    return bytes(b ^ k for b, k in zip(t, rks[0]))


def _aes128_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    rks = _aes128_round_keys(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        block = ct[i:i + 16]
        dec = _aes128_decrypt_block(rks, block)
        out.extend(b ^ p for b, p in zip(dec, prev))
        prev = block
    return bytes(out)


def decrypt_2423(raw: str) -> str:
    """解开 “2423” 型加密配置，返回明文 JSON 文本。"""
    data = re.sub(r"\s+", "", raw)
    decoded = bytes.fromhex(data).decode("utf-8", errors="replace").lower()
    key_str = decoded[decoded.index("$#") + 2:decoded.index("#$")]
    iv_str = decoded[-13:]
    pad16 = lambda s: (s + "0" * (16 - len(s))).encode("utf-8")
    ct = bytes.fromhex(data[data.index("2324") + 4:len(data) - 26])
    pt = _aes128_cbc_decrypt(pad16(key_str), pad16(iv_str), ct)
    if pt and 0 < pt[-1] <= 16:
        pt = pt[:-pt[-1]]
    return pt.decode("utf-8")


def fetch_json(url: str):
    req = urllib.request.Request(normalize_url(url), headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        raw = r.read().decode("utf-8", errors="replace")
    raw = raw.lstrip("\ufeff").strip()
    if re.sub(r"\s+", "", raw).startswith("2423"):
        # 加密配置：先解密再走正常解析
        raw = decrypt_2423(raw)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # 个别源带 // 注释，去掉后重试
        cleaned = re.sub(r"(?m)^\s*//.*$", "", raw)
        return json.loads(cleaned)


# ---- 站点探活剪枝（2026-11-01 为“源太多加载慢”加）----
# 只处理能直接探的站点：CMS 接口（type 0/1 的 http api）、py/js 规则文件、
# csp 站 ext 里的第一个 URL。探不到的（纯 csp 无 ext URL）一律保留不动。
# 两轮探测都失败才定性：硬死（连接拒绝/DNS 失败/404/410/5xx）→ 删除；
# 软死（超时/连接被断开）→ 保留但 searchable=0，不再拖慢全网搜索。
# 沙箱出口与用户家庭网络的可达性可能不同，所以标准卡得很严，且每次合并
# 都重新探——站点恢复了下一轮自动回来。探活整体出错时跳过剪枝，不影响合并。

def _probe_once(url: str):
    """返回 (alive: bool, hard: bool)。hard=True 表示失败属于硬失败。"""
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=6) as r:
            r.read(256)
            return (r.status < 500), (r.status >= 500)
    except urllib.error.HTTPError as e:
        if e.code in (404, 410) or e.code >= 500:
            return False, True
        return True, False  # 401/403 等说明服务器活着
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, (ConnectionRefusedError, socket.gaierror)):
            return False, True
        return False, False  # 超时/断开等软失败
    except Exception:
        return False, False


def _site_probe_url(site):
    api = str(site.get("api", ""))
    if api.startswith("http") and (api.endswith(".py") or api.endswith(".js")):
        return api
    if site.get("type") in (0, 1) and api.startswith("http"):
        return api
    if api.startswith("csp_"):
        ext = site.get("ext")
        if ext is not None:
            m = re.search(r"https?://[^\s\"'\\]+", json.dumps(ext, ensure_ascii=False))
            if m:
                return m.group(0)
    return None


def apply_liveness(sites):
    """对 sites 原地剪枝，返回 (删掉数, 降级搜索数)。"""
    targets = {}
    for i, s in enumerate(sites):
        u = _site_probe_url(s)
        if u:
            targets[i] = u
    if not targets:
        return 0, 0

    def probe_round(indices):
        result = {}
        with ThreadPoolExecutor(max_workers=40) as ex:
            futs = {ex.submit(_probe_once, targets[i]): i for i in indices}
            for fut, i in futs.items():
                result[i] = fut.result()
        return result

    first = probe_round(list(targets))
    failed = [i for i, (alive, _h) in first.items() if not alive]
    second = probe_round(failed) if failed else {}

    drop, demote = set(), set()
    for i in failed:
        alive2, hard2 = second.get(i, (False, False))
        if alive2:
            continue
        _alive1, hard1 = first[i]
        if hard1 and hard2:
            drop.add(i)
        else:
            demote.add(i)

    kept = []
    for i, s in enumerate(sites):
        if i in drop:
            continue
        if i in demote:
            s = dict(s)
            s["searchable"] = 0
        kept.append(s)
    sites[:] = kept
    return len(drop), len(demote)


def main() -> int:
    sources = json.loads((HERE / "sources.json").read_text(encoding="utf-8"))
    fetched = []  # (name, cfg)
    for s in sources:
        try:
            cfg = fetch_json(s["url"])
            if isinstance(cfg, dict) and cfg.get("spider"):
                # 相对 spider（如 ./x.jar）按源地址补成绝对地址，否则合并后在新地址下会解析错位置
                cfg["spider"] = fix_jar_url(urljoin(normalize_url(s["url"]), cfg["spider"]))
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
    absolutized = 0
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
            api = str(site.get("api", ""))
            if api and not api.startswith(("http://", "https://", "csp_")):
                # 相对 api（如 ./libs/drpy2.min.js）按来源地址补成绝对地址，
                # 否则合并后会相对聚合配置的地址解析，基本等于失效
                new_api = urljoin(normalize_url(src_url), api)
                if new_api != api:
                    site["api"] = new_api
                    absolutized += 1
            if site.get("jar") and not str(site["jar"]).startswith("http"):
                # 站点自带的相对 jar 按其来源地址补成绝对地址
                site["jar"] = urljoin(normalize_url(src_url), str(site["jar"]))
            if src_spider and src_spider != spider and not site.get("jar"):
                site["jar"] = src_spider
            if site.get("jar"):
                site["jar"] = fix_jar_url(str(site["jar"]))
            sites.append(site)
        for live in cfg.get("lives", []):
            if not isinstance(live, dict) or not live.get("url"):
                continue
            live = dict(live)
            raw_url = str(live["url"])
            # 相对直播地址（如 ./lib/iptv.m3u）按来源补成绝对地址，否则在新托管地址下解析错位
            if not raw_url.startswith("http"):
                raw_url = urljoin(normalize_url(src_url), raw_url)
            if not raw_url.startswith(("http://", "https://")):
                continue
            # 末段是整段 base64 的伪地址（金鹰源的 live 编码形式），壳不会解码，剔除
            if re.fullmatch(r"[A-Za-z0-9+/=]{40,}", raw_url.rsplit("/", 1)[-1]):
                continue
            if "127.0.0.1" in raw_url or "localhost" in raw_url:
                continue
            if raw_url in LIVE_DENYLIST:
                continue
            live["url"] = raw_url
            sig = (live.get("name", ""), raw_url)
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

    # 精确去重：key 已去重过，这里再按 (type, api, ext) 去掉内容完全相同的站
    seen_triples = set()
    deduped = []
    dup_removed = 0
    for s in sites:
        sig = (s.get("type"), str(s.get("api", "")),
               json.dumps(s.get("ext"), ensure_ascii=False, sort_keys=True) if s.get("ext") is not None else "")
        if sig in seen_triples:
            dup_removed += 1
            continue
        seen_triples.add(sig)
        deduped.append(s)
    sites = deduped
    try:
        dropped, demoted = apply_liveness(sites)
    except Exception as e:
        dropped, demoted = 0, 0
        print(f"[prune] 探活异常，跳过剪枝：{e}")
    print(f"[prune] 相对 api 绝对化 {absolutized} 个；精确重复删除 {dup_removed} 个；硬死站删除 {dropped} 个；软死站降级搜索 {demoted} 个")

    rank_of = {u: i for i, u in enumerate(LIVE_RANK)}
    lives.sort(key=lambda lv: (0, rank_of[lv["url"]]) if lv["url"] in rank_of else (1, 0))

    # 壁纸：用户指定用高天流云的（2026-11-01，实测直出 image/jpeg）
    out = {"wallpaper": "https://wallpapers.gaoops.top/other", "spider": spider, "sites": sites, "lives": lives, "parses": parses}
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
