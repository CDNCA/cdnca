#!/usr/bin/env python3
"""公开 Bot/扫描器清单 → 官方系统层规则包（版本 1.0.0，默认动作 log，可由参数 action 改为拦截/挑战）+ 已知良性爬虫清单。

用法：gen_rulepacks.py <out-dir>
输入：~/.cache/cdnca-waf-datasets/seed/src（见 SOURCES.md）
输出（每个包一个 JSON，过 rulepackcheck 编译与冲突检查）：
  system-bot-bad-ua.json        waf_v2 nginx-ultimate-bad-bot-blocker 坏 UA（MIT，直接用）
  system-bot-scanner-ua.json    waf_v2 上表中的漏洞扫描器子集（MIT，直接用）
  system-bot-ai-crawler.json    waf_v2 ai.robots.txt AI 爬虫（MIT，直接用）
  system-cc-404-burst.json      cc_v2  单 IP 短时大量 404（自写；思路来源 bunkerweb badbehavior，AGPL-3.0）
  system-waf-sensitive-file.json waf_v2 备份/敏感文件探测（payloadbox directory-payload-list，MIT，直接用）
  system-waf-scheme-wrapper.json waf_v2 参数中的协议包装器（自写；思路来源 naxsi 核心规则，GPL-3.0）
  system-waf-traversal-probe.json waf_v2 参数中的目录穿越/系统文件探测（自写；思路来源 naxsi 核心规则，GPL-3.0）
  known-good-crawlers.json      arcjet well-known-bots（MIT）中可验证（rDNS/IP 段）的良性爬虫，
                                字段同 CCV2TrustedCrawler，另带 categories / network_sources 供后续拉取 IP 段

UA 包用 waf_v2 inspect user_agent contains：节点两侧都转小写比较（cdnca_waf.lua positive_match），即不区分
大小写；生成时清单项统一转小写去重。cc_v2 的 header contains 区分大小写，所以不用 cc_v2。
与常见浏览器 UA（BROWSER_UAS）子串相交的清单项丢弃（统计 dropped_browser）。

404 规则说明：cc_v2 没有“每次命中都记录”的算法（always 只配 challenge），status_404_count 只能配 fixed_window，
且 404 计数窗口就是 limit.window_seconds。fixed_window 判定 count>requests、requests 最小 1，所以同一 IP 在
一个 60 秒窗口内 404 达 10 次后，第 1 个请求只计数不记录，第 2 个起每次记录。
"""
import glob
import json
import os
import re
import sys

SRC = os.path.expanduser("~/.cache/cdnca-waf-datasets/seed/src")
MAX_VALUES = 64  # wafInspectMaxValues
VERSION = "1.0.0"
# 主流浏览器/客户端 UA（误报过滤）：坏 UA 清单项（小写）是其中任一的子串即丢弃。
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S9180) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.81 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; 23127PN0CC Build/UKQ1.230804.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/122.0.6261.120 Mobile Safari/537.36 XWEB/1220099 MMWEBSDK/20240404 MMWEBID/2390 MicroMessenger/8.0.49.2600(0x28003133) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64",
    "Mozilla/5.0 (Linux; Android 13; V2227A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36 VivoBrowser/20.1.0.0",
    "Mozilla/5.0 (Linux; U; Android 12; zh-cn; M2012K11AC Build/SKQ1.211006.001) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.127 Mobile Safari/537.36 XiaoMi/MiuiBrowser/17.8.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 QIHU 360SE",
    "Mozilla/5.0 (Linux; Android 10; HMA-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/99.0.4844.88 Mobile Safari/537.36 HuaweiBrowser/14.0.5.302",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
    "Mozilla/5.0 (Linux; Android 12; ALN-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 MQQBrowser/6.2 TBS/046805 Mobile Safari/537.36 QQ/9.0.65",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Core/1.116.454.400 QQBrowser/13.0.6022.400",
]
SCANNERS = {"acunetix", "dirbuster", "havij", "masscan", "nessus", "nikto", "nmap", "nuclei", "openvas", "sqlmap",
            "wpscan", "zmeu", "zgrab", "netsparker", "w3af", "arachni", "gobuster", "dirb", "ffuf", "jaeles",
            "whatweb", "wfuzz", "skipfish", "paros", "webinspect", "appscan", "qualys", "commix", "xsstrike",
            "nessus", "morfeus", "zeus", "jorgee", "fimap", "grabber", "httrack", "brutus", "hydra"}


def src(prefix):
    return glob.glob(os.path.join(SRC, prefix + "-*"))[0]


def literal(pattern):
    """正则清单项 → 字面子串；去掉转义后仍有元字符的返回 None。"""
    text = re.sub(r"\\([^A-Za-z0-9])", r"\1", pattern)
    if re.search(r"\\[A-Za-z0-9]|[\^$\[\]()|*+?{}]", pattern.replace("\\.", "").replace("\\ ", "").replace("\\-", "")
                 .replace("\\/", "").replace("\\_", "")):
        return None
    return text


def printable(value):
    return 0 < len(value) <= 1024 and all(" " <= ch <= "~" for ch in value)


def chunks(values, size=MAX_VALUES):
    values = sorted(set(values))
    return [values[i:i + size] for i in range(0, len(values), size)]


def ua_tokens(values):
    """清单项 → 小写去重；与浏览器 UA 相交的丢弃。返回 (保留, 丢弃)。"""
    browsers = [ua.lower() for ua in BROWSER_UAS]
    keep, drop = set(), set()
    for value in values:
        token = value.lower()
        (drop if any(token in ua for ua in browsers) else keep).add(token)
    return sorted(keep), sorted(drop)


def ua_log_rule(rid, name, tokens):
    return waf_log_rule(rid, name, [{"target": "user_agent", "operator": "contains", "values": tokens}])


def waf_log_rule(rid, name, inspect):
    return {"id": rid, "name": name, "waf": {"match": {"inspect": inspect}, "action": "log", "flow": "continue"}}


# 动作参数：包默认 log；启用后用户可改为拦截/挑战（libs/rulepack bind 目标 waf.action / cc.action.kind）。
ACTION_PARAMS = {
    "waf_v2": {"type": "string", "enum": ["log", "block", "challenge"], "bind": {"target": "waf.action", "rules": []}},
    "cc_v2": {"type": "string", "enum": ["log", "reject_429", "challenge"], "bind": {"target": "cc.action.kind", "rules": []}},
}


def pack(pack_id, engine, version, name, description, rules, license_spdx=None):
    doc = {"schema": "cdnca.rule-pack/v1", "pack_id": pack_id, "version": VERSION, "layer": "system",
           "engine": engine, "engine_min_version": version, "name": name, "description": description,
           "params_schema": {"action": ACTION_PARAMS[engine]}, "exports": sorted(r["id"] for r in rules), "rules": rules,
           "defaults": {"action": "log"}}
    if license_spdx:
        doc["license_spdx"] = license_spdx
    return doc


def bad_ua_packs():
    d = src("mitchellkrogza_nginx-ultimate-bad-bot-blocker")
    raw = [l.strip() for l in open(os.path.join(d, "_generator_lists/bad-user-agents.list"), errors="ignore") if l.strip()]
    tokens, skipped = [], []
    for item in raw:
        lit = literal(item)
        (tokens if lit and printable(lit) and len(lit) >= 3 else skipped).append(lit or item)
    scanners, scan_drop = ua_tokens(t for t in tokens if t.lower() in SCANNERS)
    others, other_drop = ua_tokens(t for t in tokens if t.lower() not in SCANNERS)
    others = sorted(set(others) - set(scanners))
    bad = [ua_log_rule("bad-ua-%02d" % i, "坏 UA 第 %d 组" % (i + 1), vals) for i, vals in enumerate(chunks(others))]
    scan = [ua_log_rule("scanner-ua-%02d" % i, "扫描器 UA 第 %d 组" % (i + 1), vals) for i, vals in enumerate(chunks(scanners))]
    src_note = "来源 mitchellkrogza/nginx-ultimate-bad-bot-blocker（MIT，Copyright (c) 2017 Mitchell Krog）_generator_lists/bad-user-agents.list"
    return [
        ("system-bot-bad-ua.json", pack("system/bot-bad-ua", "waf_v2", 1, "恶意 Bot UA",
                                        "UA 含已知恶意/采集 Bot 标识（不区分大小写子串）即记录，可改为拦截或挑战。" + src_note, bad, "MIT")),
        ("system-bot-scanner-ua.json", pack("system/bot-scanner-ua", "waf_v2", 1, "漏洞扫描器 UA",
                                            "UA 含已知漏洞扫描器标识（不区分大小写）即记录，可改为拦截或挑战。" + src_note, scan, "MIT")),
    ], {"bad_ua": len(others), "scanner_ua": len(scanners), "skipped_regex": len(skipped),
        "dropped_browser": other_drop + scan_drop}


def ai_crawler_pack():
    d = src("ai-robots-txt_ai.robots.txt")
    names, _ = ua_tokens(n for n in json.load(open(os.path.join(d, "robots.json"))) if printable(n) and len(n) >= 3)
    rules = [ua_log_rule("ai-crawler-%02d" % i, "AI 爬虫第 %d 组" % (i + 1), vals) for i, vals in enumerate(chunks(names))]
    return ("system-bot-ai-crawler.json", pack("system/bot-ai-crawler", "waf_v2", 1, "AI 爬虫",
            "UA 含 AI 训练/检索爬虫标识（不区分大小写）即记录，可改为拦截或挑战。来源 ai-robots-txt/ai.robots.txt（MIT）robots.json",
            rules, "MIT")), len(names)


def bad_behavior_pack():
    rule = {"id": "status-404-burst", "name": "单 IP 一分钟 10 次 404", "cc": {
        "rule_id": "", "priority": 0, "flow": "continue", "dimension": "client_ip",
        "match": {"status_404_count": 10},
        "limit": {"algorithm": "fixed_window", "requests": 1, "window_seconds": 60},
        "action": {"kind": "log"}}}
    return ("system-cc-404-burst.json", pack("system/cc-404-burst", "cc_v2", 3, "404 扫描行为",
            "同一 IP 60 秒内 404 达 10 次后记录其请求（达到后第 1 个请求只计数：fixed_window 判定超过 requests=1 才算命中，"
            "第 2 个起每次记录），可改为 429 拒绝或挑战。自有写法；思路来源 bunkerity/bunkerweb badbehavior（AGPL-3.0，未复制代码）", [rule]))


def sensitive_file_pack():
    d = src("payload-box_directory-payload-list")
    names = [l.strip().lstrip("/") for l in open(os.path.join(d, "Intruder/backup-sensitive.txt"), errors="ignore")]
    # 只取带扩展名或以点开头的文件名（目录名单独出现误报太高），统一小写后按路径后缀匹配
    files = sorted({"/" + n.lower() for n in names if n and printable(n) and " " not in n and
                    (n.startswith(".") or re.search(r"\.[a-z0-9]{1,5}$", n.lower()))})
    rules = [waf_log_rule("sensitive-file-%02d" % i, "敏感文件第 %d 组" % (i + 1),
                          [{"target": "path", "operator": "suffix", "values": vals, "filters": ["lowercase"]}])
             for i, vals in enumerate(chunks(files))]
    return ("system-waf-sensitive-file.json", pack("system/waf-sensitive-file", "waf_v2", 1, "备份/敏感文件探测",
            "路径以已知备份/配置/凭据文件名结尾即记录，可改为拦截或挑战。来源 payloadbox/directory-payload-list（MIT）Intruder/backup-sensitive.txt",
            rules, "MIT")), len(files)


def naxsi_idea_packs():
    wrappers = ["data://", "dict://", "expect://", "file://", "ftp://", "glob://", "gopher://", "jar:", "ldap://",
                "phar://", "php://", "zip://", "zlib://"]
    traversal = ["../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self/", "boot.ini", "c:\\windows", "win.ini"]
    note = "自有写法；思路来源 wargio/naxsi naxsi_core.rules（GPL-3.0，未复制规则文本）"
    w = waf_log_rule("scheme-wrapper", "参数含协议包装器",
                     [{"target": "args", "operator": "contains", "values": sorted(wrappers), "filters": ["unicode_decode", "lowercase"]}])
    t = waf_log_rule("traversal-probe", "参数含目录穿越/系统文件",
                     [{"target": "args", "operator": "contains", "values": sorted(traversal), "filters": ["unicode_decode", "lowercase"]}])
    return [
        ("system-waf-scheme-wrapper.json", pack("system/waf-scheme-wrapper", "waf_v2", 1, "参数协议包装器",
                                                "参数值含 php:// phar:// gopher:// 等包装器即记录。" + note, [w])),
        ("system-waf-traversal-probe.json", pack("system/waf-traversal-probe", "waf_v2", 1, "参数目录穿越探测",
                                                 "参数值含 ../ 或系统敏感文件路径即记录。" + note, [t])),
    ]


def good_crawlers():
    d = src("arcjet_well-known-bots")
    out, unverifiable = [], 0
    for bot in json.load(open(os.path.join(d, "well-known-bots.json"))):
        # CCV2TrustedCrawler token 不能含空格：取不含空格的最长片段
        lits = [max(t.split(" "), key=len) for t in (literal(p) for p in bot["pattern"]["accepted"]) if t and printable(t)]
        tokens = sorted({t for t in lits if len(t) >= 3})
        suffixes, networks, net_sources = set(), set(), []
        for v in bot.get("verification", []):
            if v["type"] == "dns":
                for mask in v.get("masks", []):
                    tail = mask.rsplit("*", 1)[-1].lstrip(".-")
                    if tail.count(".") >= 1 and re.fullmatch(r"[a-z0-9.-]+", tail):
                        suffixes.add(tail)
            elif v["type"] in ("ip", "cidr"):
                networks.update(ip if "/" in ip else ip + ("/128" if ":" in ip else "/32") for ip in v.get("ips", []))
                net_sources += [s["url"] for s in v.get("sources", []) if "url" in s]
        if not tokens or not (suffixes or networks or net_sources):
            unverifiable += 1
            continue
        entry = {"name": bot["id"].lower(), "categories": bot.get("categories", []), "user_agent_tokens": tokens[:16]}
        if networks:
            entry["networks"] = sorted(networks)[:256]
        if suffixes:
            entry["rdns_suffixes"] = sorted(suffixes)[:16]
        if net_sources:
            entry["network_sources"] = sorted(set(net_sources))
        out.append(entry)
    out.sort(key=lambda e: e["name"])
    return out, unverifiable


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    packs, stats = bad_ua_packs()
    ai, stats["ai_crawler"] = ai_crawler_pack()
    sens, stats["sensitive_file"] = sensitive_file_pack()
    packs += [ai, bad_behavior_pack(), sens] + naxsi_idea_packs()
    for name, doc in packs:
        with open(os.path.join(out, name), "w") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
        stats[name] = len(doc["rules"])
    crawlers, stats["crawler_unverifiable"] = good_crawlers()
    stats["known_good_crawlers"] = len(crawlers)
    with open(os.path.join(out, "known-good-crawlers.json"), "w") as f:
        json.dump({"source": "arcjet/well-known-bots（MIT）", "crawlers": crawlers}, f, ensure_ascii=False, indent=1)
    print(json.dumps(stats, ensure_ascii=False))


if __name__ == "__main__":
    main()
