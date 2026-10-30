#!/usr/bin/env python3
"""生成 libs/edgeconfig/crawlerdefaults/default.json（良性爬虫默认 trusted_crawlers）。

输入 rulepacks/known-good-crawlers.json（gen_rulepacks.py 产物）+ 原前端 4 个预设（baidu/bing/google/sogou）。
- cloudflare-* 不进默认清单（信任 Cloudflare 全网段等于信任所有经 Cloudflare 的 UA 声明）。
- 只收搜索/AI/广告/预览/社交/归档类；类别全在 monitor/webhook/tool/optimizer 内的（监控、回调、扫描工具）
  只对用到它们的站点有意义，不进默认清单，站点自行添加。
- 同一厂商（OWNER 表，否则按校验条件相同）合并为一条：UA token、networks、rDNS 后缀、来源取并集
  （同厂商的不同爬虫互相冒用不构成风险），使清单 ≤ 32（CC trusted_crawlers 上限）。
- 每条带 sources（官方 IP 段地址及格式），授权端每日拉取后并入 networks；无 networks 且无 rDNS 的条目在拉到段之前不生效。
用法：python3 gen_default_crawlers.py rulepacks/known-good-crawlers.json ../../../libs/edgeconfig/crawlerdefaults/default.json
"""
import json, sys

PRESETS = [
    {"name": "baidu", "categories": ["search-engine"], "user_agent_tokens": ["Baiduspider"], "rdns_suffixes": ["baidu.com", "baidu.jp"]},
    {"name": "bing", "categories": ["search-engine"], "user_agent_tokens": ["bingbot"], "rdns_suffixes": ["search.msn.com"]},
    {"name": "sogou", "categories": ["search-engine"], "user_agent_tokens": ["Sogou"], "rdns_suffixes": ["sogou.com"]},
]
# 非 JSON 通用遍历的来源：格式与筛选。
SOURCE_FORMAT = {
    "https://www.facebook.com/peering/geofeed": {"format": "csv"},
    "https://core.telegram.org/resources/cidr.txt": {"format": "text"},
    "https://sentry.io/api/0/uptime-ips/": {"format": "text"},
    "https://uptimerobot.com/inc/files/ips/IPv4.txt": {"format": "text"},
    "https://uptimerobot.com/inc/files/ips/IPv6.txt": {"format": "text"},
    "https://api.github.com/meta": {"format": "json", "only_key": "hooks"},
    "https://ip-ranges.amazonaws.com/ip-ranges.json": {"format": "json", "where_field": "service", "where_value": "ROUTE53_HEALTHCHECKS"},
}
NOT_DEFAULT = {"monitor", "webhook", "tool", "optimizer"}
VENDOR_TAGS = {"amazon", "apple", "google", "meta", "microsoft"}
# 爬虫名前缀 -> 合并后的厂商条目名。
OWNER = {"google-": "google", "bing": "bing", "microsoft-": "bing", "openai-": "openai", "kimi-": "kimi",
         "duck": "duckduckgo", "anthropic-": "anthropic", "ahrefs-": "ahrefs", "facebook-": "meta", "meta-": "meta",
         "ccbot-": "commoncrawl", "commoncrawl-": "commoncrawl"}


def owner(entry):
    name = entry["name"]
    # Google 两组 rDNS（googlebot.com 爬虫 / google.com 抓取器）合起来 20 个 token 超过 16，分两条。
    if name.startswith("google-"):
        return "google" if "googlebot.com" in entry.get("rdns_suffixes", []) else "google-fetcher"
    for prefix, group in OWNER.items():
        if name.startswith(prefix):
            return group
    return name


def main():
    crawlers = json.load(open(sys.argv[1]))["crawlers"]
    groups = {}
    for entry in crawlers + PRESETS:
        if entry["name"].startswith("cloudflare-") or set(entry.get("categories", [])) - VENDOR_TAGS <= NOT_DEFAULT:
            continue
        groups.setdefault(owner(entry), []).append(entry)
    out = []
    for name, members in groups.items():
        networks = sorted({n for m in members for n in m.get("networks", [])})
        suffixes = sorted({n for m in members for n in m.get("rdns_suffixes", [])})
        sources = sorted({n for m in members for n in m.get("network_sources", [])})
        members.sort(key=lambda e: e["name"])
        tokens = sorted({t for m in members for t in m["user_agent_tokens"]})
        if len(tokens) > 16:
            raise SystemExit(f"{members[0]['name']}: {len(tokens)} tokens")
        item = {"name": name,
                "members": [m["name"] for m in members],
                "categories": sorted({c for m in members for c in m.get("categories", [])}),
                "user_agent_tokens": tokens}
        if networks:
            item["networks"] = list(networks)
        if suffixes:
            item["rdns_suffixes"] = suffixes
        if sources:
            item["sources"] = [dict({"url": u}, **SOURCE_FORMAT.get(u, {"format": "json"})) for u in sources]
        out.append(item)
    out.sort(key=lambda e: e["name"])
    if len(out) > 32:
        raise SystemExit(f"{len(out)} default crawlers > 32")
    names = [e["name"] for e in out]
    if len(set(names)) != len(names):
        raise SystemExit("duplicate group names")
    with open(sys.argv[2], "w") as f:
        json.dump({"schema": "cdnca.default-crawlers/v1", "source": "arcjet/well-known-bots（MIT）+ 原前端预设",
                   "crawlers": out}, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(len(out), "groups")


if __name__ == "__main__":
    main()
