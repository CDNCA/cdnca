#!/usr/bin/env python3
"""生成 scripts/security/datasets/SOURCES.md：公开 WAF/Bot 数据集来源、提交号、许可证、分类、SHA-256。

数据根目录：~/.cache/cdnca-waf-datasets/seed/{tar,src,seclists}
分类口径：
  rule-direct  规则文本宽松许可证（MIT/BSD/Apache/CC0/ISC/Unlicense），可直接转官方规则包
  rule-adopted 非宽松许可证（GPL/AGPL/LGPL）的规则原文已转官方规则包（直接用原文，
               不注明出处；gen_imported_packs.py → rulepacks/imported/）
  sample-only  只作攻击样本（授权端样本库与本地评测，不随产品分发）
"""
import hashlib
import os
import subprocess

ROOT = os.path.expanduser("~/.cache/cdnca-waf-datasets/seed")

# (目录前缀, GitHub 仓库, 许可证（读自仓库 LICENSE）, 分类, 用途)
SOURCES = [
    ("swisskyrepo_PayloadsAllTheThings", "swisskyrepo/PayloadsAllTheThings", "MIT", "sample-only", "多类攻击样本"),
    ("fuzzdb-project_fuzzdb", "fuzzdb-project/fuzzdb", "BSD-3-Clause（_copyright.txt）", "sample-only", "攻击样本"),
    ("sqlmapproject_sqlmap", "sqlmapproject/sqlmap", "GPL-2.0-or-later", "sample-only", "SQLi 载荷（data/xml/payloads）"),
    ("s0md3v_XSStrike", "s0md3v/XSStrike", "GPL-3.0", "sample-only", "XSS 载荷"),
    ("payload-box_command-injection-payload-list", "payloadbox/command-injection-payload-list", "MIT", "sample-only", "命令注入"),
    ("payload-box_crlf-injection-payload-list", "payloadbox/crlf-injection-payload-list", "MIT", "sample-only", "CRLF"),
    ("payload-box_directory-payload-list", "payloadbox/directory-payload-list", "MIT", "sample-only", "路径穿越"),
    ("payload-box_open-redirect-payload-list", "payloadbox/open-redirect-payload-list", "MIT", "sample-only", "开放重定向"),
    ("payload-box_server-side-template-injection-payloads", "payloadbox/server-side-template-injection-payloads", "MIT", "sample-only", "SSTI"),
    ("payload-box_sql-injection-payload-list", "payloadbox/sql-injection-payload-list", "MIT", "sample-only", "SQLi"),
    ("payload-box_waf-bypass-payload-list", "payloadbox/waf-bypass-payload-list", "MIT", "sample-only", "WAF 绕过"),
    ("payload-box_xss-payload-list", "payloadbox/xss-payload-list", "MIT（仅 README 徽章，无 LICENSE 文件）", "sample-only", "XSS"),
    ("payload-box_xxe-injection-payload-list", "payloadbox/xxe-injection-payload-list", "MIT", "sample-only", "XXE"),
    ("1N3_IntruderPayloads", "1N3/IntruderPayloads", "无许可证", "sample-only", "多类攻击样本"),
    ("foospidy_payloads", "foospidy/payloads", "GPL-3.0", "sample-only", "多类攻击样本"),
    ("nemesida-waf_waf-bypass", "nemesida-waf/waf-bypass", "MIT", "sample-only", "WAF 绕过样本"),
    ("chaitin_blazehttp", "chaitin/blazehttp", "GPL-3.0", "sample-only", "攻击/白样本 HTTP 报文"),
    ("PortSwigger_xss-cheatsheet-data", "PortSwigger/xss-cheatsheet-data", "无许可证（版权声明禁止衍生速查表）", "sample-only", "XSS 向量，仅内部评测"),
    ("cujanovic_SSRF-Testing", "cujanovic/SSRF-Testing", "无许可证", "sample-only", "SSRF"),
    ("minimaxir_big-list-of-naughty-strings", "minimaxir/big-list-of-naughty-strings", "MIT", "sample-only", "边界字符串（误报评测）"),
    ("wallarm_gotestwaf", "wallarm/gotestwaf", "MIT", "sample-only", "测试用例"),
    ("JayBizzle_Crawler-Detect", "JayBizzle/Crawler-Detect", "MIT", "rule-direct", "爬虫 UA 正则"),
    ("monperrus_crawler-user-agents", "monperrus/crawler-user-agents", "MIT", "rule-direct", "爬虫 UA 模式"),
    ("omrilotan_isbot", "omrilotan/isbot", "Unlicense", "rule-direct", "Bot UA 模式"),
    ("arcjet_well-known-bots", "arcjet/well-known-bots", "MIT", "rule-direct", "良性爬虫清单（分类/验证方式）"),
    ("ai-robots-txt_ai.robots.txt", "ai-robots-txt/ai.robots.txt", "MIT", "rule-direct", "AI 爬虫清单"),
    ("mitchellkrogza_nginx-ultimate-bad-bot-blocker", "mitchellkrogza/nginx-ultimate-bad-bot-blocker", "MIT", "rule-direct", "恶意 UA/扫描器"),
    ("matomo-org_device-detector", "matomo-org/device-detector", "LGPL-3.0", "rule-adopted", "Bot 正则 → system/bot-dd-scraper、bot-dd-service"),
    ("bunkerity_bunkerweb", "bunkerity/bunkerweb", "AGPL-3.0", "rule-adopted", "方法/请求头数/请求体默认限制 → system/bw-request-limits（坏 UA、坏行为已在 bot-bad-ua、cc-404-burst）"),
    ("wargio_naxsi", "wargio/naxsi", "GPL-3.0（另含 LGPL-3.0 部分）", "rule-adopted", "核心规则+blocking 规则 → system/naxsi-strong（核心规则多字符强特征）、naxsi-scanner、naxsi-websec、naxsi-sqli"),
]

LABEL = {"rule-direct": "规则可直接用", "rule-adopted": "规则已采用", "sample-only": "仅样本"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    tars = sorted(os.listdir(os.path.join(ROOT, "tar")))
    rows, counts = [], {}
    for prefix, repo, lic, cls, use in SOURCES:
        tar = next(t for t in tars if t.startswith(prefix + "-"))
        commit = tar[len(prefix) + 1:-len(".tar.gz")]
        rows.append(f"| {repo} | https://github.com/{repo} | `{commit}` | {lic} | {LABEL[cls]} | {use} | `{sha256(os.path.join(ROOT, 'tar', tar))}` |")
        counts[cls] = counts.get(cls, 0) + 1
    sl = os.path.join(ROOT, "seclists")
    sl_commit = subprocess.check_output(["git", "-C", sl, "rev-parse", "HEAD"], text=True).strip()
    rows.append(f"| danielmiessler/SecLists | https://github.com/danielmiessler/SecLists | `{sl_commit[:12]}` | MIT | 仅样本 | 攻击样本（git 浅克隆，无 tar） | — |")
    counts["sample-only"] += 1
    out = [
        "# WAF/Bot 公开数据集来源",
        "",
        "由 `scripts/security/datasets/gen_sources.py` 生成；数据只放 `~/.cache/cdnca-waf-datasets/`，不进仓库、不随产品分发。",
        "",
        "分类口径：攻击样本不论许可证全部进授权端样本库与本地评测；规则文本为宽松许可证（MIT/BSD/Apache/CC0/ISC/Unlicense）直接转官方规则包；"
        "GPL/AGPL/LGPL 来源的规则原文也已转换进官方规则包（规则已采用，不注明出处）；"
        "CC-BY-SA/NC/无许可证的规则只作样本。",
        "",
        f"统计：规则可直接用 {counts.get('rule-direct', 0)}，规则已采用 {counts.get('rule-adopted', 0)}，仅样本 {counts.get('sample-only', 0)}，共 {sum(counts.values())}。",
        "",
        "提交号取自下载目录名后缀（GitHub tarball 短提交号）；SHA-256 针对 `seed/tar/<目录名>.tar.gz`。",
        "",
        "| 仓库 | URL | 提交 | 许可证 | 分类 | 用途 | tar SHA-256 |",
        "|---|---|---|---|---|---|---|",
        *rows,
        "",
    ]
    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "SOURCES.md")
    with open(dst, "w") as f:
        f.write("\n".join(out))
    print(dst, counts)


if __name__ == "__main__":
    main()
