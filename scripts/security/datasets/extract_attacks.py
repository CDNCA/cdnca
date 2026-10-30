#!/usr/bin/env python3
"""从 ~/.cache/cdnca-waf-datasets/seed 下已解包的公开仓库抽取攻击样本，按类别归档并去重。

输出 ~/.cache/cdnca-waf-datasets/corpus/seed-attacks.jsonl.gz，每行
{"category", "payload", "source"}；同一类别内按规范形式去重（小写、空白折叠、
URL 解码一次），与 libs/entitlement/ruleintel/cluster 的 Normalize 口径一致的
最小子集（这里只为去掉逐字重复与大小写/编码变体；授权端入库时还会再跑 Normalize）。

数据只在本地使用（SOURCES.md 分类：全部来源都可作样本）。
用法：extract_attacks.py [seed 根目录] [输出文件]
"""
import gzip
import json
import os
import re
import sys
import urllib.parse
from collections import Counter

SEED = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "~/.cache/cdnca-waf-datasets/seed")
OUT = os.path.expanduser(sys.argv[2] if len(sys.argv) > 2 else "~/.cache/cdnca-waf-datasets/corpus/seed-attacks.jsonl.gz")

# 路径关键词 → 类别（先匹配先得）
CATEGORIES = [
    ("sqli", r"sql|sqli|blind|union|nosql"),
    ("xss", r"xss|cross.?site.?script|html.?inject|polyglot"),
    ("ssti", r"ssti|template.?inject|server.?side.?template"),
    ("cmd", r"command.?inject|cmd.?inject|cmdi|os.?command|rce|remote.?code|shell"),
    ("path", r"traversal|directory|lfi|file.?inclu|path"),
    ("ssrf", r"ssrf|server.?side.?request"),
    ("xxe", r"xxe|xml.?external|xml"),
    ("ldap", r"ldap"),
    ("xpath", r"xpath"),
    ("crlf", r"crlf|header.?inject|response.?split"),
    ("redirect", r"open.?redirect|redirect"),
    ("deser", r"deserial|ysoserial|java.?serial|php.?serial|pickle"),
    ("nosql", r"mongo|nosql"),
    ("proto", r"prototype.?pollution"),
    ("upload", r"upload|extension"),
    ("format", r"format.?string"),
]
CATEGORY_RE = [(name, re.compile(pattern, re.I)) for name, pattern in CATEGORIES]

# 只取攻击载荷目录；跳过字典/用户名/口令/发现类列表（不是攻击）
SKIP_DIR = re.compile(r"(^|/)(discovery|passwords?|usernames?|wordlists?|web-content|dns|subdomains?|dirbuster|"
                      r"\.git|images?|docs?|_?site|bot|crawler|robots|user-?agents?|device|requirements|"
                      r"test/valgrind|autoconf|ui)(/|$)", re.I)
# 字典/路径爆破列表（不是攻击）与 libinjection 自带的非攻击语料
SKIP_FILE = re.compile(r"(directory-list|raft-|common\.txt|big\.txt|fingerprints\.txt|requirements\.txt|"
                       r"sqli-forums|xss-arm|false.?positive)", re.I)
# libinjection data/ 下的攻击语料按文件名定类
LIBINJECTION = {"sqli-sqlmap": "sqli", "sqli-sqlmap-20130419": "sqli", "xss-shazzer": "xss",
                "xss-html5sec": "xss", "xss-rsnake": "xss", "xss-ofer": "xss", "xss-gareth": "xss",
                "sqli-misc": "sqli", "sqli-hackers": "sqli", "sqli-rsnake": "sqli", "sqli-arf": "sqli",
                "sqli-ckinfo": "sqli", "sqli-mysqlsec": "sqli", "sqli-spidermarket": "sqli"}
MAX_LEN = 4096
MAX_FILE = 8 * 1024 * 1024


def category_of(path):
    for name, pattern in CATEGORY_RE:
        if pattern.search(path):
            return name
    return None


def canonical(payload):
    text = payload.strip()
    try:
        decoded = urllib.parse.unquote(text)
    except Exception:
        decoded = text
    return re.sub(r"\s+", " ", decoded).lower()


def lines_of(path):
    try:
        if os.path.getsize(path) > MAX_FILE:
            return []
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read().splitlines()
    except OSError:
        return []


def from_text(path):
    for line in lines_of(path):
        line = line.rstrip("\r")
        if not line.strip() or line.lstrip().startswith("#") or len(line) > MAX_LEN:
            continue
        yield line


NEMESIDA = {"SQLi": "sqli", "XSS": "xss", "SSTI": "ssti", "RCE": "cmd", "LFI": "path", "RFI": "rfi",
            "SSRF": "ssrf", "LDAP": "ldap", "NoSQLi": "nosql", "OR": "redirect", "SSI": "ssi",
            "GraphQL": "graphql", "API": "api", "UWA": "unwanted_access", "MFD": "upload", "Misc": "misc",
            "CM": None, "FP": "benign"}  # CM 是自定义 HTTP 方法；FP 是误报（正常）样本，单独输出


def from_nemesida(path):
    # nemesida waf-bypass utils/payload/<类>/<n>.json：{"payload": [{"ARGS"|"BODY"|"UA"|...: 值, "ENCODE": ...}]}
    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return
    for item in document.get("payload") or []:
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            if key in ("ENCODE", "BLOCKED", "METHOD", "BOUNDARY", "JSON") or not isinstance(value, str):
                continue
            if value.strip() and len(value) <= MAX_LEN:
                yield value


def walk(root):
    for directory, subdirs, files in os.walk(root):
        relative = os.path.relpath(directory, SEED)
        if SKIP_DIR.search("/" + relative.replace(os.sep, "/") + "/"):
            subdirs[:] = []
            continue
        for name in files:
            yield os.path.join(directory, name)


def main():
    seen = {}
    counts = Counter()
    sources = Counter()
    benign = []
    src_root = os.path.join(SEED, "src")
    roots = [os.path.join(src_root, name) for name in sorted(os.listdir(src_root))]
    roots.append(os.path.join(SEED, "seclists"))
    for root in roots:
        root_source = os.path.basename(root)
        for path in walk(root):
            source = root_source
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            if "nemesida" in source and relative.startswith("utils/payload/") and path.endswith(".json"):
                klass = relative.split("/")[2]
                category = NEMESIDA.get(klass)
                if category is None:
                    continue
                values = from_nemesida(path)
            elif path.endswith((".txt", ".lst", ".list")) or os.path.basename(path).lower() in ("payloads", "intruder"):
                if SKIP_FILE.search(os.path.basename(path)):
                    continue
                if "/libinjection/" in relative:
                    stem = os.path.basename(path).rsplit(".", 1)[0]
                    category = LIBINJECTION.get(stem)
                    if category is None:
                        continue
                    source = root_source + ":libinjection"
                else:
                    category = category_of(relative)
                if category is None:
                    continue
                values = from_text(path)
            else:
                continue
            for value in values:
                if category == "benign":
                    benign.append({"category": "benign", "payload": value, "source": source})
                    continue
                key = (category, canonical(value))
                if key in seen:
                    continue
                seen[key] = {"category": category, "payload": value, "source": source}
                counts[category] += 1
                sources[source] += 1
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8") as handle:
        for record in seen.values():
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    benign_out = OUT.replace("seed-attacks", "seed-benign")
    with gzip.open(benign_out, "wt", encoding="utf-8") as handle:
        for record in benign:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps({"attacks": len(seen), "benign": len(benign), "by_category": dict(counts.most_common()),
                      "by_source": dict(sources.most_common())}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()