#!/usr/bin/env python3
"""naxsi-strong 特征筛选：naxsi-core 多字符候选（gen_imported_packs.naxsi_strong_candidates）在 waf-comparison fast
正常集上逐条估算命中率（离线复刻节点取值：参数名与值、表单/JSON 叶子、Cookie 名值，最多 3 次 URL 解码；contains 两侧
小写），单条 <0.5% 的选入；args 的 http:// 与 && 虽 <0.5% 但会把并集推过 0.5%，不选。最终数字以真实 OpenResty 评测
（eval_imported_packs.py）为准。
用法：~/.cache/cdnca-waf-datasets/venv/bin/python screen_naxsi_strong.py → rulepacks/imported/naxsi-strong-screen.json
"""
import gzip
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from gen_imported_packs import naxsi_strong_candidates  # noqa: E402

CORPUS = os.path.expanduser("~/.cache/cdnca-waf-datasets/corpus")
LIMIT = 0.5
EXCLUDE = {("args", "contains", "http://"), ("args", "contains", "&&")}


def decode(value):
    for _ in range(3):
        if "%" not in value and "+" not in value:
            break
        unquoted = urllib.parse.unquote_plus(value)
        if unquoted == value:
            break
        value = unquoted
    return value


def pairs(raw, separator="&"):
    out = []
    for part in raw.split(separator):
        part = part.strip()
        if part:
            name, equals, value = part.partition("=")
            out.append(decode(name))
            if equals:
                out.append(decode(value))
    return out


def leaves(node, out):
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for name, child in node.items():
            out.append(name)
            leaves(child, out)
    elif isinstance(node, list):
        for child in node:
            leaves(child, out)


def values(request):
    uri = request.get("uri") or "/"
    headers = {k.lower(): v for k, v in (request.get("headers") or {}).items()}
    args = pairs(uri.split("?", 1)[1] if "?" in uri else "")
    body, kind = request.get("data") or "", headers.get("content-type", "")
    if body:
        if "x-www-form-urlencoded" in kind:
            args += pairs(body)
        elif "json" in kind:
            try:
                leaves(json.loads(body), args)
            except ValueError:
                args.append(body)
        else:
            args.append(body)
    return {"args": args, "request_uri": [decode(uri)], "cookie": pairs(headers.get("cookie", ""), ";")}


def main():
    candidates = [(t, op, v, re.compile(v) if op == "regex" else None) for t, _, op, v, _ in naxsi_strong_candidates()]
    hits, total = [0] * len(candidates), 0
    with gzip.open(os.path.join(CORPUS, "wafcomp-legit.jsonl.gz"), "rt") as f:
        for line in f:
            request = json.loads(line)
            if not request.get("fast"):
                continue
            total += 1
            got = values(request)
            for index, (target, op, value, compiled) in enumerate(candidates):
                if any((value in x.lower()) if op == "contains" else compiled.search(x) for x in got[target]):
                    hits[index] += 1
    out = []
    for (target, op, value, _), count in zip(candidates, hits):
        rate = 100.0 * count / total
        out.append({"target": target, "operator": op, "value": value, "legit_hits": count, "legit_pct": round(rate, 3),
                    "selected": rate < LIMIT and (target, op, value) not in EXCLUDE})
    path = os.path.join(HERE, "rulepacks", "imported", "naxsi-strong-screen.json")
    json.dump({"corpus": "wafcomp-legit fast", "requests": total, "limit_pct": LIMIT, "candidates": out},
              open(path, "w"), ensure_ascii=False, indent=1)
    print(path, sum(c["selected"] for c in out), "of", len(out))


if __name__ == "__main__":
    main()
