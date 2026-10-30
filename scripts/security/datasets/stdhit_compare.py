#!/usr/bin/env python3
"""Per request STDHIT comparison of two run-std.sh log dirs (waf-cookie-fp):
标准防护 verdicts must be identical; tiers must be monotonic (a request
blocked at tier t is blocked at every stricter tier) in the new run.
stdhit_compare.py <before dir> <after dir>"""
import collections, glob, os, re, sys


def load(path):
    hits = {}
    for log in glob.glob(os.path.join(path, "*.log")):
        for line in open(log, errors="replace"):
            if line.startswith("STDHIT "):
                parts = line.split()
                tiers = re.search(r"tiers=(\d+)", line).group(1)
                hits[(parts[1], parts[2])] = set(int(t) for t in tiers)
    return hits


before, after = load(sys.argv[1]), load(sys.argv[2])
keys = set(before) | set(after)
names = ["仅记录", "标准防护", "严格防护", "极严格防护"]
for tier in range(4):
    changed = collections.Counter()
    for key in keys:
        b, a = tier in before.get(key, ()), tier in after.get(key, ())
        if b != a:
            changed[(key[0], "+" if a else "-")] += 1
    print(f"{names[tier]} 逐条变化: {dict(changed) or 0}")
broken = [k for k, t in after.items() if any(x in t and x + 1 not in t for x in (1, 2))]
print(f"改后非递增（某档拦、更严档不拦）: {len(broken)} {broken[:5]}")
