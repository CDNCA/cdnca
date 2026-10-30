#!/usr/bin/env python3
"""RI-03 eval comparison: per request, the 标准防护 verdict must equal the
baseline before RI-03 (two-level scoring + detectors on the corrected
corpus c838d8ff2: data/eval-final4.jsonl.gz); 严格防护 block+challenge vs the
pre two-level TPR (eval-before, old corpus). Usage:
ri03_compare.py <new eval log> [baseline jsonl.gz] [before jsonl.gz]"""
import gzip, json, sys, os

def load(path):
    opener = gzip.open if path.endswith(".gz") else open
    rows = {}
    with opener(path, "rt", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("EVAL "):
                continue
            row = json.loads(line[5:])
            rows[row["id"]] = row
    return rows

new = load(sys.argv[1])
data = os.path.join(os.path.dirname(__file__), "data")
base = load(sys.argv[2] if len(sys.argv) > 2 else os.path.join(data, "eval-final4.jsonl.gz"))
before = load(sys.argv[3] if len(sys.argv) > 3 else os.path.join(data, "eval-before.jsonl.gz"))
names = ["仅记录", "标准防护", "严格防护", "极严格防护"]
common = sorted(set(new) & set(base))
changed = [i for i in common if new[i]["tiers"][1] != base[i]["tiers"][1]]
print(f"common {len(common)} new-only {len(set(new)-set(base))} base-only {len(set(base)-set(new))}")
print(f"标准防护 verdict changed: {len(changed)} {changed[:10]}")
for tier in range(4):
    for label, rows in (("before", before), ("2b", base), ("ri03", new)):
        attacks = [r for r in rows.values() if r["attack"]] or [{"tiers": [False] * 4}]
        benign = [r for r in rows.values() if not r["attack"]] or [{"tiers": [False] * 4}]
        blocked = sum(r["tiers"][tier] for r in attacks)
        fp = sum(r["tiers"][tier] for r in benign)
        ch = sum((r.get("challenged") or [False] * 4)[tier] for r in attacks)
        bch = sum((r.get("challenged") or [False] * 4)[tier] for r in benign)
        print(f"{names[tier]} {label:6} attacks {len(attacks)} TPR {blocked/len(attacks):.4f} TPR+challenge {(blocked+ch)/len(attacks):.4f} "
              f"benign {len(benign)} FPR(block) {fp/len(benign):.4f} challenged-benign {bch/len(benign):.4f}")
