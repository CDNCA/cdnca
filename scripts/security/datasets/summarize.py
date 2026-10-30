#!/usr/bin/env python3
"""Sum the STD lines of run-std.sh batch logs: rate, Wilson 95% interval per
dataset x tier, and the waf-comparison balanced accuracy (TPR + TNR) / 2.
usage: summarize.py <log dir>   (markdown table on stdout)"""
import glob
import math
import os
import re
import sys

TIERS = ["仅记录", "标准防护", "严格防护", "极严格防护"]


def wilson(k, n, z=1.959964):
    if n == 0:
        return 0.0, 0.0
    p = k / n
    center = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, center - half), min(1.0, center + half)


def main(directory):
    sums = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.log"))):
        for line in open(path, encoding="utf-8"):
            if not line.startswith("STD dataset="):
                continue
            fields = dict(re.findall(r"(\w+)=(\S+)", line))
            key = (fields["dataset"], fields["tier"])
            total = sums.setdefault(key, [0, 0, 0])
            total[0] += int(fields["counted"])
            total[1] += int(fields["blocked"])
            total[2] += int(fields["excluded"])
    print("| 数据集 | 档 | 计入 | 拦截 | 比率 | 95% 区间 | 排除 |")
    print("|---|---|---|---|---|---|---|")
    for (dataset, tier), (counted, blocked, excluded) in sorted(sums.items(), key=lambda kv: (kv[0][0], TIERS.index(kv[0][1]))):
        low, high = wilson(blocked, counted)
        print(f"| {dataset} | {tier} | {counted} | {blocked} | {blocked / max(counted, 1):.2%} | {low:.2%}–{high:.2%} | {excluded} |")
    print()
    print("| 档 | TPR | FPR | 平衡准确率 |")
    print("|---|---|---|---|")
    for tier in TIERS:
        attack, benign = sums.get(("wafcomp-mal/attack", tier)), sums.get(("wafcomp-legit/benign", tier))
        if not attack or not benign:
            continue
        tpr, fpr = attack[1] / attack[0], benign[1] / benign[0]
        print(f"| {tier} | {tpr:.2%} | {fpr:.2%} | {(tpr + 1 - fpr) / 2:.2%} |")


if __name__ == "__main__":
    main(sys.argv[1])
