#!/usr/bin/env python3
"""汇总 run_eval.sh 各批输出：种子样本（ID seed-<类别>-<位置>-<序号>）按类别、类别×位置的四档拦截率，最弱 10 类。

用法：summarize_eval.py out-00.log [out-01.log ...]
内置攻击/正常语料每批都会重复跑，只取第一批的一份作对照（正常样本给误报率）。
最弱 10 类：按“严格防护”拦截率升序，样本 < 10 条的类不参与排名（另列）。
"""
import collections
import json
import sys

TIERS = ["仅记录", "标准防护", "严格防护", "极严格防护"]
LOCS = ["query", "form", "json", "cookie", "header", "upload"]  # upload：waf-gap4 -real 的 multipart


def rate(hit, total):
    return "%5.1f%%" % (100.0 * hit / total) if total else "    -"


def main():
    cat = collections.defaultdict(lambda: [0, [0] * 4])
    cell = collections.defaultdict(lambda: [0, [0] * 4])
    builtin = {}
    for index, path in enumerate(sys.argv[1:]):
        for line in open(path, errors="replace"):
            if not line.startswith("EVAL "):
                continue
            r = json.loads(line[5:])
            if r["id"].startswith("seed-"):
                _, category, loc, _ = r["id"].split("-", 3) if r["id"].count("-") >= 3 else (None,) * 4
                # 类别可能含下划线不含连字符；位置固定
                for key in (category, (category, loc)):
                    bucket = cat[key] if key == category else cell[key]
                    bucket[0] += 1
                    for t, blocked in enumerate(r["tiers"]):
                        bucket[1][t] += blocked
            elif index == 0:
                builtin[r["id"]] = r
    total = [sum(v[0] for v in cat.values()), [sum(v[1][t] for v in cat.values()) for t in range(4)]]
    print("## 种子攻击样本 %d 条，四档拦截率" % total[0])
    print("| 档 | 拦截 | 拦截率 |")
    print("|---|---|---|")
    for t, name in enumerate(TIERS):
        print("| %s | %d | %s |" % (name, total[1][t], rate(total[1][t], total[0])))
    benign = [r for r in builtin.values() if not r["attack"]]
    if benign:
        fp = [sum(r["tiers"][t] for r in benign) for t in range(4)]
        print("\n内置正常样本 %d 条误报率：%s" % (len(benign), "，".join("%s %s" % (n, rate(fp[t], len(benign)).strip()) for t, n in enumerate(TIERS))))
    print("\n## 按类别（标准 / 严格 / 极严格）")
    print("| 类别 | 样本 | 标准 | 严格 | 极严格 | " + " | ".join("严格·" + l for l in LOCS) + " |")
    print("|---|---|---|---|---|" + "---|" * len(LOCS))
    for category in sorted(cat, key=lambda c: -cat[c][0]):
        n, hits = cat[category]
        locs = [rate(cell[(category, l)][1][2], cell[(category, l)][0]).strip() for l in LOCS]
        print("| %s | %d | %s | %s | %s | %s |" % (category, n, rate(hits[1], n).strip(), rate(hits[2], n).strip(),
                                                   rate(hits[3], n).strip(), " | ".join(locs)))
    print("\n## 按位置（四档）")
    print("| 位置 | 样本 | " + " | ".join(TIERS) + " |")
    print("|---|---|" + "---|" * len(TIERS))
    for l in LOCS:
        n = sum(v[0] for k, v in cell.items() if k[1] == l)
        if n:
            hs = [sum(v[1][t] for k, v in cell.items() if k[1] == l) for t in range(4)]
            print("| %s | %d | %s |" % (l, n, " | ".join(rate(h, n).strip() for h in hs)))
    ranked = sorted((c for c in cat if cat[c][0] >= 10), key=lambda c: (cat[c][1][2] / cat[c][0], c))
    print("\n## 最弱 10 类（严格防护拦截率升序，样本 ≥10）")
    for c in ranked[:10]:
        n, hits = cat[c]
        print("- %s：%s（%d/%d；极严格 %s）" % (c, rate(hits[2], n).strip(), hits[2], n, rate(hits[3], n).strip()))
    small = sorted(c for c in cat if cat[c][0] < 10)
    if small:
        print("- 样本 <10 未排名：" + "，".join("%s %d/%d" % (c, cat[c][1][2], cat[c][0]) for c in small))


if __name__ == "__main__":
    main()
