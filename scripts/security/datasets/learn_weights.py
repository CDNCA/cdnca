#!/usr/bin/env python3
"""waf-gap6 S1：离线学习两级评分里弱分规则（PL>1）的非负整数权重（研究 §3.1，ModSec-Learn 的正式版）。

输入：STDVEC 行（cdnca-waf-check -std-probe，探针站 PL4 命中向量 r[] + 检测器 x[]）与 EVAL 行（seed/CRS 评测，rules[] + detectors[]）。
模型：与节点一致的按集合两级评分——强分 = PL1 规则严重度 + 检测器 5；弱分 = Σ 权重（PL2+ 规则，本档 PL 以内）；
      强分 ≥ 5 或 强分+弱分 ≥ W(10) 即拦截。只学弱分权重 w ∈ {0..5}，PL1 与检测器固定（标准档 ⊆ 严格档）。
训练：坐标下降，目标 = 训练集 TPR − λ·FPR（正常样本数大时按比例加权），每轮对每条规则试 0..5 取最优；
      跨档一致：严格（PL2）与极严格（PL3）用同一组权重（节点同一集合键单一计分），目标为两档之和。
防过拟合：按请求 ID 哈希 70/30 切分，只在训练集上选权重，报告验证集；权重只降不升（初值 = 严重度），
          不引入负权重（研究 §3.1 风险：负权重可被攻击者利用）。
用法：learn_weights.py --vec 'runs/gap6-vec/*.log' --eval 'runs/gap5-after/out-0*.log' [--lambda 4] [--out weights.json]
"""
import argparse
import collections
import glob
import gzip
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "../../..")
SEV = {"critical": 5, "error": 4, "warning": 3, "notice": 2}
DET = {"sqli": "crs_sqli", "xss": "crs_xss", "ssti": "crs_ssti", "java_deser": "crs_java_deserialization",
       "php_deser": "crs_php_deserialization", "ssrf": "crs_file_include", "cmd": "crs_cmd_injection",
       "crlf": "crs_xss", "redirect": "crs_file_include", "format": "crs_cmd_injection", "nosql": "crs_sqli",
       "ldap": "crs_sqli", "upload": "crs_file_upload", "xxe": "crs_file_include", "proto": "crs_generic",
       "path": "crs_file_include"}


def crs_rules():
    path = os.path.join(REPO, "scripts/security/wsa-proto/data/crs-rules.json")
    return {int(k): (v[0], SEV[v[1]], v[2]) for k, v in json.load(open(path)).items()}


def owners(pack, crs):
    sets = json.load(open(os.path.join(REPO, "libs/rulepack/testdata/crs-profiles", pack + ".json")))["rules"]
    own = {}
    for s in sets:
        c = s["crs"]
        for rid, (_, _, f) in crs.items():
            if any(f.startswith(p + "-") for p in c["files"]) and rid not in c["exclude_ids"]:
                own[rid] = s["id"]
    for s in sets:
        for rid in s["crs"]["include_ids"]:
            if rid in crs:
                own[rid] = s["id"]
    return own


def opener(path):
    return gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, errors="replace")


def load(vec_globs, eval_globs):
    rows, seen = [], set()
    for pattern in vec_globs:
        for path in sorted(glob.glob(os.path.expanduser(pattern))):
            for line in opener(path):
                if line.startswith("STDVEC "):
                    try:
                        r = json.loads(line[7:])
                    except ValueError:  # a shard still being written
                        continue
                    key = r["d"] + "/" + r["id"]
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append((key, r["d"], bool(r["a"]), r["r"] or [], r["x"] or []))
    for pattern in eval_globs:
        for path in sorted(glob.glob(os.path.expanduser(pattern))):
            for line in opener(path):
                if line.startswith("EVAL "):
                    r = json.loads(line[5:])
                    key = "eval/" + r["id"]
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append((key, "eval", bool(r["attack"]), r.get("rules") or [], r.get("detectors") or []))
    return rows


def split(key):
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 10 < 7


class Tier:
    """一档（pack, pl）下每条请求的强分（按集合）与弱分规则表。"""

    def __init__(self, rows, own, crs, pl):
        self.strong, self.weak = [], []
        for _, _, _, rules, dets in rows:
            strong, weak = collections.Counter(), collections.defaultdict(list)
            for rid in rules:
                if rid not in own or crs[rid][0] > pl:
                    continue
                if crs[rid][0] == 1:
                    strong[own[rid]] += crs[rid][1]
                else:
                    weak[own[rid]].append(rid)
            for d in dets:
                if d in DET:
                    strong[DET[d]] += 5
            self.strong.append(strong)
            self.weak.append(weak)

    def blocked(self, index, weights, W=10):
        strong, weak = self.strong[index], self.weak[index]
        for key in set(strong) | set(weak):
            s = strong.get(key, 0)
            if s >= 5 or s + sum(weights[r] for r in weak.get(key, ())) >= W:
                return True
        return False


class State:
    """每行每档的拦截结果缓存；改一条规则的权重只重算含该规则的行。"""

    def __init__(self, rows, tiers, weights, indices):
        self.rows, self.tiers, self.weights, self.indices = rows, tiers, weights, indices
        self.hit = {(i, t): tiers[t].blocked(i, weights) for i in indices for t in range(len(tiers))}
        self.by_rule = collections.defaultdict(set)
        for i in indices:
            for t, tier in enumerate(tiers):
                for rules in tier.weak[i].values():
                    for rid in rules:
                        self.by_rule[rid].add((i, t))
        self.a = sum(len(tiers) for i in indices if rows[i][2])
        self.b = sum(len(tiers) for i in indices if not rows[i][2])
        self.tp = sum(1 for (i, t), h in self.hit.items() if h and rows[i][2])
        self.fp = sum(1 for (i, t), h in self.hit.items() if h and not rows[i][2])

    def objective(self, lam, tp=None, fp=None):
        tp = self.tp if tp is None else tp
        fp = self.fp if fp is None else fp
        return tp / max(self.a, 1) - lam * fp / max(self.b, 1)

    def trial(self, rid, w):
        """权重改为 w 时的 (tp, fp, 变化表)，不落地。"""
        keep = self.weights[rid]
        self.weights[rid] = w
        tp, fp, changes = self.tp, self.fp, []
        for i, t in self.by_rule.get(rid, ()):
            now = self.tiers[t].blocked(i, self.weights)
            if now != self.hit[(i, t)]:
                changes.append((i, t, now))
                delta = 1 if now else -1
                if self.rows[i][2]:
                    tp += delta
                else:
                    fp += delta
        self.weights[rid] = keep
        return tp, fp, changes

    def commit(self, rid, w, tp, fp, changes):
        self.weights[rid] = w
        self.tp, self.fp = tp, fp
        for i, t, now in changes:
            self.hit[(i, t)] = now


def table(rows, tiers, names, weights, indices, label):
    out = []
    for name, tier in zip(names, tiers):
        a = [i for i in indices if rows[i][2]]
        b = [i for i in indices if not rows[i][2]]
        tp = sum(1 for i in a if tier.blocked(i, weights))
        fp = sum(1 for i in b if tier.blocked(i, weights))
        out.append("%s %-10s TPR %6d/%-6d=%.4f  FPR %6d/%-6d=%.4f" % (label, name, tp, len(a), tp / max(len(a), 1), fp, len(b), fp / max(len(b), 1)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vec", action="append", default=[])
    ap.add_argument("--eval", action="append", default=[])
    ap.add_argument("--lambda", dest="lam", type=float, default=4.0)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--keep-tpr", action="store_true",
                    help="约束：训练集两档拦截数都不低于基线（waf-strict-algo 约束“TPR 不降”），只减误报")
    ap.add_argument("--out")
    args = ap.parse_args()
    crs = crs_rules()
    rows = load(args.vec, args.eval)
    if not rows:
        sys.exit("no rows")
    own2, own3 = owners("crs-pl2", crs), owners("crs-pl3", crs)
    tiers = [Tier(rows, own2, crs, 2), Tier(rows, own3, crs, 3)]
    names = ["严格防护", "极严格防护"]
    train = [i for i, r in enumerate(rows) if split(r[0])]
    valid = [i for i, r in enumerate(rows) if not split(r[0])]
    base = {rid: v[1] for rid, v in crs.items()}
    weights = dict(base)
    # 只调训练集里出现过的弱分规则
    used = collections.Counter()
    for i in train:
        for t in tiers:
            for rules in t.weak[i].values():
                used.update(rules)
    candidates = sorted(r for r in used if crs[r][0] > 1)
    print("rows %d (attack %d, benign %d), train %d valid %d, weak rules seen %d" % (
        len(rows), sum(1 for r in rows if r[2]), sum(1 for r in rows if not r[2]), len(train), len(valid), len(candidates)))
    for line in table(rows, tiers, names, base, valid, "valid base   "):
        print(line)
    state = State(rows, tiers, weights, train)
    floor = [sum(1 for i in train if rows[i][2] and state.hit[(i, t)]) for t in range(len(tiers))]
    # waf-gap7：回归集（EVAL 行，训练+验证全部）里每条已拦截的攻击都不得变为放过
    # （S4 要求严格/极严格逐条不降）；训练集其余攻击只要求拦截数不低于基线
    guard = State(rows, tiers, weights, [i for i, r in enumerate(rows) if r[1] == "eval" and r[2]])

    def allowed(rid, w, changes):
        if not args.keep_tpr:
            return True, None
        lost = [0] * len(tiers)
        for i, t, now in changes:
            if rows[i][2]:
                lost[t] += -1 if now else 1
        if not all(state_tp[t] - lost[t] >= floor[t] for t in range(len(tiers))):
            return False, None
        trial = guard.trial(rid, w)
        return not any(not now for _, _, now in trial[2]), trial

    state_tp = list(floor)
    # 同一权重分数相同时取较大者（离严重度近，少改）
    for round_ in range(args.rounds):
        changed = 0
        for rid in candidates:
            keep = weights[rid]
            best = (state.objective(args.lam), keep, None)
            for w in range(base[rid], -1, -1):
                if w == keep:
                    continue
                tp, fp, changes = state.trial(rid, w)
                ok, guarded = allowed(rid, w, changes)
                if not ok:
                    continue
                value = state.objective(args.lam, tp, fp)
                if value > best[0] + 1e-12:
                    best = (value, w, (tp, fp, changes), guarded)
            if best[1] != keep:
                for i, t, now in best[2][2]:
                    if rows[i][2]:
                        state_tp[t] += 1 if now else -1
                state.commit(rid, best[1], *best[2])
                if best[3] is not None:
                    guard.commit(rid, best[1], *best[3])
                changed += 1
        print("round %d: %d rules changed, train objective %.5f" % (round_, changed, state.objective(args.lam)))
        if changed == 0:
            break
    for line in table(rows, tiers, names, weights, train, "train learned"):
        print(line)
    for line in table(rows, tiers, names, base, valid, "valid base   "):
        print(line)
    for line in table(rows, tiers, names, weights, valid, "valid learned"):
        print(line)
    changed = {rid: weights[rid] for rid in candidates if weights[rid] != base[rid]}
    print("learned weights differing from severity: %d" % len(changed))
    for rid in sorted(changed):
        print("  %d PL%d %s: %d -> %d" % (rid, crs[rid][0], crs[rid][2].split("-")[1], base[rid], changed[rid]))
    if args.out:
        json.dump({str(k): v for k, v in sorted(changed.items())}, open(args.out, "w"), indent=1)


if __name__ == "__main__":
    main()
