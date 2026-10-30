#!/usr/bin/env python3
"""Offline estimate (waf-cookie-fp2): count a cookie's weak score only when
the cookie deviates from the site's learned profile (ADR 0011 3.3 typed
parameters, cdnca_managed_waf.lua adapt.kind / adapt.misfit).

Learn per site (wafcomp-legit category) from the records outside the fast
subset (85%), evaluate on the fast subset (15%, the run-std.sh FAST=1 set):
a request "deviates" when some cookie of a typed name misfits (variant typed)
or, on a site whose cookie profile is mature, also when a cookie name was
never seen (variant names). The verdict of a deviating request is the one
with cookie weak scores, approximated as blocked after OR blocked before the
cookie change (an upper bound: before also lacks the detector changes); the
others keep the run after it.
cookieprofile.py <corpus jsonl.gz> <before run dir> <after run dir> [crs eval jsonl(.gz) before] [crs eval log after]
"""
import collections, glob, gzip, json, math, os, re, sys

TYPES = {"number": {"number"}, "ident": {"number", "ident"}, "binary": {"number", "ident", "binary"}}
CHARSET = [(r"['\"]", 1), (r"[<>]", 2), (r"[()]", 4), (r";", 8), (r"\|", 16), (r"`", 32), (r"\$", 64), (r"[{}]", 128),
           (r"%[0-9A-Fa-f]{2}", 256), (r"\s", 512), (r"[\x00-\x1f\x7f]", 1024), (r"[\x80-\xff]", 2048), (r"\\", 4096)]
CHARSET = [(re.compile(p), b) for p, b in CHARSET]


def kind(value):
    if re.fullmatch(r"-?\d+\.?\d*", value):
        return "number"
    if len(value) <= 64 and re.fullmatch(r"[A-Za-z0-9_.\-]+", value):
        return "ident"
    if re.fullmatch(r"[A-Za-z0-9+/_\-]+=*", value):
        return "binary"
    return "other"


def bucket(value):
    length, b = len(value.encode("latin1", "replace")), 0
    while length > 0 and b < 7:
        b, length = b + 1, length // 2
    return b


def charset(value):
    return sum(bit for pattern, bit in CHARSET if pattern.search(value))


def cookies(headers):
    raw = next((v for k, v in (headers or {}).items() if k.lower() == "cookie"), None)
    if not raw:
        return None
    out = []
    for pair in raw.split(";"):
        m = re.match(r"^\s*([^=]+)=(.*)$", pair)
        out.append((m.group(1), m.group(2)) if m else (pair.strip(), None))
    return out


def wilson_low(k, n, z=1.96):
    if n == 0:
        return 0.0
    p = k / n
    return (p + z * z / (2 * n) - z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / (1 + z * z / n)


def learn(stats, seen_min, text):
    """typed[name] = (type, max bucket, charset) by ADR 3.3 (seen, Wilson 99%);
    text: also profile untyped cookies (type check off, bucket and charset on)."""
    typed = {}
    for name, s in stats.items():
        if s["n"] < seen_min:
            continue
        chosen = None
        for t in ("number", "ident", "binary"):
            if wilson_low(sum(s["kind"][k] for k in TYPES[t]), s["n"]) >= 0.99:
                chosen = t
                break
        if chosen or text:
            typed[name] = (chosen or "text", s["bucket"], s["charset"])
    return typed


def misfit(entry, value):
    t, b, c = entry
    if t != "text" and kind(value) not in TYPES[t]:
        return True
    return bucket(value) > b or charset(value) & ~c != 0


def deviates(site, pairs, variant):
    prof = site["typed"][variant[0]]
    for name, value in pairs:
        if value is None or name not in site["names"]:
            if variant[1] and site["mature"]:
                return True
            continue
        entry = prof.get(name)
        if entry and misfit(entry, value):
            return True
    return False


def hits(path, dataset):
    out = {}
    for log in glob.glob(os.path.join(path, dataset + "-*.log")):
        for line in open(log, errors="replace"):
            if line.startswith("STDHIT "):
                out[line.split()[2]] = re.search(r"tiers=(\d+)", line).group(1)
    return out


corpus, before_dir, after_dir = sys.argv[1:4]
seen_mins = (1000, 200)
stats = collections.defaultdict(lambda: collections.defaultdict(lambda: {"n": 0, "kind": collections.Counter(), "bucket": 0, "charset": 0}))
requests = collections.Counter()
evaluate = []
for line in gzip.open(corpus, "rt"):
    r = json.loads(line)
    pairs = cookies(r.get("headers"))
    if r.get("fast"):
        evaluate.append((r["category"], r["id"], pairs))
        continue
    requests[r["category"]] += 1
    for name, value in pairs or ():
        if value is None:
            continue
        s = stats[r["category"]][name]
        s["n"] += 1
        s["kind"][kind(value)] += 1
        s["bucket"] = max(s["bucket"], bucket(value))
        s["charset"] |= charset(value)
sites = {}
for cat, st in stats.items():
    for seen_min in seen_mins:
        site = sites.setdefault(cat, {"names": set(st), "typed": {}, "mature": requests[cat] >= 1000})
        site["typed"][(seen_min, False)] = learn(st, seen_min, False)
        site["typed"][(seen_min, True)] = learn(st, seen_min, True)
before, after = hits(before_dir, "wafcomp-legit"), hits(after_dir, "wafcomp-legit")
variants = [((m, t), u) for m in seen_mins for t in (False, True) for u in (False, True)]
label = lambda v: f"seen>={v[0][0]} {'text+typed' if v[0][1] else 'typed'} {'unknown-name' if v[1] else 'known-only'}"
n = len(evaluate)
for tier in ("2", "3"):
    base = sum(tier in after.get(i, "") for _, i, _ in evaluate)
    print(f"tier {tier}: fast legit {n}, blocked after {base} ({base / n:.2%}), before {sum(tier in before.get(i, '') for _, i, _ in evaluate) / n:.2%}")
    for v in variants:
        dev = blocked = 0
        for cat, i, pairs in evaluate:
            d = bool(pairs) and cat in sites and deviates(sites[cat], pairs, v)
            dev += d
            blocked += (tier in after.get(i, "")) or (d and tier in before.get(i, ""))
        print(f"  {label(v)}: deviating {dev} ({dev / n:.2%}), blocked {blocked} ({blocked / n:.2%}, {blocked - base:+d})")
typed_counts = collections.Counter()
for cat, site in sites.items():
    for key, prof in site["typed"].items():
        typed_counts[key] += len(prof)
print("profiled cookie names total:", dict(typed_counts), "sites mature", sum(s["mature"] for s in sites.values()), "of", len(sites))

if len(sys.argv) > 5:
    def load(path):
        opener = gzip.open if path.endswith(".gz") else open
        return {row["id"]: row for row in (json.loads(l[5:]) for l in opener(path, "rt", errors="replace") if l.startswith("EVAL "))}
    crs_before, crs_after = load(sys.argv[4]), load(sys.argv[5])
    caught = lambda row, t: row["tiers"][t] or row["challenged"][t]
    mature = [s for s in sites.values() if s["mature"]]
    for t in (2, 3):
        lost = [i for i, row in crs_before.items() if row["attack"] and caught(row, t) and not caught(crs_after[i], t)]
        print(f"CRS tier {t}: lost {len(lost)}")
        for v in variants:
            recovered = 0.0
            for i in lost:
                pairs = cookies(crs_after[i].get("headers")) or []
                recovered += sum(deviates(s, pairs, v) for s in mature) / len(mature)
            print(f"  {label(v)}: recovered {recovered:.1f} (averaged over {len(mature)} mature site profiles)")
    # the same payloads in a cookie the site did type: share of (site, typed
    # cookie) pairs where the payload value misfits (typed variant, ADR rule)
    for t in (2, 3):
        lost = [i for i, row in crs_before.items() if row["attack"] and caught(row, t) and not caught(crs_after[i], t)]
        values = [v for i in lost for _, v in (cookies(crs_after[i].get("headers")) or []) if v]
        hit = total = 0
        for s in mature:
            for entry in s["typed"][(1000, False)].values():
                for value in values:
                    total += 1
                    hit += misfit(entry, value)
        print(f"CRS tier {t}: payloads ({len(values)} values) in typed cookies of mature sites: misfit {hit}/{total} ({hit / max(total, 1):.1%})")
