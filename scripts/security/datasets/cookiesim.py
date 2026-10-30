#!/usr/bin/env python3
"""Offline replay of STDRULE lines (waf-cookie-fp): two-level set decisions
under different treatments of cookie-located weak hits.
cookiesim.py <STDRULE log> <crs rules dir> <profile json> [tier index]
Treatments: now (as rendered), drop (weak rules ignore cookies), gate (cookie
weak counts only when the set has non-cookie evidence), half (cookie weak x0.5).
A request is blocked when a set's strong >= threshold or strong+weak >= W.
"""
import collections, glob, json, os, re, sys

log, crsdir, profile = sys.argv[1:4]
tier = int(sys.argv[4]) if len(sys.argv) > 4 else 2
SEV = {"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2}
rules = {}
for path in glob.glob(os.path.join(crsdir, "REQUEST-9*.conf")):
    text = open(path).read()
    fname = os.path.basename(path)
    for block in re.split(r"\nSecRule ", text):
        m = re.search(r"id:(\d+)", block)
        if not m:
            continue
        pl = re.search(r"paranoia-level/(\d)", block)
        sev = re.search(r"severity:'?(\w+)", block)
        rules[m.group(1)] = (fname, int(pl.group(1)) if pl else 1, SEV.get(sev.group(1).upper(), 0) if sev else 0)
pack = json.load(open(profile))
sets = []
for r in pack["rules"]:
    c = r["crs"]
    sets.append((r["id"], c["files"], set(map(str, c.get("include_ids") or [])), set(map(str, c.get("exclude_ids") or [])),
                 c["paranoia"], c["threshold"], c.get("strong_paranoia", 0), c.get("weak_threshold", 0)))


def set_of(rule):
    f = rules.get(rule)
    if not f:
        return None
    for s in sets:
        if rule in s[3]:
            continue
        if rule in s[2] or any(f[0].startswith(p + "-") for p in s[1]):
            return s
    return None


def cookie(var, nocookie_req):
    return var.startswith("REQUEST_COOKIES") or var.lower() == "request_headers:cookie" or (var == "" and nocookie_req)


out = collections.Counter()
n = 0
for line in open(log, errors="replace"):
    if not line.startswith("STDRULE "):
        continue
    r = json.loads(line[8:])
    n += 1
    ms = r["matches"][tier] or []
    unlocated_is_cookie = all(m["var"] == "" or m["var"].startswith("REQUEST_COOKIES") for m in ms)
    for treat in ("now", "drop", "gate", "half"):
        acc = collections.defaultdict(lambda: [0.0, 0.0, 0.0, False])  # strong, weak non-cookie, weak cookie, evidence
        for m in ms:
            s = set_of(m["rule"])
            if not s:
                continue
            _, pl, sev = rules[m["rule"]]
            a = acc[s[0]]
            ck = cookie(m["var"], unlocated_is_cookie)
            if pl <= s[6] or s[6] == 0:
                a[0] += sev
                if not ck:
                    a[3] = True
            elif ck:
                a[2] += sev
            else:
                a[1] += sev
                a[3] = True
        blocked = False
        for s in sets:
            if s[0] not in acc:
                continue
            st, wn, wc, ev = acc[s[0]]
            if treat == "drop":
                wc = 0
            elif treat == "gate" and not ev:
                wc = 0
            elif treat == "half":
                wc *= 0.5
            if st >= s[5] or s[7] and st + wn + wc >= s[7]:
                blocked = True
        out[treat] += blocked
print(f"requests={n} tier={tier}", {k: f"{v} ({v / max(n, 1):.1%})" for k, v in out.items()})
