#!/usr/bin/env python3
"""Rule attribution of STDRULE lines (run.sh STD_RULES=1, waf-cookie-fp).

rulestat.py <log> [tier index, default 2 = 严格防护] [corpus.jsonl.gz]
Prints the top 20 rules by requests hit, split by matched location
(REQUEST_COOKIES / REQUEST_COOKIES_NAMES / other), and, with the corpus,
the shape of the cookie values those rules matched.
"""
import base64, collections, gzip, json, re, sys, urllib.parse

log = sys.argv[1]
tier = int(sys.argv[2]) if len(sys.argv) > 2 else 2
corpus = sys.argv[3] if len(sys.argv) > 3 else None


def location(var):
    if var.startswith("REQUEST_COOKIES_NAMES"):
        return "cookie_name"
    if var.startswith("REQUEST_COOKIES"):
        return "cookie"
    return "other" if var else "unknown"


def shape(value):
    """Coarse structure of a cookie value."""
    v = urllib.parse.unquote(value)
    if re.fullmatch(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", v):
        return "jwt"
    if v[:1] in "{[":
        try:
            json.loads(v)
            return "json"
        except ValueError:
            return "json-like"
    if re.fullmatch(r"[0-9a-fA-F-]{16,}", v):
        return "hex/uuid"
    if re.fullmatch(r"[A-Za-z0-9+/_-]{16,}={0,2}", v):
        try:
            base64.b64decode(v + "=" * (-len(v) % 4), altchars=b"-_", validate=False)
            return "base64/token"
        except ValueError:
            pass
    if re.search(r"[|:$]", v) and re.search(r"[:=]", v):
        return "kv-packed"  # utag_main, CONSENTMGR, _ga-style
    if value != v:
        return "url-encoded"
    return "plain"


cookies = {}
if corpus:
    with gzip.open(corpus, "rt") as f:
        for line in f:
            r = json.loads(line)
            jar = {}
            for pair in r["headers"].get("cookie", "").split(";"):
                name, _, val = pair.strip().partition("=")
                jar[name] = val
            cookies[r["id"]] = jar

rules = collections.Counter()
by_loc = collections.defaultdict(collections.Counter)
shapes = collections.defaultdict(collections.Counter)
names = collections.defaultdict(collections.Counter)
requests = 0
only_cookie = 0
with open(log, errors="replace") as f:
    for line in f:
        if not line.startswith("STDRULE "):
            continue
        r = json.loads(line[8:])
        requests += 1
        matches = r["matches"][tier] or []
        seen = set()
        locs = set()
        for m in matches:
            loc = location(m["var"])
            locs.add(loc)
            key = (m["rule"], loc)
            if key in seen:
                continue
            seen.add(key)
            by_loc[m["rule"]][loc] += 1
            if loc == "cookie":
                name = m["var"].partition(":")[2]
                names[m["rule"]][name] += 1
                value = cookies.get(r["id"], {}).get(name)
                if value is not None:
                    shapes[m["rule"]][shape(value)] += 1
        for rule in {m["rule"] for m in matches}:
            rules[rule] += 1
        if locs and locs <= {"cookie", "cookie_name", "unknown"}:
            only_cookie += 1

print(f"requests={requests} tier={tier} only_cookie_or_unlocated={only_cookie}")
print("| 规则 | 命中请求 | Cookie 值 | Cookie 名 | 其他 | 未标位置 | 典型 Cookie 名 | Cookie 值形态 |")
print("|---|---|---|---|---|---|---|---|")
for rule, n in rules.most_common(20):
    loc = by_loc[rule]
    top = ", ".join(k for k, _ in names[rule].most_common(3))
    sh = ", ".join(f"{k} {v}" for k, v in shapes[rule].most_common(3))
    print(f"| {rule} | {n} | {loc['cookie']} | {loc['cookie_name']} | {loc['other']} | {loc['unknown']} | {top} | {sh} |")
