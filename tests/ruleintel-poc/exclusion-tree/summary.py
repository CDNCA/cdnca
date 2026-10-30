import sys,json,collections,statistics as s
d=collections.defaultdict(list)
for l in open(sys.argv[1]):
    if not l.startswith("round"): continue
    p=l.split(None,4); j=json.loads(p[4]); d[(p[2],p[3])].append((j["p50_ms"],j["p99_ms"]))
for k,v in sorted(d.items()):
    print("%-8s %-6s p50 %.3f p99 %.3f  (%d rounds)" % (k[0],k[1],s.median(x[0] for x in v),s.median(x[1] for x in v),len(v)))
