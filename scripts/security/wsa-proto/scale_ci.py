"""ri-03d: per round paired extra p50/p99 of the automatic exclusions
(cdnca-waf-check -only scale -scale-targets N: each round runs "waf" then
"waf-<sites>x<targets>"), median and a 95% bootstrap interval of the median.
usage: scale_ci.py <run.sh log>"""
import random
import re
import statistics
import sys

rounds = {}
for line in open(sys.argv[1]):
    m = re.match(r"INFO round (\d+) (\S+) p50=(\d+)us p90=\d+us p99=(\d+)us", line)
    if m:
        rounds.setdefault(int(m[1]), {})[m[2]] = (int(m[3]), int(m[4]))
pairs = [(r["waf"], v) for r in rounds.values() for k, v in r.items() if k.startswith("waf-")]
for label, index in (("p50", 0), ("p99", 1)):
    diffs = [ex[index] - base[index] for base, ex in pairs]
    random.seed(1)
    boots = sorted(statistics.median(random.choices(diffs, k=len(diffs))) for _ in range(10000))
    print("extra %s us: n=%d median %+.0f 95%% CI [%+.0f, %+.0f] rounds %s base median %.0f" % (
        label, len(diffs), statistics.median(diffs), boots[250], boots[9749], diffs,
        statistics.median(base[index] for base, _ in pairs)))
