"""ri-03d plan A: the node-wide exclusion hook tree (hooks.conf).

Every site with automatic exclusions in force gets ONE phase-1 rule that
matches its site ID (TX:cdnca_site, from s= of the transaction ID) and
carries one ctl:ruleRemoveTargetById per exclusion. The rules are grouped by
the last two hex digits of the site ID (random in UUID v4 and v7): a first
level of up to 16 guards (last digit) and a second level of up to 16 guards
(the digit before it), each skipping its block when the digit differs. A
request evaluates at most 16 + 16 guards and the site rules of one bucket.

Measured (run.sh): libmodsecurity's phase loop visits every rule of the
phase, skipped or not (RulesSet::evaluate), so the tree does not make a
request O(sqrt N): about 26 ns per hook rule. Plan C therefore splits the
sites into buckets of at most BUCKET (env, default 128) sites; each bucket is
a location (the tier file plus its sites' rules, matched on the transaction
ID prefix since location rules run before the node rules) and Lua maps a
site to its bucket in one table lookup.

usage: gen.py <out dir> <targets per site> <IDs file> <count>...
Writes <out>/n<count>/{hooks.conf,sites.txt,buckets.txt,locations.conf,b/}; site
1 (the hot one) excludes (942100, q) first.
"""
import hashlib
import os
import sys

HEX = "0123456789abcdef"


def site_id(index):
    h = hashlib.sha256(b"%d" % index).hexdigest()
    return "%s-%s-4%s-8%s-%s" % (h[:8], h[8:12], h[13:16], h[17:20], h[20:32])


def hooks(sites, base_id=59000000):
    """sites: [(site ID, [(rule, collection, name)])] -> rule text"""
    buckets = {}
    for site, targets in sites:
        buckets.setdefault(site[-1], {}).setdefault(site[-2], []).append((site, targets))
    out = []
    next_id = [base_id]

    def rid():
        next_id[0] += 1
        return next_id[0]

    if buckets:
        out.append('SecRule TX:cdnca_site "@rx ([0-9a-f])([0-9a-f])$" "id:%d,phase:1,pass,nolog,t:none,capture,'
                   'setvar:tx.cdnca_x2=%%{TX.1},setvar:tx.cdnca_x1=%%{TX.2}"' % rid())
    for d1 in HEX:
        if d1 not in buckets:
            continue
        out.append('SecRule TX:cdnca_x1 "!@streq %s" "id:%d,phase:1,pass,nolog,t:none,skipAfter:CDNCA-X-%s"' % (d1, rid(), d1))
        for d2 in HEX:
            if d2 not in buckets[d1]:
                continue
            out.append('SecRule TX:cdnca_x2 "!@streq %s" "id:%d,phase:1,pass,nolog,t:none,skipAfter:CDNCA-X-%s%s"' % (d2, rid(), d1, d2))
            for site, targets in sorted(buckets[d1][d2]):
                ctl = ",".join("ctl:ruleRemoveTargetById=%d;%s:%s" % t for t in targets)
                # the site's rule: on a match, skip the rest of the tree
                out.append('SecRule TX:cdnca_site "@streq %s" "id:%d,phase:1,pass,nolog,t:none,%s,skipAfter:CDNCA-X-END"' % (site, rid(), ctl))
            out.append('SecMarker "CDNCA-X-%s%s"' % (d1, d2))
        out.append('SecMarker "CDNCA-X-%s"' % d1)
    if buckets:
        out.append('SecMarker "CDNCA-X-END"')
    return "\n".join(out) + "\n"


def main():
    out, per_site, ids_file = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    ids = open(ids_file).read().split()
    for count in [int(c) for c in sys.argv[4:]]:
        sites = []
        for index in range(1, count + 1):
            pairs = [(int(rule), "ARGS", "p%d_%d" % (index, n)) for n, rule in enumerate(ids)]
            if index == 1:
                pairs = [(942100, "ARGS", "q")] + pairs[1:]
            sites.append((site_id(index), pairs[:per_site]))
        directory = os.path.join(out, "n%d" % count)
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "hooks.conf"), "w") as f:
            f.write(hooks(sites))
        with open(os.path.join(directory, "sites.txt"), "w") as f:
            f.write("".join(s + "\n" for s, _ in sites))
        bucket = int(os.environ.get("BUCKET", "128"))
        os.makedirs(os.path.join(directory, "b"), exist_ok=True)
        with open(os.path.join(directory, "buckets.txt"), "w") as listing, \
                open(os.path.join(directory, "locations.conf"), "w") as locations:
            for number, start in enumerate(range(0, len(sites), bucket)):
                lines = ["Include /poc/gen/tier.conf"]
                for offset, (site, targets) in enumerate(sites[start:start + bucket]):
                    ctl = ",".join("ctl:ruleRemoveTargetById=%d;%s:%s" % t for t in targets)
                    lines.append('SecRule UNIQUE_ID "@beginsWith s=%s|" "id:%d,phase:1,pass,nolog,t:none,%s,skipAfter:CDNCA-XB"'
                                 % (site, 58000000 + offset, ctl))
                    listing.write("%s @cdnca_waf_b%d\n" % (site, number))
                lines.append('SecMarker "CDNCA-XB"')
                with open(os.path.join(directory, "b", "%d.conf" % number), "w") as bucket_file:
                    bucket_file.write("\n".join(lines) + "\n")
                locations.write("    location @cdnca_waf_b%d { modsecurity on; modsecurity_rules_file /poc/gen/n%d/b/%d.conf; "
                                "proxy_pass http://127.0.0.1:__ORIGIN__; }\n" % (number, count, number))


if __name__ == "__main__":
    main()
