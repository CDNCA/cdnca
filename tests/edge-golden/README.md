# Edge behaviour golden (ADR 0009 §5)

What the edge runtime does for a fixed corpus of site facts and requests,
recorded against a real OpenResty. The corpus was recorded by the per-site
`server{}` (v7) compiler, deleted in 1.0.35 (dr-d13-c3b); the dynamic routing
runtime (ADR 0009) is checked against it. The directory keeps its `cdnca-v7`
name.

```
tests/edge-golden/
  run.sh                     record | check | selfcheck, in the node runtime image
  cdnca-v7/scenarios/*.json  site facts, mock origins, steps (input)
  cdnca-v7/expected/*.json   recorded observations (the golden)
  cdnca-v7/compare.json      differences that are not defects
```

Code: `agents/edge-agent/internal/edgegolden` (scenario format, runner,
clients, mock origins, normalization, diff), `.../edgegolden/goldendyn` (the
renderer), `.../edgegolden/cmd/cdnca-edge-golden` (CLI).

## Running

```sh
tests/edge-golden/run.sh check                 # run every scenario, diff against expected/ (exit 1 on a defect)
tests/edge-golden/run.sh check cache,cc        # only these scenarios
tests/edge-golden/run.sh selfcheck             # record twice: run 2 vs run 1, then run 1 vs expected/
tests/edge-golden/run.sh record [names]        # (re)write expected/ for these scenarios (default all)
```

`run.sh` builds the CLI for the Docker host's architecture, copies this
checkout's node Lua tree (as `edge/openresty/native/Dockerfile` installs it)
and runs `docker run --rm --network none --cpuset-cpus 0 --user 65534:65534` on
`cdnca-native-runtime:edge-golden` (built from that Dockerfile `--target runtime`
when missing). One CPU means one worker, so round robin positions and worker
state are the same on every run. Observations and the JSON report go to
`CDNCA_EDGE_GOLDEN_OUT` (default a printed temporary directory).

Step kinds beyond http/tls/websocket: `publish` activates a new document
(and certificate versions) in place as the agent's index-only activation
(a port profile change is refused: it needs a reload); `connection` names a
kept-alive client connection (`reused` in the observation); `proto: "h3"`
sends over HTTP/3 with the D9 probe (`tests/dynroute-filters/probe -full`,
built by `run.sh`); `tcp` / `udp` exchange one line / datagram with
`stream` origins. `facts.node.workers` pins `worker_processes`.

Scenarios that require `l4` run in a second, root container
(`--cap-add SYS_PTRACE`): the node's L4 runtime runs as root and checks its
OpenResty's process identity. `http3` is recorded on arm64 Docker; under
Rosetta (amd64 image on Apple silicon) QUIC is unreliable and needs a real
amd64 host.

The managed WAF scenario needs the ModSecurity extension
(`scripts/security/modsecurity-runtime.sh`, cached under
`~/.cache/cdnca-modsecurity`); without it that scenario is reported
`SKIPPED` (`check -strict` fails on skips). Other variables: see the header of
`run.sh`.

Renderer: `cdnca-dynroute` (default), the scenario's signed site runtime v2
release converted into site objects by the control plane's own conversion
(control-api `cmd/cdnca-site-objects-v2`) and served by the dynamic routing
skeleton (`edgeskeleton.Render`, `cdnca_dynroute` entry). A renderer converts
`facts` (the control plane output) into its own inputs.

## Corpus (33 scenarios)

| scenario | covers |
|---|---|
| host-routing | Host selection on one port: primary, alias, leading wildcard (one/two levels), exact beats wildcard, longest wildcard, case, Host with port, unknown Host, IP Host, IPv6 listener |
| tls-sni-host | certificate by SNI (exact, wildcard, unknown, none), TLS 1.2/1.3, ALPN, HTTP/2, **SNI and Host naming different sites**, plain HTTP on a TLS port |
| load-balancing | round robin (equal, weighted), ip_hash, url_hash, random (summary only), least_conn |
| retry-failover | refused origin -> next, 502/503/504 retried, 500/404 and POST not retried, read timeout -> next, single origin 504, all down 502 |
| forwarding | origin Host and headers, client X-Forwarded-*, hop-by-hop headers, methods, fixed/chunked/large bodies, URI encoding, response headers, gzip, 300 KB response, truncated origin response, 204, 6 KB header |
| cache | override HIT/MISS, alias keys, query preserve/ignore, Set-Cookie / no-store / 404 bypass, POST, rule routes (extension cache, prefix no-cache), follow_origin, cache keys on disk, purge URL/directory/site, prewarm |
| cache-ge | Cookie bypasses only paths no cache rule matches, prefix no-cache BYPASS with reason, Range cut from the cached full object (origin asked without Range), max object size BYPASS `object_size` |
| websocket-range | WebSocket upgrade on/off, Range single/suffix/multi/416/If-Range |
| force-https | 301 to the HTTPS port (path, query, POST), ACME HTTP-01 still proxied, HTTPS served |
| origin-tls | HTTPS origin: trusted CA and SNI, untrusted CA 502, SNI mismatch 502 |
| http-policy | request/response header add/set/delete, rewrites, 301/302/307/308 redirects, CORS preflight/simple, upload limit 413 (fixed and chunked) |
| site-access | host redirect (URI kept, ACME excepted), forced HTTPS 308 with an excluded domain, HSTS on HTTPS only, site gzip types, basic auth (credential not forwarded, excluded prefix, wrong password), maintenance page with an allowed network |
| http-rules | regex rewrite to the origin with captures, regex redirect with escaped captures, prefix redirect keeping the path suffix (and query), a plain prefix redirect that does not |
| acl-waf | source IP ACL, path allow before deny, header exact/exists, method, path exact/prefix and bypass attempts (case, encoding, dot segments, double slash), default deny |
| error-pages | custom pages by category (origin_response, edge_connect global/site, edge_route), untouched statuses |
| unknown-site | domain mismatch: a Host no site serves gets the global unknown_site page with its status (410), a site's own origin 404 passes through |
| cc | CC v2 fixed window 429, temporary ban, always -> challenge redirect, log action, per-IP counting, client ban queued once for the kernel ban (`<health>/cc-kernel-bans`) |
| js-challenge | click challenge page, alias, bypass routes, non-HTML Accept, forged cookie |
| l2-fallback | via L2, direct fallback when L2 is down |
| access-logs | signed telemetry access log fields and WAF security events |
| managed-waf | OWASP CRS: clean, SQLi/XSS in query and form blocked, allow CIDR (requires `managed_waf`) |
| waf-ge | WAF v2 (ge-waf): named query value, multipart upload extension, empty UA (length filter, missing header), base64 filter, not_contains log, challenge page (GET) and 307 (POST), temporary ban, auto block, observe mode, attack evidence in the security log |
| origin-forwarding | client address headers not forgeable (trusted proxy keeps the chain), Location naming the origin rewritten, custom / origin Host, backup origin, sticky cookie pinning, WebSocket Origin allowlist 403, HTTPS origin verified against the node CAs (SNI = origin Host) |
| package-limits | package connection budget 0 -> 503; package bandwidth budget renders the shared in-flight rate split (responses unchanged, only throttled) |
| site-traffic-limit | site over its own traffic cap: 509 + custom or default notice page for every method, ACME HTTP-01 path exempt, a site within its caps unaffected |
| ipv6-origin | IPv6 literal origin (`::1`): peer, visitor Host, `request_host` origin as `[::1]:port`, IPv4 refused -> IPv6 retry, mixed-family round robin, IPv6 client address headers |
| cert-rotation | a site's certificate version rotated by an index-only publication (no reload): a kept-alive connection keeps going (`reused`, old certificate), new handshakes get the new one, the other site on the port untouched |
| multi-worker | `workers: 2`: after each index activation every worker serves the new objects (origin switch, alias added, site removed -> 421, wildcard), CC fixed window counted across workers (shared dict) |
| http3 | Alt-Svc only for the h3 site, h3 GET/HEAD/POST/large bodies to the origin as h1/h2, QUIC refused for a site without h3 and an unknown SNI (requires `http3`) |
| l4-streams | v2 L4 forwards on the agent's dynamic routing runtime + node L4 runtime: TCP, UDP, TLS passthrough by SNI on a TLS website port (sites handed to the skeleton, PROXY protocol), origin switch, removal frees the ports (requires `l4`) |
| schedule302 | HTTP 302 scheduling: large files redirected per client to different nodes (path and query kept, signed landing path, no-store), the followed landing served with the original Host/URI and no scheduling headers at the origin; other extensions, POST and an unscheduled site served in place; forged landing signature and forged token header 403 |

Recorded v7 behaviour worth knowing before a new runtime is judged against it
(the golden records it as is; whether it should change is a decision, see
"Semantic changes"):

- `tls-sni-host/sni-shop-host-blog-*`: when SNI and Host name two sites of
  one port, v7 already routes by Host (HTTP/1.1 and HTTP/2), serving the SNI's
  certificate. `.../sni-shop-host-unknown` and `.../sni-shop-host-legacy`: a
  Host no site of that port serves (unknown, or a site on another port)
  answers **421**, as a plain Host miss does (`host-routing/unknown-host`).
  BATCH-PLUGIN item 12 makes "route by Host, never 421 for an SNI/Host
  mismatch" the D4 semantics.
- `forwarding/spoofed-xff`: the edge sets `X-Forwarded-For` and `X-Real-IP`
  to its peer and `X-Forwarded-Proto` to the scheme (a client cannot forge
  them; ge-origin 10-18 re-recorded every scenario for these three headers);
  `X-Forwarded-Host`, `Proxy-Authorization` and a header named by
  `Connection` are forwarded untouched. `forwarding/origin-redirect`: a
  Location naming the origin is rewritten to the visitor's host.
- Scenarios declare site_runtime 6 (the 1.0.35 floor); with
  2–5 every one but five failed to start.
- `cache/rule-other-*`: with rule routes (cache policy v2) a path no rule
  matches is not cached (BYPASS, `X-CDN-Cache-Reason: no_cache_rule`).
- `cache/entries-*`: cache keys carry the site's cache generation
  (`v2|tenant|site|<generation>|host|port|uri`), not the config version: a
  publication that does not change cache semantics keeps every object.
- `cc/banned-elsewhere`: a `temporary_ban` rule's ban applies to that rule's
  path only.
- `websocket-range/range-off-site`: `range: false` does not stop an origin's
  206.
- `retry-failover/no-retry-500`: 500 is not a retry condition.

## Observations

One JSON file per scenario, `cdnca.edge-golden.observation/v1`: per step what
the client saw (status, protocol, headers, body as length + SHA-256 + text up
to 8 KiB, TLS version/ALPN/certificate serial and names and whether it
verifies), every request the mock origins received for it in order (method,
URI, Host, headers, body, peer, SNI), cache task results, cache keys on disk,
and drained log records. `scenario_sha256` binds a golden to the exact
scenario file: an edited scenario is `stale_golden` until recorded again
(`TestCorpusGoldenMatchesScenarios` checks this without Docker).

What differs from run to run is masked before recording, never compared:
`Date`/`Age`, request IDs, timing and connection log fields, plus per-scenario
`mask` entries (challenge nonces and tokens, multipart boundaries, WebSocket
keys). Keys and certificates are generated per run; only names, serials and
issuers are recorded. Anything else that differs is a defect.

## Comparing

`check` runs a renderer and diffs; `diff -expected DIR -actual DIR` diffs two
directories of observations (`selfcheck` uses it). Differences are reported per
path `<scenario>/<step>/<field>/...` as `changed`, `missing` or `extra`, as
text and as JSON (`-report`). `compare.json` waives differences that are not
defects:

- `incomparable`: implementation details any runtime may change (e.g. a
  `server` header), for every renderer;
- `semantic_changes`: documented behaviour changes (ADR 0009 §6), for the
  renderers listed, each with its reason.

Rule paths are `/`-separated segments; `*` matches one segment (path.Match
within it), `**` any number, and a rule matching a prefix covers the subtree.
Every rule needs a reason.

## Adding or changing a scenario

1. Write or edit `cdnca-v7/scenarios/<name>.json` (format: `Scenario` in
   `edgegolden/scenario.go`; `facts.document` is the site runtime v2 document
   as control-api publishes it, `${trust:<ca>}`, `${http_policy_sha256}` and
   `${deployment_root}` are filled in at run time; ports must not collide with
   other scenarios'.
2. `tests/edge-golden/run.sh record <name>`, read the golden, then
   `tests/edge-golden/run.sh selfcheck <name>`: a scenario must reproduce
   before it is committed.
3. Commit the scenario and its golden together. Re-recording an existing
   golden replaces v7's recorded behaviour with the dynamic routing runtime's:
   do it only for a documented behaviour change.
