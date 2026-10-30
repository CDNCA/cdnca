# Edge OpenResty runtime

> 容器镜像与原生节点包同源（FX19）：`Dockerfile` 的 builder 阶段与
> `native/Dockerfile` 相同（同一 `build_base`、`native/sources.lock.json`、
> `native/patches/` 01–23、共用 `native/build-openresty.sh`），整套
> `/usr/local/openresty` 复制进镜像，所以 OpenResty 1.31.1.1（nginx 1.31.1 +
> 回补补丁 + JA4 + TOA）、LuaJIT 与 Lua/C 模块和原生包一致。生产节点仍由
> `scripts/install-node.sh` 安装签名原生包。`tests/edge-openresty-runtime-parity.test.mjs`
> 校验两份 Dockerfile 的源码/补丁/配方一致，`runtime-parity-smoke.sh` 对比构建出的
> 两个镜像（`nginx -V`、补丁数、Lua 清单）。

`runtime.env` pins the source (`OPENRESTY_VERSION`, tarball URL/SHA-256, equal to
`native/sources.lock.json`), the build base (`OPENRESTY_BUILD_IMAGE`, the lock's
`build_base.reference`) and the runtime base (`OPENRESTY_IMAGE`, the official
`1.31.1.1-alpine-fat` image by digest: it keeps perl for `resty` and the curl and
toolchain the smoke harnesses use; its `/usr/local/openresty` is overwritten).
Smoke scripts that run `${OPENRESTY_IMAGE}` directly exercise stock, unpatched
OpenResty of the same release; scripts that call `scripts/edge-runtime-build.sh`
exercise the patched build. The build checks `openresty -V`, the bundled
`sources.lock.json`/`source-verification.json` (under
`/usr/local/share/cdnca/runtime/`), the JA4 module, `proxy_toa` and the dynamic modules.

The container expects `/var/lib/cdnca-edge/current` to be the edge Agent's
atomic symlink into `/var/lib/cdnca-edge/releases/`. Every release must contain
`nginx.conf` and must keep process state such as the PID and mutable logs under
`/var/lib/cdnca-edge/shared/`, not inside the immutable release directory.

Build and run the real activation smoke test with:

```sh
./scripts/edge-runtime-build.sh
./scripts/edge-runtime-smoke.sh
./scripts/edge-site-smoke.sh
./scripts/edge-cache-smoke.sh
./scripts/edge-l4-smoke.sh
./scripts/edge-firewall-smoke.sh
./scripts/edge-runtime-repro.sh
./scripts/edge-runtime-linux-smoke.sh
```

The smoke test builds the same source twice and forces the second build to
bypass the layer cache. It requires identical runtime configuration, pinned
base layers, and entrypoint bytes. It also reports whether the exported image
IDs match. On the current Docker Desktop/BuildKit setup, no-cache builds have
produced different entrypoint-layer DiffIDs despite matching configuration,
base layers, creation time, and entrypoint bytes. Byte-identical image IDs are
therefore not currently a release claim.

`edge-runtime-repro.sh` uses a pinned Linux BuildKit container and the OCI
exporter's timestamp rewrite. It builds twice without cache and requires the
two OCI manifest digests to match. The script first verifies that the local
Docker store carries the exact pinned OpenResty repo digest, then passes its
unmodified OCI layout to BuildKit; the fixed builder does not need Docker Hub
access for the OpenResty base. The pinned BuildKit image itself must already be
available or be pulled once. This is the release reproducibility gate. The
Docker Desktop image-store observation above remains visible diagnostic
evidence rather than the release identity.

The test publishes container port 18080 to a Docker-selected loopback port and
removes its containers, image tags, and temporary state on exit. It applies a
baseline, reloads a healthy second release, injects an unhealthy third release
to force rollback, and submits an invalid fourth release to prove precheck
failure leaves the running release unchanged. It then starts a fresh container
through the production entrypoint and verifies the persisted active release
again.

The site data-plane smoke builds generated site bundles and sends real requests
through OpenResty to task-owned origins. It covers the five supported balancing
methods, IPv4/domain/IPv6 origins, GET and HEAD failover without replaying POST,
a standards-compliant WebSocket session that remains usable across one same-node
non-port-changing reload, and range responses for single, multipart, suffix,
open-ended, and unsatisfiable requests. It verifies each range's `Content-Range`,
payload, and declared length. Business-origin failure is deliberately excluded
from activation health, while runtime-health failure rolls back through the same
Manager used for normal activation.

HTTP caching is a partial edge-runtime slice with explicit `disabled`,
`follow_origin`, and `override` modes. Enabled sites have bounded per-site key
zones and disk limits, a default TTL for 200/301/302, optional sorted per-status
TTLs, and an explicit stale-on-upstream-error switch. Cache paths are derived
from the validated Agent state root and a stable hash of the canonical site
domain and listen port; callers cannot provide a filesystem path. The cache key
contains the canonical domain, listen port, normalized URI, and query string.

Only GET and HEAD are eligible. Requests carrying Authorization, Cookie,
Upgrade, or Range are bypassed. Responses carrying Set-Cookie or Cache-Control
`private`, `no-store`, or `no-cache` are not stored even in override mode.
Override ignores ordinary origin expiry metadata and applies the configured TTL;
follow-origin continues to honor origin expiry metadata. Site responses expose
only `X-CDN-Cache: HIT`, `MISS`, or `BYPASS`, plus the active config version;
upstream attempts to supply either edge-owned header are hidden.

`edge-cache-smoke.sh` uses origin request counters and real OpenResty traffic to
prove disabled bypass, follow-origin/no-store/private/Set-Cookie behavior,
override TTL, GET/HEAD sharing, POST/authentication/session bypass, status TTLs,
query/domain/port isolation, expiration, stale-on-502, healthy reload, real
`openresty -t` rejection, and health rollback. A rollback can briefly leave old
and restored workers both observable on a business port, so the smoke disables
keep-alive and requires 20 consecutive restored-version responses before its
post-rollback cache assertion.

Before invoking OpenResty precheck, the deployment Manager creates
`${state_root}/shared/cache` with owner-only permissions and rejects symlinks or
an existing cache directory with broader permissions. The node-local
`internal/cachetask` executor now provides durable exact URL, segment-bounded
directory, and whole-site purge plus bounded URL-list prewarm through the active
loopback listener. The real runtime smoke proves purge `MISS`/refill, prewarm
`HIT`, query isolation, and site availability after task failure. See
`docs/runbooks/cache-task-execution.md` for the schema and safety model.

This remains partial at platform scope. Ordered suffix/full-path policy rules,
ignore-query options, Range/206 caching, Vary acceptance coverage, cache-lock
tuning, capacity telemetry, eviction alerts, control-plane/API/UI delivery,
Gateway/JetStream commands, multi-node fan-out, and distributed completion are
not implemented or claimed.

Each HTTP/HTTPS site has an explicit native OpenResty ACL. Ordered IPv4 and IPv6
CIDR rules render as Nginx `allow`/`deny` directives followed by an explicit
default action, so the policy is isolated by the site's domain and listen port.
The Agent rejects missing or unknown actions, invalid or unsafe CIDRs, duplicate
or fully shadowed rules, and policies over 256 rules before activation.

Sites may also carry up to 128 ordered WAF rules. A rule's configured method,
normalized path (exact or segment-bounded prefix), request header (existence or
exact value), and source IPv4/IPv6 CIDR are combined with AND. `allow+continue`
evaluates later rules, `allow+stop` stops only WAF evaluation, and `deny+stop`
returns 403. `deny+continue` is invalid; an unmatched request is allowed. A stop
rule that completely covers a later rule is rejected as making that rule
unreachable.

WAF evaluation runs first in Nginx's rewrite phase. The native ACL then runs in
the access phase, so a WAF allow never bypasses the site's ACL. Source matching
uses native `geo`; a small generated Lua block only combines request-local method,
`$uri`, header, and geo results. It performs no I/O, DNS, network, control-plane,
or shared-state access. More than 100 request headers fails closed with 403, and
duplicate values never satisfy an exact header match. Configured paths must be
canonical ASCII paths without percent encoding, query/fragment syntax,
backslashes, duplicate slashes, or dot segments; incoming paths are matched
against Nginx's normalized URI.

The site smoke proves ACL and WAF 403 responses carry the active config version
and never reach the origin. It also covers ordered continue/stop behavior,
multi-condition AND, normalized and prefix paths, IPv4/IPv6 source matching,
domain/port isolation, WAF-before-ACL behavior, reload, and rejected candidates
leaving the active version and health unchanged.

This slice is not a complete OWASP or bot-management engine. Regex and query/body
matching, custom response bodies, CC rate limiting and challenges, JA4, dynamic
lists, rule telemetry, and control-plane/API/UI management remain separate work.

The edge Agent also has a standalone Linux nftables firewall publisher. It owns
only `inet cdnca_firewall`, compiles normalized source CIDRs into separate IPv4
and IPv6 allow/deny interval sets, and places allow rules before deny rules in a
node-wide input hook. The compiler rejects unsafe all-address, multicast,
link-local, mapped, zoned, unspecified, conflicting, expired, and oversized
candidates. Source, reason, and expiration metadata stay in Agent state files
with mode `0600`; they are never rendered into nftables commands.

Each firewall version is checked with `nft --check`, applied as one transaction,
confirmed through structured `nft --json` output, and marked active only after
the running table exposes the expected version and digest. Publication is
serialized across Agent processes, exact task results survive restart, and a
failed apply or health confirmation restores the prior immutable version.
Expiration creates a new version instead of mutating history.

`edge-firewall-smoke.sh` runs in a privileged, isolated Linux network namespace
and proves real IPv4/IPv6 deny behavior, allow precedence, v1-to-v2 replacement,
rejection and real `nft --check` failure leaving v2 active, restart recovery, and
preservation of a non-owned sentinel table. It removes both smoke tables, its
container, image tag, and temporary state on exit. The current P0 policy matches
source CIDR only. Control-plane delivery, site/rule attribution, destination-port
matching, dynamic feed convergence, iptables/ipset compatibility, counters and
telemetry, systemd integration, and isolated-VM release acceptance remain open.

The HTTPS site enables downstream HTTP/2 with the current `http2 on` directive,
not the deprecated `listen ... http2` parameter. The smoke requires a Go TLS
client to negotiate ALPN `h2` and report HTTP major version 2, then requires a
separate client offering only `http/1.1` to fall back successfully. The HTTPS
check proves only the edge TLS bundle and handshake; ACME issuance, secret
storage, renewal, rotation, and control-plane delivery remain separate work.

DNS origin names are currently resolved when OpenResty starts or reloads a
configuration. TTL-driven re-resolution and automatic convergence after a DNS
answer changes are not current runtime claims.

The stream smoke uses the same generated `nginx.conf`, deployment Manager,
health probe, immutable releases, and rollback path as the HTTP site smoke. It
verifies bidirectional TCP byte accounting, interleaved datagrams from two UDP
clients without cross-session payloads, an IPv6 upstream, and an upstream
PROXY protocol v1 header whose loopback source/destination addresses and ports
match the real test connection. With an unavailable business upstream, the
client connection fails while `cfg-v2` and its runtime health remain active. A
separate upstream that accepts bytes but stays silent is closed at the configured
250 ms stream response timeout without changing the active version.
An established TCP connection continues to use its `cfg-v1` upstream across one
same-port reload while a new connection uses the `cfg-v2` upstream. A failed
`cfg-v3` runtime-health check still reverts through the shared Manager.

TCP and UDP may use the same numeric port because they own separate kernel
sockets; duplicate listeners for the same transport and port are rejected.
Stream ports may not overlap the runtime health port or any HTTP/HTTPS site
port. Multi-port shortcut parsing, stream UI/control-plane CRUD, monitoring,
ACL/region policy, UDP QUIC semantics, kernel tuning, and multi-node switching
are not part of this edge-only slice. UDP currently uses one expected upstream
response per proxied datagram session; one-way and multi-response UDP protocols
need an explicit model and separate acceptance tests. PROXY protocol v1 is
accepted only for TCP streams; UDP PROXY protocol v2 is not implemented.

The Linux smoke starts real PID 1 systemd containers for Debian 12 and Ubuntu
24.04. It verifies non-root start/reload/stop/crash recovery, the unit sandbox,
immutable releases, shared runtime writes, and fail-closed behavior for a
missing `current` link, invalid configuration, and unreadable release. Native
package builds and upgrades, firewall integration, HTTP/3 kernel tuning, and
isolated-VM acceptance remain separate release gates.

HTTP/3/QUIC, DNS TTL re-resolution, multi-node cache behavior and draining, and
upgraded-connection survival across repeated or disruptive reloads are not
proven. The current long-connection result is limited to one local OpenResty
instance and one configuration-only reload that keeps the listen ports stable.
