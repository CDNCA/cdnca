# Native OpenResty source lock

This directory prepares **source only** for the native node build. It does not
authorize a release, sign a package, install a service, or declare protocol tests
successful. `build-openresty.sh` is the one download/verify/configure/install
recipe; the container image (`../Dockerfile`) runs the same builder stage, so
both ship the same OpenResty (FX19). `security-release/runtime-lock.json` now
names this source, but its `release_eligible: false` gate must not be bypassed.

## Reproduce the verified source

Requirements: Node.js 22 or newer, GnuPG (`gpg` and `gpgv`), tar, and patch.
Download the exact `source.url` from `sources.lock.json`, then run:

```sh
node edge/openresty/native/verify-sources.mjs \
  /path/openresty-1.31.1.1.tar.gz /path/new-openresty-source

CDNCA_OPENRESTY_SOURCE=/path/openresty-1.31.1.1.tar.gz \
  node --test edge/openresty/native/verify-sources.test.mjs
```

The output directory must not exist. Verification uses a private temporary
directory and never imports keys into the operator's GPG keyring. It checks the
archive, detached signature and public-key SHA-256, verifies the full signer
fingerprint, checks archive paths, and applies the ordered patch chain. Every
patch has its own SHA-256 and whole-file preimages/postimages. `patch -F 0`
dry-run and application prohibit fuzzy context matching; line offsets are
allowed only when all context and locked whole-file hashes still match. A
partially patched tree is never published to the requested output path.

The detached signature comes from the [official download endpoint](https://openresty.org/download/openresty-1.31.1.1.tar.gz.asc).
Its issuer fingerprint is `25451EB088460026195BD62CB550E09EA0E98066`, consistent
with the release signer identified by the [official download page](https://openresty.org/en/download.html).
The public key was retrieved by **full fingerprint** from Ubuntu's public key
server and is vendored with a fixed hash. The OpenResty package repository's
`pubkey.gpg` is a different key and cannot substitute for the source signer.

Upstream patch URLs are immutable commit API URLs. Their byte hashes refer to
the response requested with `Accept: application/vnd.github.patch`, not a
possibly different web-rendered representation. All build inputs are vendored
except the signed source tarball; verification makes no network requests.
The local patch-directory attributes preserve upstream byte identity: unified
diff blank-context prefixes and public-key armor comments are not reformatted.

## Reviewed security closure (2026-10-08)

OpenResty 1.31.1.1 contains NGINX 1.31.1; it does not automatically include later
NGINX fixes. The [official NGINX advisory list](https://nginx.org/en/security_advisories.html)
and [change log](https://nginx.org/en/CHANGES) were rechecked, rather than treating
the repository's older five-CVE snapshot as current.

| Source steps | Purpose |
| --- | --- |
| 01–03 | HTTP/3 insert-buffer sizing/lifetime and closed unidirectional stream handling; CVE-2026-42530 closure. |
| 04 | HTTP/2 proxy/gRPC upstream header bounds; CVE-2026-42055. |
| 05 | Charset UTF-8 recoding bounds; CVE-2026-48142. |
| 06–10, 13 | HTTP/stream script, map/regex capture, access-log, direct script consumer bounds and actual result length; CVE-2026-42533 closure. |
| 11 | Clear stale regex captures; CVE-2026-60005. |
| 12 | Reject duplicate subrequest finalization; CVE-2026-56434. |
| 14–15 | QUIC compatibility extension registration and ordinary-TLS rejection; CVE-2026-90439 closure. |
| 16 | Apply the official complex-value end-code construction to the bundled NDK and ngx_postgres copies. |
| 17 | Port the existing complete QUIC reuseport reload dispatcher to the new core. This is a compatibility patch, not an additional CVE claim. |
| 18 | HTTP/3 skipped unknown-frame length kept apart from DATA length; CVE-2026-95101. |
| 19 | `ngx_http_script_run()` / `ngx_stream_script_run()` reserved-area overrun; CVE-2026-93479. |
| 20 | Reject URI-to-path mapping with `alias` after a rewrite changed the URI; CVE-2026-15176. |
| 21 | Add `bundle/cdnca-ja4` (new files only), built with `--add-module`: `$cdnca_ja4`, the JA4 TLS client fingerprint. cdnca code, not an upstream patch; see `ja4/THIRD_PARTY.md` (JA4 BSD-3 by FoxIO, JA4+ not implemented). |
| 22 | CDNCA original `proxy_toa` (stream): pass the client address to the TOA eBPF program before `connect()`; see `docs/architecture/l4-toa-poc.md`. |
| 23 | CDNCA original: `client_max_body_size` accepts variables (per-site upload limit on a shared `server{}`, ADR 0009 §4); see below. |
| 24 | CDNCA original: `proxy_cache_valid` accepts a time with variables (per-site/per-rule cache TTL on a shared `server{}`, dynamic routing D8); see below. |
| 25 | Add `bundle/ngx_brotli` (new files only), built with `--add-module`: google/ngx_brotli's filter module at `a71f9312c2de`, linked against the build base's system Brotli; see `brotli/THIRD_PARTY.md` (BSD-2-Clause style). |
| 26 | CDNCA original: `gzip_comp_level` and `brotli_comp_level` accept variables (per-site compression level on a shared `server{}`); see below. |

### NGINX 1.31.7 advisories (rechecked 2026-10-16)

Steps 18–20 are the upstream commits byte for byte (`application/vnd.github.patch`),
applied with exact context after step 17.

| CVE | Status for this build | Basis |
| --- | --- | --- |
| CVE-2026-95101 HTTP/3 request body injection | Affected, fixed by step 18 | `--with-http_v3_module`, `http3 on` on edge listeners. `scripts/security/waf-body-stream-smoke.sh` reproduces it on the unpatched base (the tail of a split unknown frame reaches the origin as body) and passes with step 18. |
| CVE-2026-93479 script evaluation overflow | Affected, fixed by step 19 | Stock 1.31.1 is outside 1.31.2–1.31.6, but steps 07 (b76754049) and 10 (a8289aa69) are exactly the two commits the advisory names as the cause; the patched `ngx_http_script_run()` had `e.end = data + n` and `value->len = e.pos + len - data`. Source-verified; no runtime reproduction. |
| CVE-2026-15176 alias + rewrite overflow | Code affected, fixed by step 20 | Core module, always compiled. Rendered edge configs use no `alias`, but the smoke reproduces the negative-length mapping on the unpatched base. |
| CVE-2026-97629 TLS session ticket forgery | Not affected | Rotation needs nginx-managed shared keys: `ssl_session_cache shared:` without `ssl_session_ticket_key`. No edge renderer emits `ssl_session_cache` (OpenSSL's internal ticket keys are used where tickets stay on); HTTP/3 and certificate-store listeners set `ssl_session_tickets off`. Re-evaluate if a shared session cache is ever rendered. |
| CVE-2026-97205 AIO use-after-free | Not affected | Needs `aio` (off by default) and SSI `include virtual`; no renderer emits `aio`, `ssi` or `thread_pool`. |

Every release accepts the runtime freshly built from its own commit
(`scripts/native-node-runtime-acceptance.mjs`, below): a full native build,
smoke and signing, with no dependency on an earlier signed runtime.

The newer base is beyond the official affected version ranges for
CVE-2025-23419, CVE-2026-40460 and CVE-2026-9256. OpenResty's separate
[CVE-2026-55233 advisory](https://github.com/openresty/openresty/security/advisories/GHSA-wx83-v28q-68gx)
also needs tracking: it concerns upstream PROXY protocol v2 and is fixed in
1.29.2.5 and later. These version facts do not replace runtime configuration
and regression evidence.

Three explicitly documented ports differ from their input patches:

- Step 08 retains `log_escape_non_ascii` and obtains the same location
  configuration for both length measurement and escaping; it does not discard
  OpenResty's logging behavior to make the upstream patch apply.
- Step 16 is necessary because [NGINX's third-party compatibility follow-up](https://github.com/nginx/nginx/commit/4b90ec769235877ece7e104d992d17db665806da)
  alone can leave an uninitialized result tail when a module omits the new
  end-code. Both bundled hand-written complex-value compilers are adapted.
- Step 17 preserves newer encryption-level/OpenSSL, congestion-control and
  address-validation code, plus OpenResty's socket-leak-check conditional. The
  previous dispatcher instruction bytes are unchanged; helper map declarations
  use the newer `extern` convention. The [original issue](https://github.com/nginx/nginx/issues/425)
  is still open and the [successor proposal](https://github.com/nginx/nginx/pull/1686)
  has not been merged, so upgrading the version alone is not a reload fix.

## JA4 module (step 21)

`ja4/` is the reviewed source; `node ja4/make-patch.mjs --write` regenerates
`patches/21-cdnca-ja4-module.patch` and its lock entry, and
`verify-sources.test.mjs` fails if they drift. `sh ja4/test.sh` runs the parser
unit test (FoxIO vectors, ASan/UBSan). The module reads the raw ClientHello via
`SSL_CTX_set_msg_callback` on every HTTPS server context (OpenSSL's ClientHello
callback hides unknown extensions and their order), keeps the first
ClientHello's JA4 in SSL ex_data and exposes it as `$cdnca_ja4`; HTTP/2
streams share it. HTTP/3 (QUIC) and plain HTTP leave it empty: QUIC's
ClientHello is not fingerprinted in this phase. The agent declares
`CAPABILITY_NAME_JA4` v1 only when `openresty -V` lists the module.
`scripts/security/ja4-smoke.sh` checks the built runtime against a uTLS client
and Wireshark's independent `tls.handshake.ja4`.

## Variable client_max_body_size (step 23)

With variables, `client_max_body_size` is evaluated for requests that carry a
body: once at the find_config Content-Length check and once when
`ngx_http_read_client_request_body()` starts (before `100 Continue`). The second
value is fixed on the request body and used by the HTTP/1.1 chunked, HTTP/2 and
HTTP/3 body filters, so every protocol path, buffered or not, enforces the same
per-request limit. The value must be a positive size (`ngx_parse_offset`, `k/m/g`);
empty, malformed, zero or overflowing values log `invalid client_max_body_size
value` and reject the request with 500 (a routing or configuration fault, not a
client error that a smaller upload would fix; never "unlimited"). Values without
variables keep the stock `ngx_conf_set_off_slot` semantics, including `0` =
unlimited. The variable must already be set at find_config, that is by `map` or
`server_rewrite_by_lua`; a variable set in the location's rewrite phase is still
empty there and fails closed. As in stock nginx, a body that is discarded unread
is not limited. `scripts/security/body-size-variable-smoke.sh` checks h1/h2/h3
with and without Content-Length against a real runtime.

## Variable proxy_cache_valid (step 24)

The time argument of `proxy_cache_valid` (and of every directive using
`ngx_http_file_cache_valid_set_slot`) may contain variables. It is evaluated
per response, with the request's variables, wherever nginx decides a cache
lifetime: a new response, a revalidated 304, an origin error status and the
502/504 the proxy generates. Entries are tried in order as in stock nginx
(status match or `any`); an empty value skips the entry (a later entry for the
status applies, none = not cached), `0` means not cached, a malformed value logs
`invalid proxy_cache_valid time` and means not cached, so a routing fault can
only make a response uncacheable. The origin's `Cache-Control`, `Expires` and
`X-Accel-Expires` keep their precedence (unless `proxy_ignore_headers`). The
dynamic routing cache passes a per-site status table through a `map` on
`$upstream_status`. Values without variables keep the stock semantics.
`scripts/security/cache-valid-variable-smoke.sh` checks h1/h2/h3 for 200, 404,
origin 503 and proxy 502 against a real runtime.

## Brotli (steps 25–26)

`brotli/` holds google/ngx_brotli's `filter/ngx_http_brotli_filter_module.c`
and `LICENSE` byte for byte at commit `a71f9312c2deb28875acc7bacfdd5695a111aa53`
(the latest upstream commit, 2023-10-09) and CDNCA's own `config`: the filter
only (no `brotli_static`), linked with `-lbrotlienc -lbrotlicommon` from the
build base's `brotli-dev` (both runtime bases ship `brotli-libs`) instead of
the `deps/brotli` submodule. `node brotli/make-patch.mjs --write` regenerates
step 25 and its lock entry and refuses vendored files that differ from the
recorded upstream hashes. As upstream, the filter runs right before gzip, so a
Brotli response is never gzipped too, and it only encodes when the request's
`Accept-Encoding` lists `br`.

No `brotli*` or `gzip*` directive takes variables in the stock modules. The
dynamic routing skeleton therefore turns both on for every type and length and
`cdnca_dynroute`'s header filter rewrites `Accept-Encoding` per site (to `br`,
`gzip` or nothing). Step 26 adds the one per-site value that cannot be gated
that way: `gzip_comp_level` / `brotli_comp_level` with variables are evaluated
once per compressed response; empty is the inherited static level (an outer
`gzip_comp_level` / `brotli_comp_level`, default gzip 1, Brotli 6), an out of
range value is logged and uses it. Values without variables keep
the stock bounded number slot. `scripts/security/brotli-webp-smoke.sh` checks
both against a real runtime.

## Build and native closure boundary

`build_base` pins the official `1.31-alpine` image observed by the release owner
on isolated Node A: Linux/amd64, Alpine 3.23.5, OpenSSL 3.5.8, image digest
`sha256:e260a5b63b78700eb8047e934950a17b4ab3980a77ef254ec486fff8ea4617e6`.
The [official image source](https://github.com/openresty/docker-openresty/tree/25f4a6792a0ffa18a1a9feecd2d9a31d0e0cde86)
provides the matching build recipe. Use the digest, not the moving tag.

Rebuild and install the **complete OpenResty bundle** from the verified output:
NGINX, LuaJIT, bundled Lua/C modules and dynamic modules must match. Do not put
a new NGINX binary into the old 1.27.1.2 Lua runtime. The signed tarball actually
contains `ngx_lua-0.10.31rc5` and `ngx_stream_lua-0.0.19rc4`; build facts take
precedence over shortened announcement names.

CVE-2026-90439 affects the compatibility path when HTTP/3 uses OpenSSL 3.5.0 or
earlier. The pinned base reports 3.5.8, but the release must additionally verify
the final ELF dependencies, loaded libssl/libcrypto paths and hashes. Steps
14–15 remain applied even when the modern API makes that path inactive.

The native package must include the matching musl loader and complete shared
library closure, preserve required symlinks, and verify executable interpreter
and RPATH/DT_NEEDED resolution on clean Ubuntu. `resty` also requires Perl and
ncurses in the official Alpine image; copying only the NGINX ELF is insufficient
if that utility is exposed. Do not mistake a development smoke container for a
complete native package. Also verify effective worker UID and access to the
root-private immutable release; a successful root `nginx -t` is not worker read
permission evidence.

## Still required before release

`scripts/native-node-runtime-acceptance.mjs` accepts the runtime built by this
Dockerfile from the candidate commit. Arguments: `--source-commit`,
`--payload-dir` (the `native-payload` output), `--smoke-result` (the
`result.json` of `scripts/native-node-runtime-smoke.sh` for that payload and
commit) and `--source-archive` (the signed OpenResty tarball). Run it from the
committed candidate's clean Git worktree. It checks that the working tree equals
the commit for every runtime input, Lua source and the two release scripts; that
the Dockerfile copies exactly those inputs and the Lua mapping; that the
exporter's `evidence/runtime-build-inputs.sha256` equals the commit's
`verify-sources.mjs`, `sources.lock.json`, `build-openresty.sh`, every file in
`patches/` and `native-node-export.mjs` (an untracked or stale input fails);
that `runtime-sources.lock.json` and `source-verification.json` match the lock;
that `evidence/openresty-V.txt` names the locked OpenResty version, the
`build_base` OpenSSL, the required HTTP/2, HTTP/3, stream and realip flags and
the JA4 module; that payload Lua equals its sources byte for byte and the
complete runtime/Lua inventory equals `runtime-export.json` and all ten smoke
checks; then it replays source-signature and exact-patch verification. It
creates only a new `payload/evidence/runtime-acceptance.json` (`mode:
fresh-build`, input/patch/build-script/evidence hashes and the `nginx -V`
text), never overwriting prior evidence; `native-node-package.mjs prepare`
reads it as before. It sets `release_eligible: true` for the accepted runtime;
it is not an automatic security reviewer: the release owner must recheck the
latest NGINX and OpenResty advisories before signing, and the release signature
is the release decision. Agent provenance remains subject to the existing
package builder's separate gate.

The source test is deliberately **not** protocol or deployment acceptance.
The release owner must record the full build, final artifact/SBOM provenance,
ELF dependency closure, service startup/restart/autostart, node binding, config
activation and failure rollback, and these real protocol regressions:

- HTTP/1.1 and HTTP/2, HTTP/3/QUIC, Range/206, rewrite, WebSocket across reload,
  cache refresh/prewarm, and four-layer forwarding.
- Map/regex variable growth and shrinkage in rewrite, logs, NDK/set-misc and
  subrequests; slice/background-update capture isolation; duplicate SSI
  finalization; fragmented invalid UTF-8; large HTTP/2/gRPC upstream headers.
- HTTP/3 QPACK insert capacity/lifetime and closed uni-stream reopening;
  ordinary TLS versus QUIC extension handling, cross-SNI session/mTLS isolation,
  PROXY v2 header bounds, address validation and migration.
- Same existing and new QUIC connections through repeated graceful reload,
  multiple workers, IPv4/IPv6, BPF availability/permission failure, and rollback.

Existing reusable entrypoints include `scripts/edge-http3-smoke.sh`,
`scripts/edge-site-smoke.sh`, `scripts/edge-l4-smoke.sh`,
`scripts/edge-range-smoke.sh`, `scripts/edge-cache-smoke.sh`,
`scripts/edge-cache-task-smoke.sh`, `scripts/edge-runtime-linux-smoke.sh`, and
`tests/edge-linux/inside-systemd-smoke.sh`. Their existing pinned images must
not be silently confused with this new native candidate. The static
`tests/edge-runtime-security-release-e2e/run.sh` is not runtime acceptance.
