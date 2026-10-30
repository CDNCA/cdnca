# Edge cache task execution

> Historical contract only. This document describes the retired schema v1
> prototype and must not be used by control, Gateway, daemon, or Agent runtime
> integrations. The current executor accepts only schema v2; use
> [`edge-cache-task.md`](./edge-cache-task.md) as the active contract.

## Scope

`agents/edge-agent/internal/cachetask` is the first real node-local executor for
cache purge and prewarm work. It supports schema version 1 tasks for:

- exact URL purge, including exact query-string isolation;
- segment-bounded prefix/directory purge;
- all cached objects for one site context;
- a list of URLs to prewarm through the active local OpenResty listener.

This slice does not claim a control API, Agent Gateway command, protobuf message,
JetStream consumer, multi-node fan-out, UI, or distributed completion policy.
Those layers must preserve the task and result semantics below when connected.

## Trusted site context

The task contains only `site_id` and `expected_config_version`. The executor asks
its `SiteResolver` for the corresponding signed and published site context:

- canonical ASCII domain;
- HTTP or HTTPS scheme;
- listener port;
- active configuration version;
- cache-enabled flag;
- the 32-character cache identity generated for that domain and port.

The task cannot provide a cache directory, origin address, dial address, Host
header, or TLS server name. A missing, disabled, stale, or malformed site context
is rejected before filesystem or network work starts.

For prewarm, the executor always dials its configured literal loopback address at
the published listener port. It sends GET with the published Host/SNI and accepts
no caller headers. Authorization, Cookie, Range, Upgrade, and arbitrary user
headers are therefore never forwarded. Redirects are not followed. The response
must have an allowed status, the exact active `X-CDNCA-Config-Version`, and
`X-CDN-Cache: MISS` or `HIT`. Timeout, response-header, response-body, status, and
rate bounds are enforced. `MISS` is `PREWARMED`; an existing `HIT` is
`ALREADY_CACHED` and is reported as skipped.

## Version 1 task

```json
{
  "schema_version": 1,
  "task_id": "cache-task-01",
  "idempotency_key": "request-01",
  "site_id": "site-01",
  "expected_config_version": "config-1042",
  "action": "purge_exact",
  "targets": [
    "https://www.example.com/assets/app.js?v=42"
  ]
}
```

Actions are `purge_exact`, `purge_prefix`, `purge_site`, and `prewarm`.
`purge_site` requires no targets and produces one result item. Other actions
require 1 to 1000 absolute URLs. URLs must match the published scheme, canonical
host, and effective listener port. Paths are normalized to the same decoded URI
form used by the cache key; percent-encoded UTF-8 and unreserved bytes are
accepted. Encoded slash/backslash, traversal, duplicate separators, fragments,
userinfo, controls, and ambiguous whitespace are rejected. The raw query string
is retained exactly. Prefix purge does not accept a query string. A prefix
`/images` matches `/images` and `/images/...`, but not `/images-old`.

## Cache-file safety

The active OpenResty configuration uses this key and storage mapping:

```text
<canonical-domain>|<listen-port>|<normalized-uri><optional-?query>
${state_root}/shared/cache/<site-cache-identity>/
```

The executor never turns a URL into a filesystem path or glob. It walks only the
validated site cache root and indexes cache files from the pinned OpenResty
1.27.1.2 metadata. A candidate is deletable only when all of these checks pass:

1. The state root and shared cache root are real owner-only directories.
2. No traversed entry is a symlink or unsupported file type.
3. The cache file is a regular, single-link file under the expected site root.
4. A bounded header read finds the native `\nKEY: ` marker.
5. The parsed key has the exact published domain and port.
6. MD5 of that key matches both the 32-character filename and the configured
   Nginx `levels=1:2` directory layout.
7. From the site-root directory descriptor, each parent is reopened with
   `openat(O_NOFOLLOW)`; file type, device, inode, size, and link count must still
   match before `unlinkat`, followed by a parent-directory sync.

Unknown temporary regular files are ignored. A symlink, malformed cache-shaped
file, cross-site key, hard link, or changed indexed file fails closed with a
stable item code. Existing deployment releases, `current`/`previous` pointers,
Nginx configuration, certificates, and active workers are never changed.

## Persistence and retries

State is stored below `${state_root}/state/cache-tasks` with owner-only
directories and atomic `0600` JSON files. A single atomic registry binds both
task ID and idempotency key to the normalized payload digest. Reusing either
identity with another payload returns `ErrConflict`.

Each item is journaled before and after execution. A completed task replays the
same result without executing again. After a crash, `pending`, `working`, and
failed items are retried; successful and skipped items are retained. A purge
persists `destructive_started` before its first unlink. If files were removed
before a later failure or before the completion journal reached disk, retry only
sees/removes remaining files and treats an already-empty planned target as the
achieved purge outcome. This prevents repeating successful destructive
operations.

Tasks for the same site are serialized in-process and with an OS file lock.
Different sites run in parallel up to `GlobalConcurrency`. Independent global
and per-site token buckets bound prewarm request rates and bursts. Cancellation
is journaled as `TASK_CANCELLED`; the task remains retryable.

Final per-item statuses are exactly `success`, `skipped`, or `failed`. The result
contains total/completed/succeeded/skipped/failed progress, attempt counts,
affected object counts, stable codes, and timestamps. A task is `succeeded`,
`partial_failed`, or `failed`.

## Stable item codes

Successful or skipped outcomes:

- `PURGED`
- `PREWARMED`
- `CACHE_ENTRY_NOT_FOUND`
- `ALREADY_CACHED`

Retryable failure outcomes:

- `CACHE_LAYOUT_UNSAFE`
- `CACHE_METADATA_INVALID`
- `CACHE_ENTRY_CHANGED`
- `CACHE_DELETE_FAILED`
- `SITE_CONTEXT_STALE`
- `PREWARM_TIMEOUT`
- `PREWARM_REDIRECT_REJECTED`
- `PREWARM_RESPONSE_TOO_LARGE`
- `PREWARM_UPSTREAM_FAILED`
- `PREWARM_STATUS_REJECTED`
- `PREWARM_NOT_CACHEABLE`
- `TASK_CANCELLED`

## Verification

Run focused and race tests:

```sh
cd agents/edge-agent
go test -count=1 ./internal/cachetask
go test -race -count=1 ./internal/cachetask
go vet ./...
```

Run the pinned real-runtime proof:

```sh
./scripts/edge-cache-smoke.sh
```

The smoke seeds real cache objects, verifies exact query isolation, prefix
segment isolation and site purge, proves the next request after purge is `MISS`
and the following request is `HIT`, proves prewarm makes the first user request a
`HIT`, and verifies a timed-out prewarm leaves an already cached site URL
available. Its CACHE-03 evidence also records a timed prewarm rate bound, proves
a transient storage retry keeps the active cache available while reusing the
original immutable purge plan, and reconciles physical cache keys across
configuration versions so an active-version purge cannot remove the previous
version. The script removes its temporary container, image, binary, and state.
