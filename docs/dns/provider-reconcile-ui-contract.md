# DNS Provider Reconcile UI Contract

Status: `PARTIAL`. The tenant API client can call and validate the five mounted
DNS reconcile routes. A safe operator UI is blocked because the current DNS
zone and record read models do not contain the authoritative provider snapshot
required by `CheckRequest`.

## Current Boundary

The bundled and mounted tenant routes are:

- `POST /v1/sites/{site_id}/dns-reconcile/dry-run`
- `POST /v1/sites/{site_id}/dns-reconcile/apply`
- `GET /v1/sites/{site_id}/dns-reconcile/tasks/{task_id}`
- `POST /v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/commit`
- `POST /v1/sites/{site_id}/dns-reconcile/tasks/{task_id}/cancel`

`sitesApi.list` supplies the site identity and display domain. The current DNS
facts supply a local zone, local records, and local revisions only. They do not
supply `authoritative_ns` or the required provider snapshot fields:
`zone_id`, strong provider `revision`, and provider `record_id/name/type/value/ttl`.
The web client must not infer those fields from local draft rows.

Provider acceptance, an operation row marked `succeeded`, or a task marked
`committed` is not proof of authoritative DNS propagation. A completed UI state
requires the task's latest propagation fact to be healthy, its
`consecutive_healthy` value to reach `required_consecutive`, and
`last_check.compliant` to be true. Production propagation remains `UNKNOWN`
until those facts come from the configured authoritative and public recursive
probes.

## Minimal Additive Read Model

The backend/OpenAPI owner should add this tenant-scoped read operation:

```http
GET /v1/sites/{site_id}/dns-reconcile/input-snapshot?zone_id={local_zone_id}
Authorization: Bearer <session>
X-Request-ID: <metadata>
traceparent: <w3c-traceparent>
```

Required permission: `dns.read`. Tenant scope comes only from the authenticated
session. The path site, local zone, provider credential binding, and provider
zone must all belong to that tenant. Cross-tenant and cross-zone mismatches use
the same stable not-found response.

Success is `200 application/json`, `Cache-Control: no-store`, a correlated
`X-Request-ID`, and a strong `ETag` equal to the quoted provider revision:

```json
{
  "snapshot_id": "55555555-5555-4555-8555-555555555555",
  "site_id": "22222222-2222-4222-8222-222222222222",
  "local_zone_id": "44444444-4444-4444-8444-444444444444",
  "provider_id": "33333333-3333-4333-8333-333333333333",
  "provider_type": "cloudflare",
  "provider_revision": 7,
  "generated_at": "2026-08-04T00:00:00Z",
  "expires_at": "2026-08-04T00:05:00Z",
  "check": {
    "name": "www.example.com",
    "expected": [{"type": "A", "values": ["192.0.2.10"]}],
    "authoritative_ns": ["ns1.example.net"],
    "ttl": 300,
    "propagation_started_at": "2026-08-04T00:00:00Z",
    "propagation_window_seconds": 900,
    "provider": {
      "zone_id": "66666666-6666-4666-8666-666666666666",
      "revision": 7,
      "records": [{
        "record_id": "provider-record-1",
        "name": "www.example.com",
        "type": "A",
        "value": "192.0.2.9",
        "ttl": 300
      }]
    }
  }
}
```

The server, not the browser, builds `check` from the selected site's desired
DNS facts and one fresh provider read. The response must contain no credential
fields or raw provider secret. `provider_revision` must equal
`check.provider.revision` and the response `ETag`.

The browser may call dry-run while the snapshot is fresh. Apply reuses the exact
`check` bytes, sends `If-Match: "<provider_revision>"`, and freezes one
idempotency key, request ID, traceparent, and body for all unknown-outcome
retries. The browser must refresh an expired snapshot. The server remains the
authority for the existing provider-revision precondition and rejects drift
even if a stale or malicious client ignores `expires_at`.

## Reload Recovery

The backend/OpenAPI owner should also add:

```http
GET /v1/sites/{site_id}/dns-reconcile/tasks?limit=20&cursor=<opaque>
```

Required permission: `dns.read`. Success returns recent durable tasks in
descending `(updated_at, id)` order:

```json
{
  "items": ["<existing Task schema>"],
  "next_cursor": "opaque-or-null"
}
```

`limit` is `1..100`. The cursor is opaque and tenant/site bound. This endpoint
is required so a reload can recover an apply whose `202` response was lost and
can continue polling, commit, cancel, or retry the same frozen command identity
without asking an operator to paste a task UUID.

## Stable Errors

The new reads use the existing exact error envelope and stable codes. Minimum
additional codes are:

- `dns_reconcile_input_not_found` (`404`)
- `dns_reconcile_input_unavailable` (`503`)
- `dns_reconcile_snapshot_expired` (`409`, only if a future command binds a snapshot ID)

The browser maps codes through the DNS-specific locale. It never renders the
server `message`, provider response body, credential, request header, or secret.

## Production Unknowns

- No current public read supplies a safe `CheckRequest`; dry-run/apply UI is blocked.
- No current task-list read supports reload recovery; get/commit/cancel have no natural UI entry.
- No real provider credential, authoritative resolver, public recursive resolver,
  or production propagation probe was used for this contract work.
