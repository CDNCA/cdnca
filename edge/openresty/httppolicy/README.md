# HTTP policy runtime

`engine.lua` is the request-path runtime for the versioned
`cdnca.edge.http-policy/v1` contract. It accepts only canonical JSON produced
by the Edge Agent `internal/httppolicy` package; it never evaluates policy as
Nginx or Lua source.

The module is called from both phases:

```nginx
client_max_body_size 1048576;
proxy_request_buffering on;
access_by_lua_block {
  return require("engine").access({
    state_root = "/var/lib/cdnca/http-policy",
    site_id = "site-id",
  })
}
header_filter_by_lua_block { return require("engine").header_filter() }
```

`client_max_body_size` must equal the site's canonical `max_upload_bytes`.
The Lua engine checks `Content-Length`, reads and measures buffered unknown
length bodies before proxying, and rejects oversize requests, while the core
directive supplies bounded early termination for HTTP/1.1 chunked and HTTP/2
bodies.

This directory is currently loaded by the isolated
`scripts/edge-http-policy-smoke.sh` fixture. It is not yet included in the
formal `siteconfig` bundle. See `docs/runbooks/edge-http-policy.md` for the
contract and required integration work.

The runtime reads only `committed.json`. That manifest identifies one immutable
`versions/%020d.json` artifact and binds it with SHA-256. Legacy `current.json`
and `lkg.json` files are ignored, so two same-version files can never be chosen
without a commit fact. A worker retains its validated policy in memory if a
later manifest is invalid; a worker without an in-memory policy fails closed.
