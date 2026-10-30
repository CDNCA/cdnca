# Edge telemetry JSONL

`access-json.conf` and `security-json.conf` define the version 1 source
envelopes consumed by the edge Agent event spool. Nginx `escape=json` makes
control characters and newlines safe inside one physical JSONL record.

The safe default logs `$uri` without the query string and emits the four capture
fields as JSON `null`. A signed site capture policy can switch the generated
site format to allowlisted request/response headers and top-level JSON body
fields. Enabled captures preserve an empty object as `{}`. Both the generated
OpenResty source and the Agent sanitizer mask authorization, cookie, password,
token, key, and certificate values and enforce value, body and event limits.

`ja4` is the node's own TLS client fingerprint: the generated site formats log
`$cdnca_ja4_log`, which each server fills from the native module's
`$cdnca_ja4` through `set_by_lua` (a runtime without the module reads it as
nil and still passes `nginx -t`). Without a fingerprint (plain HTTP, HTTP/3,
runtime without the module) the line carries `""` and the Agent records
`null`; any other value that is not exactly one JA4 is rejected. These static
snippets for the pinned image keep `"ja4":null`. A versioned per-request
deployment task binding is still unavailable: `task_id` stays `null` and
preflight rejects manifests that claim it (or `source_capabilities.ja4`, which
is not used). The three origin timings come only from the corresponding upstream
phase variables and are converted from seconds to integer microseconds;
negative, non-numeric, overflowing and multi-upstream values are quarantined.

Before including the formats, the site configuration compiler must register
`cdnca_tenant_id`, `cdnca_site_id`, `cdnca_node_id`, and
`cdnca_config_version_id` with validated `map` directives. Security modules
register and set the four `cdnca_security_*` variables, then emit the security
log only for a completed security decision.

The collector treats the line's tenant and node fields as untrusted diagnostics.
It resolves tenant from the activated `site_id -> tenant_id` snapshot and
overwrites node with the validated enrollment identity before spooling. An
unknown site is quarantined. The local JSONL files must be pre-created as 0600
single-link regular files and rotation must preserve those properties.
These snippets write local files only; they do not connect OpenResty to NATS,
ClickHouse, or the control plane.

`syntax-test.conf` is a standalone fixture for the pinned OpenResty image; it
contains only non-production example scope values. The telemetry smoke sends
real requests for 2xx, 4xx, 5xx, and a WAF-like block, verifies the emitted
JSONL, and repeats the requests against `/dev/full` to prove log write failures
do not alter data-plane responses.
