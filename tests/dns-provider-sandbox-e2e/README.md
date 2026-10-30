# DNS provider sandbox E2E

This directory is the Round-7 live acceptance driver for exactly six DNS
providers:

1. `cloudflare` (Cloudflare)
2. `aliyun` (Alibaba Cloud DNS)
3. `huawei` (Huawei Cloud DNS)
4. `dnspod_cn` (DNSPod CN)
5. `dns_com` (DNS.COM)
6. `dns_la` (DNS.LA)

`dnsdun`, DNSPod International, and every other name are unsupported. They are
not aliases and must not be routed through one of the six accepted providers.
The machine-readable capability and credential contract is
[`contract.json`](./contract.json).

## Current status

The driver and static contract are checked in, but this task did not read a
credential, call a provider, query public DNS, or mutate a zone. A successful
static check is `READY_ROUND7`, not live provider evidence.

Run the live driver only after a root-issued execution release. Each provider
must have its own disposable delegated zone, guard TXT record, authoritative
endpoints, and authorized sandbox account. Never use a customer or production
zone.

## Safety boundary

- The driver accepts no command-line arguments and never enables shell tracing.
- `CDNCA_DNS_SANDBOX_MUTATION_ACK` must equal
  `round7-six-provider-disposable-zones` in both the shell and Go entrypoints.
- The configuration must contain all six providers in the fixed order above.
  The driver loads and validates every config, endpoint set, guard digest, and
  exact-schema credential lease before the first mutation. One invalid input
  produces zero mutation for all providers.
- Credentials come from either one provider-specific environment variable or
  one absolute owner-only secret file, never both. Secret files must be regular,
  non-symlink files with no group/other permission bits and at most 64 KiB.
- Environment credentials are supported for ephemeral CI secret injection, but
  owner-only files are preferred because a process environment cannot be
  reliably wiped. The selected environment entry is removed before mutation.
- Output contains only stable reason codes. Raw provider errors, response bodies,
  zones, record IDs, endpoints, credentials, and record values are never written
  to stdout/stderr or evidence.
- Execution is serial. A provider failure stops later providers, enters bounded
  exact-record cleanup, and records `cleanup_pending` unless provider readback
  proves absence.

## Credential sources

For provider `CODE`, set exactly one of these fields in its config entry:

```json
{
  "credential_file": "/absolute/owner-only/path/provider.json"
}
```

or:

```json
{
  "credential_env": "CDNCA_DNS_SANDBOX_CODE_CREDENTIALS_JSON"
}
```

`CODE` is the upper-case provider code, including underscores. For example,
DNSPod CN uses `CDNCA_DNS_SANDBOX_DNSPOD_CN_CREDENTIALS_JSON`.

The secret JSON must have every field and no unknown or duplicate field:

| Provider | Exact fields |
| --- | --- |
| Cloudflare | `api_token` |
| Alibaba Cloud | `access_key_id`, `access_key_secret` |
| Huawei Cloud | `access_key`, `secret_key`, `region`, `project_id` |
| DNSPod CN | `dp_id`, `dp_key` |
| DNS.COM | `api_key`, `api_secret` |
| DNS.LA | `api_id`, `api_secret` |

Never put a secret JSON document in the non-secret config file, shell history,
command arguments, evidence, tickets, or screenshots.

## Configuration contract

Set `CDNCA_DNS_SANDBOX_CONFIG_FILE` to an absolute regular JSON file. The root
shape is:

```json
{
  "schema": "cdnca:dns-provider-sandbox-e2e-config:v1",
  "evidence_path": "/absolute/existing-directory/dns-provider-evidence.json",
  "providers": []
}
```

`providers` must contain all six fixed codes in contract order. Each entry has:

| Field | Requirement |
| --- | --- |
| `code` | Exact provider code; aliases rejected |
| `zone` | Unique lower-case disposable zone without trailing dot |
| `guard_owner` | Existing TXT owner inside that zone, with trailing dot |
| `guard_sha256` | Lower-case SHA-256 of the guard's only TXT value |
| `authoritative` | Non-empty unique literal `IP:port` array |
| `public_recursive` | At least two unique literal `IP:port` public resolvers, disjoint from authoritative |
| credential source | Exactly one of `credential_env` or `credential_file` |
| `initial_ipv4`, `updated_ipv4` | Distinct canonical IPv4 test values |
| `initial_ipv6`, `updated_ipv6` | Distinct canonical non-mapped IPv6 test values |
| `cname_target`, `updated_cname_target` | Distinct lower-case canonical FQDNs with trailing dots |
| `ttl`, `updated_ttl` | Distinct values in `60..86400` |
| `update_line`, `update_weight` | Required only for DNSPod CN; weight `1..100` |
| `rate_limit_maximum_reads` | Explicit bounded sandbox probe count `1..30` |
| `rate_limit_interval_ms` | Probe spacing `1000..60000` ms |
| `timeout_seconds` | Provider lifecycle deadline `60..1800` |
| `cleanup_timeout_seconds` | Independent cleanup deadline `60..1800` |

The rate-limit probe performs only reads against the already-created sandbox
record. It stops at the first provider-classified 429 and requires a bounded,
positive `Retry-After` no greater than one hour. It never loops without a cap.
If the authorized sandbox cannot produce a real 429 within the configured cap,
the provider remains failed with `rate_limit_not_observed`; do not fabricate or
inject a result into evidence.

## Live sequence

After the all-provider preflight succeeds, each provider runs this sequence:

1. Use the production DNS-01 adapter to verify the authoritative guard, create
   unique sentinel and target TXT values, read them by exact remote identity,
   wait for authoritative then public-recursive convergence, delete only those
   values, and prove provider/authoritative/public absence.
2. Before every mutation, atomically persist a redacted journal entry and its
   monotonic resource revision.
3. Create unique A, AAAA, and CNAME records through the production reconcile
   remote and read each back by exact provider record identity.
4. Update each value and TTL. DNSPod CN additionally updates line and weight;
   all other providers declare those capabilities unsupported and send neither.
5. For each type, wait for all authoritative endpoints first, then require all
   configured public recursors (at least two) to converge.
6. Run one bounded read-only 429 probe and retain only the stable provider error
   class and validated `Retry-After` seconds.
7. Honor the observed delay, delete each exact provider record, and prove its
   absence at the provider, every authority, and every configured public
   recursor. Lost create/update/delete responses are recovered only when an
   exact identity readback proves the result; otherwise cleanup remains pending.

Every step atomically rewrites a `0600` evidence file. Provider request IDs are
domain-separated deterministic digests, not credentials or upstream response
bodies. Provider record IDs are stored only as domain-separated SHA-256
digests. The resource list contains only provider code, resource kind, identity
digests, a monotonic revision, and `planned`, `present`, `absent`, or
`cleanup_pending`.

Only top-level `status=pass`, `reason=verified`, six provider `status=pass`, and
all resources `state=absent` are completion evidence. Any other state is a
failed or incomplete Round-7 run.

## Execution

After explicit live authorization and an independent review of all disposable
zones and secrets:

```bash
export CDNCA_DNS_SANDBOX_MUTATION_ACK=round7-six-provider-disposable-zones
export CDNCA_DNS_SANDBOX_CONFIG_FILE=/absolute/path/sandbox-config.json
./tests/dns-provider-sandbox-e2e/run.sh
```

The command prints only `verified` or a stable failure reason. Inspect the
redacted evidence file for progress and cleanup state. If any resource is
`cleanup_pending`, stop reruns, keep that zone isolated, and use the authorized
provider console to identify the exact random owner before performing any manual
cleanup. Never delete a whole recordset, zone, guard, or unrelated value.

## Static acceptance

These checks do not read credentials or make network requests:

```bash
bash -n tests/dns-provider-sandbox-e2e/run.sh \
  tests/dns-provider-sandbox-e2e/contract_test.sh
shellcheck tests/dns-provider-sandbox-e2e/run.sh \
  tests/dns-provider-sandbox-e2e/contract_test.sh
GOWORK=off go test ./tests/dns-provider-sandbox-e2e/...
bash tests/dns-provider-sandbox-e2e/contract_test.sh
```

The final command is the static contract acceptance. None of these commands is
a substitute for the authorized six-provider live run.
