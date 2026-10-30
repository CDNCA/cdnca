# control-api

The control API is a Go modular monolith. Database changes are explicit and are
not run as a side effect of process startup.

```sh
export DATABASE_URL='postgres://cdnca:cdnca-local-only@127.0.0.1:5432/cdnca?sslmode=disable'
export ACCESS_TOKEN_SECRET='replace-with-at-least-32-local-bytes'
export ENTITLEMENT_TRUSTED_KEYS_FILE='/etc/cdnca/trusted-keys.json'
export LICENSE_SERVICE_URL='https://license.example.test'
export CONTROL_INSTALLATION_ID='replace-with-issued-installation-uuid'
export CONTROL_INSTALLATION_NAME='Primary control'
export CONTROL_INSTALLATION_PRIVATE_KEY_FILE='/run/secrets/cdnca/installation-key.pem'
export CONTROL_ACTIVATION_CREDENTIAL_FILE='/run/secrets/cdnca/activation-code'
export DNS_CREDENTIAL_KEY_ID='dns-credentials-v1'
export DNS_CREDENTIAL_KEY_BASE64='replace-with-base64-of-exactly-32-random-bytes'
export CONTROL_INTERNAL_GRPC_ADDR='127.0.0.1:9091'
export CONTROL_INTERNAL_SERVER_CERT_FILE='/run/secrets/cdnca/control-internal-server.crt'
export CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE='/run/secrets/cdnca/control-internal-server.key'
export CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE='/run/secrets/cdnca/gateway-client-ca.crt'
export CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN='spiffe://cdn-platform/gateway/control'
export NODE_CA_CERTIFICATE_CHAIN_FILE='/run/secrets/cdnca/node-ca-chain.crt'
export NODE_CA_PRIVATE_KEY_FILE='/run/secrets/cdnca/node-ca.key'
export EDGE_DEPLOYMENT_NATS_URL='nats://cdnca:local-only@127.0.0.1:4222'
# Optional, but both are required to enable durable node presence processing.
export NODE_PRESENCE_NATS_URL='nats://cdnca:local-only@127.0.0.1:4222'
export NODE_PRESENCE_REDIS_URL='redis://127.0.0.1:6379/0'

go run ./cmd/control-api migrate up
BOOTSTRAP_PASSWORD='replace-with-a-strong-local-password' \
  go run ./cmd/control-api bootstrap-user --username admin --email admin@example.com
go run ./cmd/control-api install-entitlement \
  --trusted-keys "$ENTITLEMENT_TRUSTED_KEYS_FILE" \
  --bundle /secure/path/entitlement-bundle.json \
  --revocation /secure/path/entitlement-revocation.json
COOKIE_SECURE=false go run ./cmd/control-api serve
```

`BOOTSTRAP_PASSWORD` is read only from the environment and is never printed or
written to the database in plaintext. The example values above are local-only;
production deployment must inject separate database, token-signing, and
bootstrap secrets through its secret manager. `serve` fails closed unless the
DNS credential key ID and a base64-encoded 32-byte AES key are supplied by the
deployment. The key is never stored in PostgreSQL; DNS provider credentials are
AES-GCM encrypted before insertion and are never returned by the API or audit log.
Credential-bearing idempotency comparisons use a domain-separated HMAC, not an
unkeyed secret-derived fingerprint.

## ControlInternal and node identity

`serve` also starts a private TLS 1.3 gRPC listener for Agent Gateway. Startup
fails unless the server certificate/key, fixed Gateway client CA, and node CA
signing material are present. Both private-key files must be regular files that
are inaccessible to group and other users. The Gateway client certificate must
contain exactly the configured workload URI SAN; the same value must be set as
`CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN` on Agent Gateway.

The service exposes standard `grpc.health.v1.Health` for the generated
`ControlInternalService` name. It becomes `SERVING` only after the listener is
running and returns to `NOT_SERVING` before shutdown. Enrollment consumes the
one-time token transactionally, binds the CSR, machine fingerprint, protocol,
capabilities, Gateway identity and X25519 artifact key, then signs a short-lived
node certificate without moving the Agent private key into the control plane.
The CA signer accepts an injected `crypto.Signer`; the local file-backed mode is
the deployment fallback for environments without a managed KMS/HSM signer.

## DNS and certificate foundation

Migration `005_dns_acme` adds tenant-scoped DNS providers, zones, structured DNS
records, and ACME certificate orders. Provider credentials are persisted only as
authenticated ciphertext. Migration `024_dns_provider_verification` adds the
`verified` provider state and the first real provider adapter. An authenticated
caller with `dns.manage` can call
`POST /v1/dns/providers/{id}/verify` with `If-Match` and `Idempotency-Key`; for a
Cloudflare provider the control API decrypts the exact `api_token` credential and
calls `GET https://api.cloudflare.com/client/v4/user/tokens/verify` with a bounded
request. Redirects are not followed and responses are capped at 64 KiB.

Success advances the provider revision and atomically commits `verified`, the
idempotency result, and audit evidence. Unsupported providers, disabled
providers, malformed credential schemas, inactive tokens, and rejected tokens
are stable audited denials. Rate limits, timeouts, transport failures, 5xx, and
invalid provider responses do not complete the idempotency key, so an identical
request can be retried. No credential, key ID, ciphertext, authorization header,
or upstream response body is returned or audited. A `verified` state proves only
that the token was active at verification time; it does not prove access to a
specific zone, DNS propagation, certificate issuance, or edge deployment. See
[`docs/runbooks/dns-provider-verification.md`](../../docs/runbooks/dns-provider-verification.md).

Zones and records remain `draft`, and certificate orders remain `pending` until
later workers call real record and CA adapters. Certificate order creation and
its `certificate.order.requested` outbox event commit atomically; the pending
outbox is the future worker boundary rather than an in-process fake.

`migrate down` rolls back exactly one migration per invocation. Tests create a
unique PostgreSQL schema and only remove that schema during cleanup:

```sh
TEST_DATABASE_URL="$DATABASE_URL" go test ./...
```

Migration `003_sites` adds `sites.read` and `sites.manage`. Existing
platform administrators continue to inherit them through `platform.admin`.
Tenant roles are deliberately not upgraded automatically: grant the new
permissions only to reviewed tenant roles, then verify list and write access
with that role before exposing the website routes. This avoids silently
expanding a custom tenant role during an upgrade.

## Layer-four forwarding control slice

Migration `007_l4_forwards` adds tenant-owned TCP/UDP forwarding rules,
`streams.read` / `streams.manage` RBAC, idempotent writes, append-only audit
evidence, optimistic revisions, and append-only publication intents. The
runtime payload matches the current Edge `Stream` fields. It remains a pending
intent: this slice does not dispatch to Agent Gateway or claim node activation.

The current Edge runtime binds IPv4 and IPv6 wildcard listeners together, so
the API deliberately accepts only `listen_address: "*"`. TCP and UDP may share
a numeric port; two rules using the same protocol and port cannot coexist.
Single-address binding, multi-origin rules, node placement, staged activation,
and rollback remain future work.

## Local entitlement guard

Website creation, re-enabling, and updates that keep a website enabled require
a locally verified `sites.manage` feature and available `domains.count` quota.
The check, global enabled-site count, resource write, idempotency record, and
audit append share one PostgreSQL transaction. Delete and enabled-to-disabled
changes remain available when the lease is in grace or expired state. Revoked
state is reserved until an authenticated revocation protocol is implemented.

`install-entitlement` reads Ed25519 root trust pins from an independently
provisioned deployment file and reads the signed lease from a separate bundle.
The optional `--revocation` file is an owner-only signed
`cdnca.entitlement.revocation-set/v2` artifact fetched with the installation
private key; when supplied it is verified and persisted before the lease is
installed. Bundle-provided keys and non-empty unsigned revocation lists are
rejected. The API process loads the same deployment file through
`ENTITLEMENT_TRUSTED_KEYS_FILE`. Migration `016_entitlement_signing_keyset`
stores the last verified `cdnca.signing-keyset/v2` body, digest and ETag, but
PostgreSQL never establishes trust by itself: every restart revalidates the
canonical PoP and previous-signer authorization chain from the deployment pin. The
command prints only serial, status, and key ID. See
[`docs/runbooks/control-entitlement.md`](../../docs/runbooks/control-entitlement.md)
for the bundle contract, state behavior, verification, and current limitations.

When `LICENSE_SERVICE_URL` is set, `serve` also starts the optional entitlement
synchronizer. It uses an externally provisioned PKCS#8 Ed25519 installation key
to activate once or prove possession during renewals. The private key is never
written to PostgreSQL. The single-use activation credential is read only from a
mode-restricted regular file, or from standard input when
`CONTROL_ACTIVATION_CREDENTIAL_FILE=-`; it is never accepted as an argument or
logged. The synchronizer accepts only HTTPS license-service URLs, verifies every
response against the resulting rotating TrustStore and expected installation
before atomically replacing the cached lease. Before activation or renewal it
conditionally fetches the public keyset using the last ETag. Only a lineage that
extends the PostgreSQL last-known-good value is accepted; unknown roots,
conflicting key identities, ancestor replay and tampered canonical proofs leave
the previous trust state unchanged. The existing lease/grace and last-known-good
keyset remain usable while the license service is unavailable.

For a fresh control installation, the one-command installer invokes
`control-api fetch-entitlement-revocation` after activation. It signs the
`/installation/v2/entitlement-revocation-sets/current` request with the
owner-only `installation.key`, writes only the signed artifact to a `0400`
path, and passes that path to `install-entitlement`. The fetch command emits
no lease, private key, or activation credential. Older bundles remain valid;
callers that already have a current revocation LKG may omit `--revocation`.

## Control-plane upgrade eligibility

Migration `023_control_upgrade_check` adds the platform-only
`control.upgrades.check` permission and the idempotent
`POST /v1/admin/control-upgrade-checks` endpoint. A check re-verifies the current
cached entitlement signature and `valid` state, requires the requested channel
to match the lease, requires the current version to remain inside the signed
range, and then evaluates the same in-memory `platformpolicy.State` used by the
background policy synchronizer. It never calls the license service and does not
perform an upgrade. Identical retries return the stored decision and append no
second audit event. See
[`docs/runbooks/control-upgrade-policy.md`](../../docs/runbooks/control-upgrade-policy.md)
for denial reasons and operator checks.

## Durable node presence

When both `NODE_PRESENCE_NATS_URL` and `NODE_PRESENCE_REDIS_URL` are set,
`serve` binds a durable pull consumer to the existing `AGENT_HEARTBEATS` stream
and `cdnca.agent.heartbeats.*` subjects. Startup fails closed if NATS, Redis,
the stream, or the durable consumer contract is unavailable or incompatible;
the HTTP listener is not started in that state. Omitting both variables disables
this worker. Setting only one is a configuration error.

Gateway `HeartbeatAck` means only that JetStream returned PubAck. For a current
heartbeat, control-api acknowledges the JetStream delivery after PostgreSQL has
stored the latest projection, Redis has accepted the monotonic online lease, and
PostgreSQL has confirmed the exact projected token, including its request ID and
optional Agent version. The latest runtime projection
is intentionally separate from confirmed `last_seen_at`: a Redis failure may
preserve newer runtime evidence, but it cannot extend online status or create an
online audit transition. Transient PostgreSQL, Redis, confirmation, and ACK
failures are redelivered safely; malformed, conflicting, and unknown-node events
are terminated. Heartbeats older than the configured offline threshold are also
terminated before projection, so durable backlog cannot manufacture a fresh
online lease after a long control-plane outage; the exact threshold boundary is
accepted.

The offline worker requires both an expired confirmed PostgreSQL `last_seen_at`
and an explicitly absent Redis lease. Redis errors fail the scan instead of
marking nodes offline. The row-locked transition compares the confirmed epoch,
sequence, event ID, request ID, payload digest, and lease deadline so concurrent workers can
emit only one offline transition and a racing newer heartbeat finishes online.
Only online/offline transitions are appended to the audit log. Offline audit
events use the confirmed request ID rather than the event ID or an unconfirmed
newer projection.

`GET /v1/nodes` and `GET /v1/nodes/{id}` expose a nested `presence` object built
only from confirmed PostgreSQL fields. Its effective status is `online` only
while the confirmed token is within `NODE_PRESENCE_OFFLINE_AFTER`; older
confirmed tokens are `offline`, and nodes without a confirmed token are
`unknown`. The optional `agent_version` is the version confirmed after the Redis
lease write, not a newer unconfirmed projection. Agents released before the
heartbeat version field therefore appear with `agent_version` omitted.

Lists accept an independent `presence=online|offline|unknown` filter. Filtering
happens before UUID cursor pagination. The response also reports
`projection_freshness` (`fresh`, `stale`, or `never`) and `lease_signal`
(`present`, `absent`, or `unavailable`). A Redis read failure does not fail the
HTTP request or erase confirmed PostgreSQL evidence; it returns
`lease_signal: "unavailable"` and logs a warning so operators can distinguish a
lease-store outage from a confirmed offline node.

The main tuning variables are `NODE_PRESENCE_ACK_WAIT`,
`NODE_PRESENCE_OPERATION_TIMEOUT`, `NODE_PRESENCE_NAK_DELAY`,
`NODE_PRESENCE_LEASE_TTL`, `NODE_PRESENCE_OFFLINE_AFTER`, and
`NODE_PRESENCE_OFFLINE_INTERVAL`. `ACK_WAIT` must exceed three operation timeouts,
and the lease TTL must not exceed the offline threshold. Stream, subject,
durable, Redis key prefix, payload/deployment bounds, consumer limits, and scan
batch size also have `NODE_PRESENCE_*` overrides in `internal/config`.
