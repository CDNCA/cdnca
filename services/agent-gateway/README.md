# Agent Gateway

This module is the transport and session boundary between edge Agents and the
control plane. It does not own node records, certificate signing keys,
deployment state, artifacts, Redis, NATS, or PostgreSQL.

## Security boundaries

- `Servers.Enrollment` is a dedicated server-authenticated TLS 1.3 gRPC server.
  Its service descriptor contains only `Enroll`.
- `Servers.MTLS` is a separate TLS 1.3 gRPC server with
  `RequireAndVerifyClientCert`. Its service descriptor contains only
  `RenewCertificate`, `Connect`, and `FetchArtifact`.
- Node identity comes only from one verified URI SAN with the exact form
  `spiffe://cdn-platform/node/{canonical-uuid}`. A body `node_id` cannot replace
  or override that identity.
- Enrollment, certificate renewal, authorization, and artifact access are
  forwarded through the versioned ControlInternal client via the narrow
  `ControlPlane` interface. This module has no data-store credentials or CA
  private key.
- Receive/send sizes, metadata sizes, collection counts, handshake/control/
  artifact deadlines, keepalive enforcement, and concurrent streams are
  explicit in `Config`.

`Connect` requires `AgentHello` first, returns `GatewayHello` as the first
successful server payload, negotiates the highest shared protocol version, and
checks stream sequence, heartbeat sequence, session epoch, and bounded event
metadata before acknowledging receipt. Both session coordinators preserve the
same takeover rule: a response that already began completes before takeover is
published, while a fenced lease cannot start another response. Network calls
are not made while holding a Go mutex.

Production composition uses `NewWithDurableMessaging`. Each validated
heartbeat is published as deterministic protobuf binary to
`cdnca.agent.heartbeats.{node_id}` in `AGENT_HEARTBEATS`, with
`heartbeat.event.event_id` as `Nats-Msg-Id`. The Gateway sends `HeartbeatAck`
only after JetStream returns a PubAck for the configured stream. Duplicate
events are still acknowledged and are deduplicated by JetStream. Publication
timeout, disconnect, a mismatched expected stream, or any other persistence
failure closes the session without an acknowledgement, so the Agent reconnects
and retransmits the stable event.

When constructed with `NewWithCommandBus`, `Connect` binds a durable JetStream
pull consumer filtered to the authenticated node subject. The subscription is
created only after the node's session lease is acquired and only while the
current authorization snapshot has `deployments_allowed=true`. Every command
send passes through the lease's `FencedSend`; disconnects, failed sends,
superseded leases, and authorization revocation leave the command unacknowledged
and issue a best-effort negative acknowledgement for prompt redelivery.

Deployment statuses are strictly bounded and validated before publication as
deterministic protobuf binary. The Gateway waits for the status stream PubAck
before synchronously acknowledging every matching command delivery. The match
key is `deployment_id + attempt + config_version_id`. Status `event_id` is the
JetStream message ID, so a crash between status publication and command ACK can
repeat either operation without losing the durable status or changing the
original command event/request/deployment/attempt fields.

A session that negotiates `EDGE_UPGRADE` binds the per-node durable
`node_upgrade_<node_id with _>` on `AGENT_COMMANDS` (filter
`cdnca.agent.commands.upgrade.<node_id>`). The Gateway owns it like the other
per-node command durables: it creates the exact expected configuration on
first use (an identical create is idempotent), then requires an exact match
before and after binding. An existing durable with any other configuration is
never modified and the session is refused.

Upgrade status acknowledgements carry the exact status-stream PubAck stream and
sequence when `EDGE_UPGRADE_STATUS_PUBACK` is negotiated. With the optional
acknowledgement-receipt capability, the Gateway retains the acknowledgement
until the Agent confirms its durable journal. PubAck-only peers use the same
durable identity ledger as a bounded per-node replay horizon (the configured
pending-command limit); a repeated status returns the original sequence and
persisted time, while old completed identities are evicted from the horizon and
are never sent proactively during reconnect.

Session coordination mode is mandatory in `NewSessionCoordinator`:

- `standalone` uses `MemorySessionCoordinator` for one Gateway process;
- `distributed` requires a configured go-redis client and never falls back to
  memory when Redis is unavailable.

Distributed state uses one Redis hash slot per node. A TTL state hash contains
the active cryptographically random token, gateway/session owner, epoch, and
in-flight send count. A persistent counter in the same slot allocates monotonic
epochs. Lua is limited to acquire, renew, begin/end send, and release. Acquire
replaces an idle owner immediately, but waits with a configured deadline while
a prior send is in flight. Every send atomically validates its token and raises
the in-flight count before invoking the network callback. Renew, end-send, and
release are token-matched, so a stale token cannot revive or delete a newer
owner. Losing Redis or ownership closes `Superseded` within the configured
renew and operation bounds.

## Current boundary

In durable mode, a heartbeat acknowledgement proves that JetStream accepted the
event into its configured stream. It does not prove that PostgreSQL has projected
the event or that a Redis online lease has been derived. Those projections and
the offline decision worker are implemented by control-api's `nodepresence`
runtime and remain outside this module. `New()` and
`NewWithCommandBus()` intentionally keep compatibility without a heartbeat
sink; their heartbeat acknowledgements prove only process-local receipt and
must not be used for production online state.

Command creation, stream creation, status and heartbeat consumption into
PostgreSQL, authorization revocation push, and durable task orchestration are
outside this module. The Gateway binds pre-created NATS streams and does not own
their retention or replication policy.

The default subjects are `cdnca.agent.commands.{node_id}` and
`cdnca.agent.deployment-status.{node_id}` in `AGENT_COMMANDS` and
`AGENT_DEPLOYMENT_STATUS`; heartbeats use
`cdnca.agent.heartbeats.{node_id}` in `AGENT_HEARTBEATS`. Stream/subject names,
command/status/heartbeat byte limits, heartbeat persistence timeout, per-session
pending commands, consumer pending/waiting limits, AckWait, and NATS operation
timeouts are explicit configuration. The Gateway never logs command, status, or
heartbeat protobuf payloads, artifact bytes, tokens, certificates, or secrets.

The distributed coordinator assumes Redis persistence preserves the epoch
counter. Redis HA/failover validation, cross-region coordination, and recovery
from Redis data loss remain deployment work; they are not silently treated as
standalone operation.

`GatewayHello.message_id_replay_window` bounds inbound message ID digest
retention. Within that window, identical retransmissions are recognized and a
changed payload is rejected; after eviction, the stream sequence high-water
mark rejects the old message. The node authorization snapshot also carries the
enrollment-bound artifact encryption key ID, which is checked at handshake and
on every snapshot refresh.

The production executable is `cmd/agent-gateway`. It fails closed until Redis,
JetStream (including all three pre-created streams), and the mTLS
ControlInternal endpoint are ready. It then binds two distinct listeners and
stops both within a bounded grace period on `SIGINT` or `SIGTERM`.

Required environment:

```text
CDNCA_GATEWAY_ENROLLMENT_ADDR=:8443
CDNCA_GATEWAY_AGENT_ADDR=:8444
CDNCA_GATEWAY_INSTANCE_ID=<canonical UUID>
CDNCA_GATEWAY_VERSION=<release version>
CDNCA_GATEWAY_TLS_CERT_FILE=/run/secrets/gateway.crt
CDNCA_GATEWAY_TLS_KEY_FILE=/run/secrets/gateway.key
CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE=/run/secrets/agent-ca.crt
CDNCA_CONTROL_ADDRESS=control-api:9443
CDNCA_CONTROL_SERVER_NAME=control-api.internal
CDNCA_CONTROL_CLIENT_CERT_FILE=/run/secrets/control-client.crt
CDNCA_CONTROL_CLIENT_KEY_FILE=/run/secrets/control-client.key
CDNCA_CONTROL_SERVER_CA_FILE=/run/secrets/control-ca.crt
CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN=spiffe://cdn-platform/gateway/control
CDNCA_REDIS_URL=redis://redis:6379/0
CDNCA_NATS_URL=nats://nats:4222
CDNCA_TELEMETRY_NATS_URL=nats://analytics-nats:4222
CDNCA_TELEMETRY_NATS_USER=<publisher-only user>
CDNCA_TELEMETRY_NATS_PASSWORD=<publisher-only password>
```

`CDNCA_GATEWAY_STARTUP_TIMEOUT` and `CDNCA_GATEWAY_SHUTDOWN_TIMEOUT` are
optional positive Go durations and both default to `15s`. Redis and NATS URLs
may carry credentials, but configuration values, certificates, message
payloads, and dependency errors are never logged. NATS stream retention and
replication remain deployment-owned and are never created by this process.

`CDNCA_NATS_URL` is the command/status broker. `CDNCA_TELEMETRY_NATS_URL` is
the independent analytics broker; its username and password must be supplied
together and must identify a publisher-only account restricted to the
telemetry, CC coordination, connection, and L4 ingest subjects. It must not
reuse the control-api analytics consumer identity. An unauthenticated local
broker may omit both telemetry credential variables, but production Helm
deployments require all three values from the dedicated publisher Secret.

Startup verifies both command and telemetry JetStream dependencies before the
Gateway becomes ready. Shutdown marks the process unready, then independently
drains both NATS connections within `CDNCA_GATEWAY_SHUTDOWN_TIMEOUT`; a failed
drain is closed rather than allowed to extend shutdown without a bound.

The ControlInternal client certificate must contain exactly one URI SAN equal
to `CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN`. All Gateway private-key files must
be owner-only. The executable fixes both sides of every TLS connection to TLS
1.3 and, after the blocking mTLS dial, requires the standard health response for
`ControlInternalService` to be `SERVING`; transport connectivity alone is not
accepted as control-plane readiness.

The executable composition supplies:

- two distinct listeners and public server certificates;
- a client CA pool for the mTLS listener;
- an authenticated generated `ControlInternalServiceClient`;
- an explicit standalone/distributed session mode and, for distributed mode,
  a production-configured go-redis client;
- a pre-provisioned, file-backed heartbeat stream and `HeartbeatSink` through
  `NewWithDurableMessaging` for production online-state inputs;
- configuration and lifecycle handling for both gRPC servers.

The repository root must add this module to `go.work`; this slice intentionally
does not modify root-owned files. The root workspace now includes it; it can also
be verified independently with:

```sh
GOWORK=off go test -count=1 ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
```

The real Redis suite starts an isolated `redis-server` on a random loopback port
and uses a temporary data directory:

```sh
GOWORK=off go test -tags=integration -count=1 ./...
GOWORK=off go test -race -tags=integration -count=1 ./...
```

The JetStream integration additionally requires task-owned NATS and Redis
addresses. It creates uniquely named streams and Redis keys and removes only
those resources:

```sh
CDNCA_TEST_NATS_URL=nats://127.0.0.1:4222 \
CDNCA_TEST_REDIS_ADDR=127.0.0.1:6379 \
GOWORK=off go test -tags=integration -run JetStream -count=1 ./...
```

That suite uses separate NATS connections and Redis Gateway identities to prove
fencing, disconnect redelivery, status-stream failure, duplicate status
publication, and eventual command acknowledgement. The NATS-only heartbeat test
also proves PubAck-before-HeartbeatAck ordering, deterministic payloads,
cross-Gateway deduplication, disconnect/retransmit recovery, expected-stream
failure, canonical node IDs, and payload limits.

Integration tests create self-signed CA and leaf keys only in process memory.
No test private key is stored in the repository, and Redis tests do not flush
or reuse a developer Redis database.
