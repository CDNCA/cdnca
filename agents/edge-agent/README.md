# CDNCA Edge Agent

`internal/gatewayclient` is the production client boundary for the Agent Gateway. It connects only with TLS 1.3 mTLS, verifies the Gateway certificate name, negotiates the protobuf protocol version, sends heartbeats, receives durable deployment commands, downloads authorized artifacts through `FetchArtifact`, and executes them with `deployment.Manager`.

## Durable behavior

- A command is written atomically to an owner-only journal before `DELIVERED` is sent.
- The durable identity is `event_id + deployment_id + attempt + config_version_id`; a conflicting command for the same deployment attempt is rejected.
- Every verified artifact chunk advances a durable offset. A new `FetchArtifact` request at a new offset uses a new request ID.
- Deployment status event IDs and protobuf bytes are stable across reconnects and process restarts.
- Upgrade status acknowledgements include the Gateway-verified `AGENT_DEPLOYMENT_STATUS` stream and sequence when that capability is negotiated; the Agent persists that exact publication identity before compacting the status journal. Receipt-capable sessions additionally persist the canonical acknowledgement receipt. A session that cannot provide the negotiated publication identity fails closed instead of writing an unverifiable acknowledgement.
- `deployment.Manager` remains the activation journal. If the process stops after activation but before client status persistence, retrying `Process` returns the recorded result without reloading the runtime again.
- An explicit `ROLLBACK` uses `config_version_id` as the target and requires `previous_config_version_id` to match the active baseline. The target must be the locally recorded previous healthy release; its digest comes only from local pointers and its immutable files are fully reverified.
- `ROLLBACK` requires an empty artifact list and never calls `FetchArtifact`. The target digest comes only from the local previous-release pointer, so a rollback command cannot introduce new bytes or trust metadata.

The journal directory, artifact parts, client certificate, and private key must be in non-symlink, owner-only directories. Journal and artifact files are written with mode `0600`.

## Cache task executor

`internal/cachetask` executes schema version 2 exact URL, directory-prefix, whole-site
purge, and URL-list prewarm tasks against a resolver-supplied published site
context. It journals task and item progress, binds task IDs and operation IDs,
recovers unfinished work after restart, retains successful items during partial
retry, serializes the same site, and allows bounded parallel work across sites.

Purge scans only the hashed site cache directory and deletes a regular cache file
after its bounded native key metadata, MD5 filename, Nginx `levels=1:2` path,
domain, port, inode, and link count all match. Prewarm can dial only the configured
loopback address and published site listener; it sends GET without caller headers,
does not follow redirects, and bounds time, headers, body, response status, global
rate, and site rate. Details and stable result codes are in
`docs/runbooks/edge-cache-task.md`.

This is a node-local executor. The current protobuf and daemon do not yet expose a
cache-task command, and no control API, Gateway delivery, JetStream fan-out, UI,
or distributed completion is claimed.

## Configuration artifact

This slice accepts exactly one descriptor with:

- kind `CONFIGURATION`
- encryption `NONE` or RFC 9180 HPKE `X25519/HKDF-SHA256/AES-256-GCM`
- compression `NONE` or `ZSTD`
- media type `application/vnd.cdnca.edge-configuration-bundle+json;version=1`
- an Ed25519 or ECDSA P-256 SHA-256 signature from an independently configured trust anchor

For encrypted artifacts the wire format is exactly `enc[32] || ciphertext || GCM-tag[16]`. The descriptor size, SHA-256, and signature cover those encrypted wire bytes. The Agent verifies all three before HPKE decryption, then performs bounded decompression and strict JSON decoding. Plaintext artifacts remain supported for version 1 configurations.

HPKE binds the ciphertext to the event ID, deployment ID, attempt, configuration version, artifact ID, recipient key ID, kind, encrypted size, signing key ID, signature algorithm, compression, media type, and encryption algorithm. The protocol domains are `cdnca-edge-artifact-hpke-binding-v1`, `cdnca-edge-artifact-hpke-info-v1`, and `cdnca-edge-artifact-hpke-aad-v1`, each followed by a NUL byte. The complete binary binding uses big-endian length-prefixed strings and integers as implemented in `internal/gatewayclient/hpke.go`; producers must use the identical versioned encoding.

After verification and optional decryption, the bounded decompressed bytes are decoded as strict JSON:

```json
{
  "version": 1,
  "manifest": {
    "files": [
      {
        "path": "nginx/site.conf",
        "size": 25,
        "sha256": "lowercase-sha256"
      }
    ]
  },
  "manifest_sha256": "lowercase-sha256-of-normalized-manifest",
  "files": {
    "nginx/site.conf": "base64-encoded-file-bytes"
  }
}
```

Unknown fields, trailing JSON, invalid paths, digest mismatches, oversized content, extra artifacts, plaintext node secret bundles, unknown encryption algorithms, recipient mismatches, and failed HPKE authentication are rejected for `APPLY`. Encrypted node secret bundles remain unsupported by this configuration-only slice. `RECONCILE` remains unsupported; no unsupported command is treated as applied. Decrypted and decompressed byte slices are cleared after use on a best-effort basis; Go runtime copies and kernel/filesystem buffers cannot be guaranteed to be zeroized.

## Explicit rollback

An explicit rollback is limited to the pair already recorded in `pointers.json`:

- `config_version_id` must equal `previous`, and `previous_config_version_id` must equal `current`.
- The active `current` symlink and its verified digest must still match the recorded baseline before any switch.
- The target directory must already exist under `releases/<sha256>` and pass manifest, file-set, size, and file SHA-256 verification. The command cannot provide a deployment bundle to `deployment.Manager`.
- The Agent re-runs the target precheck, atomically switches `current`, reloads, and confirms health before swapping current/previous pointers.
- Target, baseline, precheck, pointer, reload, and health failures use stable rollback error codes. A target runtime failure enters a durable restore phase; the original release is selected, reloaded, and health-checked with bounded recovery time before `FAILED` can report `running_config_unchanged=true`. Failure to confirm the original release ends in `ROLLBACK_FAILED`.
- Successful transitions are `DELIVERED -> STAGED -> PRECHECKED -> REVERTING -> REVERTED`. Duplicate delivery and process restart replay the same journal result without rechecking the now-swapped baseline or repeating reload.

## Trust anchors

Trust anchors can be injected with `NewTrustStore`, or loaded from a deployment-owned read-only file with `LoadTrustStore`. The file's containing directory must be mode `0700`, and the file must have no write bits, for example mode `0400`.

```json
{
  "version": 1,
  "keys": [
    {
      "key_id": "release-2026-01",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    }
  ]
}
```

Trust never comes from the configuration bundle itself. The client package does not log commands, artifacts, certificates, private keys, or payloads.

## Daemon

`cmd/edge-agent` assembles the mTLS Gateway client, artifact trust store, durable Gateway journal, deployment manager, and the real `deployment.OpenResty` adapter into a long-running process. In configuration version 2, `node_id`, the artifact recipient key, and mTLS client paths come only from the validated enrollment identity directory. A new `boot_id` is generated for every process start, so reconnects within one process retain a boot identity while a systemd restart creates a new one.

### Initial enrollment

Run enrollment before writing the daemon configuration. The enrollment listener uses TLS 1.3 server authentication and the issued identity is subsequently usable only with mTLS:

```sh
edge-agent enroll \
  --gateway-address gateway.example.internal:19443 \
  --gateway-server-name gateway.example.internal \
  --gateway-root-ca-file /etc/cdnca-edge-agent/tls/ca.pem \
  --identity-dir /etc/cdnca-edge-agent/identity \
  --token-file /run/secrets/cdnca-edge-enrollment-token
```

Omit `--token-file` to read one exact token line from stdin. A token file must be a non-symlink owner-only regular file. The command hashes the bounded, non-symlink `--machine-id-file` (default `/etc/machine-id`) with the `cdnca-machine-fingerprint-v1` domain; it never sends or persists the raw machine ID. It creates an Ed25519 mTLS key and SAN-free CSR plus an independent X25519 artifact key. The token and private keys are never logged.

Re-enrollment (a `re_enrollment` token, after moving the old identity aside) may omit `--gateway-address` and `--gateway-server-name`: the command then reads the Gateway list the daemon persisted from GatewayHello (`--journal-dir`, default `/var/lib/cdnca-edge-agent/gateway-journal`, file `gateway-endpoints.json`) and tries each published Gateway's enrollment address (`grpc` entries with `EnrollmentAddress`) in order. Only a Gateway-side failure (unreachable, disabled, refused) moves to the next one; the same pending request is replayed, so a retry cannot issue two identities.

The output directory is created atomically with mode `0700` and contains owner-only `identity.json`, `client.pem`, `client-key.pem`, and `artifact-x25519-key.bin`. Configuration version 2 references only this directory; the daemon revalidates the certificate chain, ClientAuth-only SPIFFE identity, Ed25519 key binding, validity period, and X25519 key ID on every start. A sibling `.enrolling` directory contains no token and is retained only when an RPC outcome is uncertain; rerunning with the same token safely replays the same request ID, CSR, fingerprint, and X25519 public key. An existing completed identity is never overwritten, and an OS-backed file lock fences concurrent enrollment processes.

The daemon reads one strict JSON file from `/etc/cdnca-edge-agent/config.json`. Set `CDNCA_EDGE_CONFIG` or pass `-config` to select another absolute path. The file must be a non-symlink owner-only regular file (for example mode `0600`). All state and security paths must be absolute and clean, and no existing ancestor may be a symbolic link. On macOS, use resolved `/private/var/...` and `/private/etc/...` forms; production Linux normally keeps `/var/...` and `/etc/...`. Unknown fields, duplicate fields, trailing JSON, unsafe or overlapping state roots, non-loopback health URLs, zero limits, and inconsistent timeouts are rejected before connecting.

```json
{
  "version": 2,
  "identity_dir": "/etc/cdnca-edge-agent/identity",
  "artifact_trust_file": "/etc/cdnca-edge-agent/trust/artifacts.json",
  "deployment_root": "/var/lib/cdnca-edge-agent/deployments",
  "journal_dir": "/var/lib/cdnca-edge-agent/gateway-journal",
  "gateway": {
    "address": "gateway.internal:19444",
    "server_name": "gateway.internal",
    "root_ca_file": "/etc/cdnca-edge-agent/tls/ca.pem"
  },
  "openresty": {
    "binary": "/usr/local/openresty/bin/openresty",
    "config_file": "nginx.conf",
    "health_url": "http://127.0.0.1:18080/healthz",
    "version": "1.31.1.1"
  },
  "certificate_runtime": {
    "state_root": "/var/lib/cdnca-edge-agent/certificates",
    "listen_address": "127.0.0.1",
    "listen_port": 18443
  },
  "limits": {
    "max_command_bytes": 1048576,
    "max_status_bytes": 262144,
    "max_artifact_bytes": 134217728,
    "max_decompressed_bytes": 134217728,
    "max_artifact_chunk_bytes": 1048576,
    "max_active_deployments": 128,
    "command_queue_size": 32,
    "max_files": 4096,
    "max_file_bytes": 16777216,
    "max_total_bytes": 134217728,
    "retain_releases": 5
  },
  "timeouts": {
    "handshake": "10s",
    "artifact_fetch": "2m",
    "initial_backoff": "250ms",
    "maximum_backoff": "30s",
    "precheck": "15s",
    "reload": "15s",
    "health": "30s",
    "health_interval": "500ms",
    "health_request": "2s"
  }
}
```

The identity and TLS files must be owner-only. Version 2 forbids `node_id`, `artifact_encryption_key_id`, `gateway.client_certificate_file`, and `gateway.client_private_key_file`, including empty overrides. Version 1 remains accepted for migration but has no artifact decryption private key and therefore supports plaintext artifacts only. The artifact trust file must additionally be read-only and live in an owner-only directory as described above. The health endpoint must return HTTP 200, the exact `X-CDNCA-Config-Version` header, and `ok:<config-version>\n`; it is restricted to a literal IPv4 or IPv6 loopback address. `certificate_runtime.state_root` is a separate private state tree, and its listener must be a canonical, zone-free loopback IP with a nonzero port. Before the Gateway stream starts, the Agent restores the persisted current certificate release or its last-known-good fallback; malformed persisted certificate state fails startup.

The site deployment OpenResty master is a separate systemd-managed runtime. The Agent does not copy the smoke-test process wrapper into production; it prechecks staged site releases and asks that existing master to reload after the deployment manager atomically changes the active release pointer. Certificate serving uses a distinct Agent-managed OpenResty master with its own state root, PID file, loopback listener, and temporary directories. Certificate apply and startup recovery may start or reload that master, and Agent shutdown deliberately leaves the active certificate process serving while the next Agent start validates and recovers current or last-known-good state. systemd should order the Agent after the site OpenResty service and use `SIGTERM`; both `SIGTERM` and `SIGINT` cancel the Gateway stream and in-flight bounded operations cleanly.

Explicit `ROLLBACK` is supported only for the locally recorded previous healthy release as described above. `RECONCILE` remains unsupported.
