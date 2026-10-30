# Edge Agent Packaging Helper Protocol v1 through v4

This file is the frozen character-level contract for OPS-06/11. Implementations
and tests may not extend it implicitly. A new field, operation, framing rule, or
meaning requires a new protocol version.

## Transport and peer authority

- Linux only. The transport is one Unix `SOCK_SEQPACKET` connection per request.
- The production address is `/run/cdnca-edge-agent/helper.sock`.
- systemd owns the listening socket as `cdnca-edge:cdnca-edge` with mode `0600`.
- The helper accepts exactly two peer identities: the numeric UID and primary
  GID resolved for the fixed `cdnca-edge` account, and the exact root identity
  UID 0 with GID 0. It obtains them from `SO_PEERCRED`; request bytes never
  carry identity authority. Any other pair, including UID 0 with a non-zero GID
  or a non-zero UID with GID 0, is `ERR_UNAUTHORIZED`.
- Root is accepted because native nodes run the Agent as root (their OpenResty
  worker management requires it). A root peer can already read the pinned keys,
  write the release tree and run the fixed packaging scripts directly, so the
  helper grants it no authority it lacks; every bundle, manifest signature,
  pinned-key, journal and replay check applies to it unchanged. The socket
  owner, group and mode below do not change: root connects through DAC override.
- At startup the helper verifies fd 3 is one listening Unix `SOCK_SEQPACKET`
  socket, its path is the production address, and `lstat` reports the expected
  numeric owner, group, type, and exact mode. The client performs the same path,
  type, owner, group, and mode checks before connecting. Any mismatch fails
  closed.
- A connection carries exactly one request packet and one response packet and
  is then closed. Request and response packets are at most 32768 bytes. Kernel
  `MSG_TRUNC` or `MSG_CTRUNC`, empty packets, extra packets, and malformed
  control messages are rejected.
- Client context deadlines are capped by fixed operation limits. The helper
  enforces 5 seconds for `current` and v2 `inspect_transaction`, and 300 seconds
  for `query`, `install`, `rollback`, v2 `prepare_install`, v4
  `mark_installing`, and v2 `activate_install`. v1 `query` may resume an interrupted mutation, so it uses
  the mutation budget. No caller-controlled timeout is present on the wire.

## Canonical JSON

Packets are UTF-8 JSON without a BOM or trailing newline. They are the exact
compact output of Go `encoding/json.Marshal` for the field order shown below.
Unknown fields, duplicate keys, missing required fields, alternate field order,
insignificant whitespace, trailing bytes, and non-canonical escapes or numbers
are rejected. Strings must contain printable ASCII and satisfy the field rules;
there are no `null` values.

The four request shapes are exactly:

```text
{"protocol_version":1,"operation":"current"}
{"protocol_version":1,"operation":"query","transaction_id":"txn-123"}
{"protocol_version":1,"operation":"install","transaction_id":"txn-123","release_sequence":2,"current_version":"1.0.0","target_version":"1.1.0","platform":"linux","architecture":"amd64","artifact_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","artifact_size":1234,"audit_basename":"artifact","current_receipt":RECEIPT}
{"protocol_version":1,"operation":"rollback","transaction_id":"txn-123","release_sequence":2,"artifact_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expected_current_version":"1.1.0","rollback_version":"1.0.0","active_receipt":RECEIPT,"previous_receipt":RECEIPT}
```

`RECEIPT` is exactly this field order. `previous_version` is omitted only when
empty:

```text
{"schema_version":1,"installer_transaction_id":"txn-123","release_sequence":2,"artifact_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","current_version":"1.1.0","previous_version":"1.0.0","status":"active","issued_at":"2026-07-28T00:00:00Z","signature":{"key_id":"helper-2026-01","value":"BASE64RAW"}}
```

Success and error responses are exactly:

```text
{"protocol_version":1,"ok":true,"receipt":RECEIPT}
{"protocol_version":1,"ok":false,"error_code":"ERR_BAD_REQUEST"}
```

Protocol v2 adds a split journal workflow without changing any v1 shape or
meaning. Its four request shapes are exactly:

```text
{"protocol_version":2,"operation":"prepare_install","transaction_id":"txn-123","release_sequence":2,"current_version":"1.0.0","target_version":"1.1.0","platform":"linux","architecture":"amd64","artifact_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","artifact_size":1234,"audit_basename":"artifact","current_receipt":RECEIPT}
{"protocol_version":2,"operation":"inspect_transaction","transaction_id":"txn-123"}
{"protocol_version":2,"operation":"activate_install","transaction_id":"txn-123","install_payload_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","prepared_ack":PREPARED_ACK}
{"protocol_version":2,"operation":"abort_prepared","transaction_id":"txn-123","install_payload_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","prepared_ack":PREPARED_ACK}
```

Protocol v3 keeps the split journal operations while adding execution sequence
and action fields for v3 transactions. `mark_installing` is a v4 extension
because it changes the operation set. Its only request shape is:

```text
{"protocol_version":4,"operation":"mark_installing","transaction_id":"txn-123","install_payload_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","prepared_ack":PREPARED_ACK}
```

The v4 mark request accepts either the v2 prepared ACK or the v3 prepared ACK.
An older helper that rejects v4 with `ERR_PROTOCOL` is safely probed with the
legacy v2/v3 `activate_install` operation. That fallback performs the atomic
activation and returns an active receipt; the edge runtime does not publish an
intermediate `installing` status for that path. Any other negotiation or
activation error remains fail-closed.

After a v4 `mark_installing` response, the client must perform the durable
`inspect_transaction` readback using protocol v2 or v3 (matching the prepared
ACK's schema). Protocol v4 intentionally exposes only `mark_installing`; a v4
inspect request is malformed and must never be used as the readback proof.

`PREPARED_ACK` is the exact durable identity of the staged transaction:

```text
{"schema_version":1,"transaction_id":"txn-123","install_payload_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","release_sequence":2,"artifact_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","manifest_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","executable_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sbom_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","previous_version":"1.0.0","target_version":"1.1.0"}
```

Successful v2 responses are an exact union of one receipt, one prepared ACK, or
one transaction status. Error responses contain none of them:

```text
{"protocol_version":2,"ok":true,"prepared_ack":PREPARED_ACK}
{"protocol_version":2,"ok":true,"transaction_status":{"transaction_id":"txn-123","phase":"prepared","prepared_ack":PREPARED_ACK}}
{"protocol_version":2,"ok":true,"receipt":RECEIPT}
{"protocol_version":2,"ok":false,"error_code":"ERR_TRANSACTION_CONFLICT"}
```

Transaction status phases are exactly `unknown`, `prepared`, `aborted`,
`installing`, `active`, and `rolled_back`. `unknown` contains only the
transaction ID and phase. `prepared`, `aborted`, and `installing` also contain
the exact prepared ACK. `active` and `rolled_back` additionally contain their
stored signed receipt. A client must reject a response whose
`protocol_version` differs from its request.

Identifiers and versions are 1 through 128 bytes and match
`[A-Za-z0-9][A-Za-z0-9._-]*`. SHA-256 values are 64 lowercase hex bytes.
`artifact_size` is positive and at most 285229182. `release_sequence` is
positive. `platform` is `linux`; `architecture` is `amd64` or `arm64` and must
match the host. `audit_basename` has the identifier grammar, is never opened,
and is not filesystem authority.

## Descriptor transfer and release bundle

- v1 `install` and v2 `prepare_install` carry exactly one `SCM_RIGHTS` fd. Every
  other operation carries no fd. Replayed `install` and `prepare_install` calls
  still carry and revalidate one fd.
- The helper requires `fstat` regular file, link count 1, positive exact size,
  and `fcntl(F_GETFL)` access mode `O_RDONLY`. It seeks and recomputes SHA-256
  from that fd. It never reopens a caller path and rejects directories,
  symlinks, sockets, devices, writable descriptors, extra descriptors, procfs
  indirection, size mismatch, and digest mismatch.
- The production artifact is canonical binary release bundle v1. It starts
  with the exact 30-byte sequence made from the 29 ASCII bytes
  `cdnca-edge-release-bundle/v1` followed by one NUL byte. Four sections follow
  in this fixed order: `manifest`, `signature`,
  `sbom`, `executable`. Each section is encoded as one unsigned 64-bit
  big-endian length followed immediately by that many raw bytes. There are no
  encoded names, modes, timestamps, paths, optional fields, compression,
  padding, or trailing bytes.
- Section limits are: manifest 1 through 16384 bytes; signature exactly 64
  bytes; SBOM 1 through 16777216 bytes; executable 1 through 268435456 bytes.
  The maximum outer bundle size, including the 30-byte magic and four 8-byte
  lengths, is exactly 285229182 bytes. The parser streams each section to the
  fixed root-only staging filenames `manifest`, `manifest.sig`,
  `edge-agent.spdx.json`, and `edge-agent`, rejects short reads, zero lengths,
  overflow, over-limit lengths, and any trailing byte, then uses mode `0500`
  for the executable and `0400` for the other files.
- A golden vector is the byte concatenation
  `MAGIC || u64be(len(manifest)) || manifest || u64be(64) || signature ||
  u64be(len(sbom)) || sbom || u64be(len(executable)) || executable`. Tests
  freeze its exact SHA-256 and reject any byte, order, length, or suffix change.
- The root-only `0700` transaction staging paths are never passed to packaging.
  For each upgrade attempt the helper creates a fresh root-owned task directory
  with the fixed prefix `/tmp/cdnca-edge-agent-helper-` inside the service's
  systemd `PrivateTmp`, mode `0711`, and one fixed child named `handoff`, mode
  `0755`. The child contains only `manifest`, `manifest.sig`,
  `edge-agent.spdx.json`, and `edge-agent`; the executable is `0555` and the
  other files are `0444`, so the packaging UID 65534 probe can traverse,
  read, and execute but cannot modify them.
- The helper opens each root-staged source with `O_NOFOLLOW`, requires a
  root-owned single-link regular file with the journal-bound mode and exact
  size, and recomputes its journal-bound digest while copying. Each destination
  is created in the root-owned handoff with `O_EXCL|O_NOFOLLOW`, is never
  hard-linked, and is fsynced before the directory is exposed to packaging.
  Success, failure, and cancellation remove and fsync the complete task
  directory. Concurrent attempts use distinct random suffixes. No handoff is
  durable or reused after a crash; restart reconstructs new handoff bytes only
  from the verified root journal staging.
- The helper passes only those generated handoff paths and the fixed pinned key
  `/etc/cdnca-edge-agent/package-signing.pem` to the fixed
  `/usr/libexec/cdnca-edge-agent/upgrade.sh`. It executes no shell and no
  caller-supplied program, path, URL, environment, node identity, option, or
  command. Rollback invokes only
  `/usr/libexec/cdnca-edge-agent/rollback.sh --version <journal-bound-version>`.
  The scripts retain their manifest signature, SBOM, ELF, version, config,
  atomic current/previous, health, recovery, and rollback checks.

## Transactions and recovery

- The fixed state directory is `/var/lib/cdnca-edge-agent-helper` (`0700`,
  root:root). Key and journal files are non-symlink, single-link regular files.
  Journals are `0600`, root:root.
- Packaging's canonical live state is
  `/var/lib/cdnca-edge-agent-backups/active-state`. State restore staging and
  historical backups are siblings below the same exact common root. Packaging
  exchanges the canonical directory directly; it never exchanges through the
  edge service's `/var/lib/cdnca-edge-agent` bind target. Every accepted state
  tree is confined to the filesystem device of its root; a nested mount or
  other cross-device entry fails closed.
- The edge service exposes `active-state` at the unchanged service-account home
  with the fixed systemd bind
  `/var/lib/cdnca-edge-agent-backups/active-state:/var/lib/cdnca-edge-agent:norbind`.
  The helper has no write exception for the bind target and receives no broad
  `/var/lib` authority, `CAP_SYS_ADMIN`, namespace escape, or copy-back path.
- The restricted updater requires the migrated layout and never creates or
  repairs it. A fixed root package installer owns legacy migration. Its durable,
  fsynced phases are `prepared`, `unit_installed`, `state_move_intent`,
  `activated`, and `revert_intent`; recovery binds the legacy device, inode,
  canonical tree digest, and old/new unit digests. Double presence, double
  absence, or any mismatched fact fails closed. The new bind unit is installed
  before the atomic move, and the unchanged old release must pass health through
  that unit before activation. Revert restores the old unit and atomically moves
  the same payload back to the legacy path.
- Tmpfiles declares only `/var/lib/cdnca-edge-agent-backups`; it does not create
  `active-state`, the legacy bind target, or their children. The root package
  installer owns those paths and keeps the bind target root-owned, mode `0700`,
  and empty outside the edge service mount namespace. The helper service starts
  only when `active-state` is a directory and
  `/var/lib/cdnca-edge-agent-packaging/layout-migration` does not exist. A
  legacy or interrupted layout therefore fails before helper key or journal
  creation and must be recovered by the root installer.
- Each transaction has one canonical `install` packet hash and, after an active
  install, at most one canonical `rollback` packet hash. A repeat of the same
  operation with the same transaction ID and exact packet is idempotent. The
  same operation and ID with any different byte is
  `ERR_TRANSACTION_CONFLICT`. `rollback` is deliberately a second operation on
  the install transaction and must bind the stored active and previous facts.
- v2 `prepare_install` stages and verifies the complete bundle, persists the
  existing `prepared` journal phase durably, and only then returns the exact
  prepared ACK. It never invokes packaging. Replaying the same canonical
  prepare packet returns the journal-derived ACK in every known phase except
  `aborted`, without repeating packaging. The `aborted` tombstone is terminal
  for preparation: the same or a different prepare packet for that transaction
  fails with `ERR_TRANSACTION_CONFLICT`.
- v2 `abort_prepared` binds the original canonical prepare-packet SHA-256 and
  exact prepared ACK. It is accepted only from `prepared`, persists the
  `aborted` tombstone before removing the staged transaction directory, and
  never invokes packaging. A cleanup failure returns `ERR_STATE_UNCERTAIN`
  while retaining the tombstone so a retry can finish cleanup. An idempotent
  abort replay returns the same journal-derived status; `installing`, `active`,
  and `rolled_back` reject abort with `ERR_TRANSACTION_CONFLICT`.
- v2 `inspect_transaction` is a pure journal read. It never calls packaging,
  inspects or changes the installed release, writes a journal/current receipt,
  or resumes a transaction. A missing journal is the successful `unknown`
  status. Contradictory or corrupt durable facts fail with
  `ERR_STATE_UNCERTAIN` rather than being normalized.
- v2 `activate_install` carries no artifact fd and binds both the original
  canonical prepare-packet SHA-256 and the exact prepared ACK. The helper
  persists `installing` before invoking packaging. A conflicting digest or ACK
  fails closed. Terminal replay returns the stored signed receipt without
  invoking packaging again.
- v4 `mark_installing` carries no artifact fd and binds the same canonical
  prepare-packet SHA-256 and exact prepared ACK. It durably transitions only a
  `prepared` journal to `installing`; replay while already `installing` returns
  the same transaction status, while terminal phases fail closed. The edge
  runtime publishes its `installing` status only after this response is durable.
- Before an external packaging side effect, the helper stages and fsyncs the
  bundle sections, writes and fsyncs a canonical journal, atomically renames
  it, and fsyncs the parent directory. Result receipts and current facts are persisted
  with the same write/fsync/rename/fsync sequence before a response is sent.
- Journal phases are exactly `prepared`, `aborted`, `installing`, `active`,
  `rollbacking`, and `rolled_back`. The journal binds the outer bundle digest,
  the complete signed manifest digest, and the signed manifest's inner
  executable and SBOM digests for recovery audit. On restart, `query` or an
  idempotent retry resumes `prepared`, `installing`, or `rollbacking` by invoking the same fixed
  packaging operation against the journal-owned staging. The packaging
  transaction journal performs its own recovery first. The helper then verifies
  the root-owned installed manifest/current facts and persists the result. It
  never infers success from an exit status alone.
- When recovering an `installing` journal, the helper first verifies installed
  facts. Exact target facts are signed and persisted as `active` without
  repeating packaging. Exact previous facts permit one recovery invocation of
  the fixed packaging operation. Any third state returns
  `ERR_STATE_UNCERTAIN` without invoking packaging. This covers process death
  immediately before and immediately after the external activation boundary.
- `current` verifies the installed current symlink and signed installed
  manifest against the pinned release key. Its release sequence is the maximum
  of the installed manifest, accepted-manifest high-water mark, and persisted
  helper high-water mark. Unknown or contradictory facts return
  `ERR_STATE_UNCERTAIN`; they are not guessed.

## Receipt signature and key lifecycle

The helper signs updater `ActivationReceipt` schema 1 with Ed25519. Signing
bytes are the exact compact `encoding/json.Marshal` output in this field order;
`previous_version` is omitted only when empty:

```text
{"schema_version":1,"installer_transaction_id":"txn-123","release_sequence":2,"artifact_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","current_version":"1.1.0","previous_version":"1.0.0","status":"active","issued_at":"2026-07-28T00:00:00Z","key_id":"helper-2026-01"}
```

`issued_at` is UTC using Go's canonical `time.Time` JSON encoding. Signature
values use unpadded base64 (`base64.RawStdEncoding`). An install receipt binds
the outer release-bundle digest. A rollback result has status `rolled_back`,
current version equal to the restored version, and previous version equal to
the failed version. `current` always returns an `active` receipt.

The current private key is
`/var/lib/cdnca-edge-agent-helper/receipt-key.json`, canonical JSON mode `0400`,
root:root, with `schema_version`, `key_id`, and an unpadded base64 64-byte
Ed25519 private key. It is generated from kernel randomness only by the fixed
root helper key-initialization action and is loaded after owner/mode/type/link
checks. It is never sent over IPC, inherited by packaging children, placed in
arguments or environment, or logged. The matching public pin is
`/etc/cdnca-edge-agent/helper-receipt-public.json`, mode `0440`,
root:cdnca-edge. Rotation atomically provisions a new private file and public
pin with a new key ID; updater trust overlaps old and new public key IDs until
all in-flight journals settle. Old public keys may remain trusted, but old
private keys are not retained by the Agent.

## Stable errors

The complete v1 error set is:

```text
ERR_BAD_REQUEST
ERR_PROTOCOL
ERR_UNAUTHORIZED
ERR_SOCKET_POLICY
ERR_FD_REQUIRED
ERR_FD_FORBIDDEN
ERR_FD_UNSAFE
ERR_ARTIFACT_MISMATCH
ERR_TRANSACTION_CONFLICT
ERR_TRANSACTION_UNKNOWN
ERR_CURRENT_UNAVAILABLE
ERR_PACKAGING_FAILED
ERR_ROLLBACK_FAILED
ERR_STATE_UNCERTAIN
ERR_DEADLINE
ERR_INTERNAL
```

Errors contain no caller URL/path, private key material, receipt signature,
artifact bytes, command output, or uncontrolled text.
