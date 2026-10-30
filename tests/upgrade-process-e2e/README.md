# Upgrade Process E2E

This directory owns the repository-external UPG-01 process acceptance driver. It exercises the production chain:

`License -> Control rollout -> Gateway JetStream -> Linux Edge Agent/helper -> License parent receipt`

The driver does not replace package tests. It starts the four production binaries, with the privileged packaging helper activated by systemd inside the Edge container. It must remain independent of production Go packages so that it observes only public HTTP, gRPC, JetStream, PostgreSQL, filesystem, and process behavior.

## One-shot command

```sh
bash tests/upgrade-process-e2e/run.sh
```

To assemble the local inputs without creating any external registry or attestation evidence, first run the task-owned preparer with the required local artifact paths in the environment:

```sh
bash tests/upgrade-process-e2e/prepare-inputs.sh --output /tmp/cdnca-upgrade-e2e.env
set -a; . /tmp/cdnca-upgrade-e2e.env; set +a
```

The preparer validates, but never fabricates, the 19 external GitHub OIDC/GHCR inputs (the digest-pinned systemd image, two native subjects, exact issuer/workflow identity, and seven evidence files with canonical SHA-256 values). A missing or drifting external artifact fails before any local output is created. It generates or assembles only the remaining 100 local variables/files and never prints secret values.

The default command is fail-closed. It exits `77` before reserving a task identity, creating a work directory, starting Docker, or launching any process unless every frozen external input is supplied and valid. Static validation starts no resources:

```sh
UPGRADE_E2E_STATIC_ONLY=1 tests/upgrade-process-e2e/run.sh
```

## Frozen inputs

Every manifest uses sorted unique lines in `SHA256<two spaces>repo-relative-path` form. The driver hashes the manifest itself and every listed regular non-symlink file. Manifest C is set-equal to the full `agents/edge-agent/` tree with no exclusions: its file count is derived dynamically from that complete tree, and any later addition or removal must be reflected by the manifest. A symlink at the repository or Edge root, a tree symlink, or any non-directory/non-regular member such as a FIFO fails closed. The live comparison completes before task reservation or work-directory creation. The immutable snapshot phase independently filters its frozen inventory and repeats the exact comparison, so an add, delete or byte change between preflight and copy is rejected.

Required image, identity, contract and credential values:

- `UPGRADE_E2E_SYSTEMD_IMAGE`: immutable OCI digest reference (`name@sha256:<64-lowercase-hex>`)
- `UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT`, `UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT`: the two distinct native image digests in the final image index, using the same repository as `UPGRADE_E2E_SYSTEMD_IMAGE`
- `UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER`: exact GitHub Actions issuer `https://token.actions.githubusercontent.com`
- `UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY`: exact repository workflow identity ending in `.github/workflows/edge-supply-chain.yml@refs/heads/...` or `@refs/tags/...`
- `UPGRADE_E2E_PROCESS_CONTRACT_VERSION`: `sha256:<contract.json SHA-256>`
- `UPGRADE_E2E_LICENSE_PARENT_RECEIPT_SCHEMA`: exact request schema from `contract.json`
- `UPGRADE_E2E_NODE_ID`: canonical lowercase UUID used by all three scenarios
- `UPGRADE_E2E_INITIAL_VERSION`, `UPGRADE_E2E_FORWARD_VERSION`: distinct release versions
- `UPGRADE_E2E_BEARER_TOKEN`: 16..8192 bytes from the driver's restricted character set

`UPGRADE_E2E_EDGE_CONFIG_JSON` is a canonical version-2 template. It must set `identity_dir` to `/etc/cdnca-edge-agent/identity` and must not contain top-level `node_id` or `artifact_encryption_key_id`, nor `gateway.client_certificate_file` or `gateway.client_private_key_file`. The driver generates the task identity only after immutable preflight, task reservation, snapshotting, and runtime authorization.

The immutable Control SQL is a test fixture template, not enrollment. Each of its four `psql` literal placeholders occurs exactly once. After generating the Edge identity, the driver binds only the validated certificate serial, leaf DER SHA-256, X25519 artifact key ID, and X25519 public key into that snapshot, then reads the exact production Control authorization facts back before starting Gateway or Edge. No private key enters fixture substitution.

Required frozen file/SHA-256 pairs:

- `UPGRADE_E2E_B_MANIFEST`, `UPGRADE_E2E_B_MANIFEST_SHA256`
- `UPGRADE_E2E_C_MANIFEST`, `UPGRADE_E2E_C_MANIFEST_SHA256`
- `UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST`, `UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST_SHA256`
- `UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST`, `UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST_SHA256`
- `UPGRADE_E2E_NATS_RESOURCES_JSON`, `UPGRADE_E2E_NATS_RESOURCES_SHA256`
- `UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL`, `UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SHA256`
- `UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL`, `UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SHA256`
- `UPGRADE_E2E_EDGE_CONFIG_JSON`, `UPGRADE_E2E_EDGE_CONFIG_SHA256`
- `UPGRADE_E2E_SUCCESS_ROLLOUT_JSON`, `UPGRADE_E2E_SUCCESS_ROLLOUT_SHA256`
- `UPGRADE_E2E_AUTOMATIC_ROLLBACK_JSON`, `UPGRADE_E2E_AUTOMATIC_ROLLBACK_SHA256`
- `UPGRADE_E2E_OPERATOR_ROLLBACK_JSON`, `UPGRADE_E2E_OPERATOR_ROLLBACK_SHA256`
- `ENTITLEMENT_TRUSTED_KEYS_FILE`, `ENTITLEMENT_TRUSTED_KEYS_SHA256`
- `CONTROL_INSTALLATION_PRIVATE_KEY_FILE`, `CONTROL_INSTALLATION_PRIVATE_KEY_SHA256`
- `CONTROL_ACTIVATION_CREDENTIAL_FILE`, `CONTROL_ACTIVATION_CREDENTIAL_SHA256`
- `CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE`, `CONTROL_UPGRADE_COMMAND_GRANT_TRUST_SHA256`
- `CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE`, `CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_SHA256`
- `CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE`, `CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_SHA256`
- `UPGRADE_E2E_INITIAL_ARTIFACT`, `UPGRADE_E2E_INITIAL_ARTIFACT_SHA256`
- `UPGRADE_E2E_INITIAL_SBOM`, `UPGRADE_E2E_INITIAL_SBOM_SHA256`
- `UPGRADE_E2E_INITIAL_MANIFEST`, `UPGRADE_E2E_INITIAL_MANIFEST_SHA256`
- `UPGRADE_E2E_INITIAL_SIGNATURE`, `UPGRADE_E2E_INITIAL_SIGNATURE_SHA256`
- `UPGRADE_E2E_INITIAL_PUBLIC_KEY`, `UPGRADE_E2E_INITIAL_PUBLIC_KEY_SHA256`
- `UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY`, `UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY_SHA256`
- `UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY`, `UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY_SHA256`
- `UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST`, `UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST_SHA256`
- `UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST`, `UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST_SHA256`
- `UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE`, `UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE_SHA256`
- `UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE`, `UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE_SHA256`
- `UPGRADE_E2E_SYSTEMD_SPDX`, `UPGRADE_E2E_SYSTEMD_SPDX_SHA256`

The systemd evidence files are public supply-chain evidence and are scanned normally; they are not secret-source exclusions. Before task reservation or work-directory creation, the driver uses no-follow reads to verify every supplied digest and proves that the final OCI index contains exactly the supplied `linux/amd64` and `linux/arm64` native subjects. It separately reads each exact native subject with `imagetools inspect --raw` and requires each raw manifest SHA-256 to equal that subject digest. Both native manifests must have a supported OCI/Docker schema and media type, a valid config descriptor and a nonempty valid layer set. The final index must bind each raw manifest one-to-one by digest, media type, exact byte size, Linux OS and amd64/arm64 architecture. The driver also verifies the keyless signature against the exact issuer and workflow identity, and binds the two real BuildKit SLSA predicates plus the complete SPDX package/file/relationship document to that final digest. After reservation, the same files are copied into the immutable input snapshot with before/copy/after digest checks and the native subject digests are checked again.

The Edge config supplies the paths for its artifact, control-execution and edge-execution trust files. Their required independent digest inputs are:

- `UPGRADE_E2E_EDGE_ARTIFACT_TRUST_SHA256`
- `UPGRADE_E2E_EDGE_CONTROL_EXECUTION_TRUST_SHA256`
- `UPGRADE_E2E_EDGE_EXECUTION_TRUST_SHA256`

Each release bundle has a path, digest and exact byte size:

- `UPGRADE_E2E_FORWARD_BUNDLE`, `UPGRADE_E2E_FORWARD_BUNDLE_SHA256`, `UPGRADE_E2E_FORWARD_BUNDLE_SIZE`
- `UPGRADE_E2E_ROLLBACK_BUNDLE`, `UPGRADE_E2E_ROLLBACK_BUNDLE_SHA256`, `UPGRADE_E2E_ROLLBACK_BUNDLE_SIZE`

The migration authority heads are License `046` and Control `186`. The immutable snapshot contains the complete License and Control migration trees and the runtime verifies those database heads. The License authority manifest must include the current `046` up/down/integration-test or contract-test entries. The Control manifest remains the exact upgrade-domain scope `096..102` (21 entries), not a claim that it is the full historical migration list; missing, malformed, or drifting scope entries are `UNKNOWN`, never a release pass. The NATS JSON permits exactly two placeholders: `${NODE_ID}` remains the canonical UUID in the command filter subject, while `${NODE_ID_UNDERSCORE}` is used only in JetStream resource names. No intermediate SHA is embedded in the driver.

## Production boundary

- PostgreSQL is pinned to 17.9 and listens only on its task-owned Unix socket, with `max_connections=20` and `max_locks_per_transaction=512`.
- Redis and NATS are task-owned. NATS is pinned to 2.11.x and uses file storage.
- Streams `AGENT_COMMANDS`, `AGENT_DEPLOYMENT_STATUS`, and `AGENT_HEARTBEATS` and all required durable consumers are precreated from the frozen NATS manifest. Production processes are verify-only.
- After creation and again after every scenario, the driver reads every behavior-changing stream and consumer field back from the server, compares the canonical projections, and enumerates the exact three-stream/four-consumer set through the JetStream API. Extra, missing, mutated or mismatched resources fail the run.
- Stream subjects are an exact allow-set, not broad `>` coverage. Generic deployment status keeps the legacy `cdnca.agent.deployment-status.*` subject readable and publishes new events to the immutable `cdnca.agent.deployment-status.generic-v2.*.*` namespace; `control_api_edge_status` uses those two ordered filters and binds the new subject's node/event UUIDs to the payload. Terminal command receipts, confirmations, and their recovery index use three separate exact namespaces so every wildcard stays terminal and Gateway startup fails when durable receipt coverage is missing. The fixed literals also prevent the generic consumer from matching ACME, cache, upgrade, drain, or Gateway port-transition status subjects. The separate `control_api_upgrade_status` consumer uses the two exact filters `cdnca.agent.deployment-status.upgrade.*` and `cdnca.agent.deployment-status.upgrade-v2.*`; the latter binds the canonical Gateway publication to `StatusID`.
- Before enabling `upgrade-v2`, operators must drain Gateways that only publish the legacy per-node status subject. Historical or uncontrolled old binaries can physically overlap legacy and v2 messages, so the rollout relies on the durable `StatusID` transaction fence to apply an exact replay once and never regress state; it does not claim arbitrary old-version mixed writes are broker-deduplicated.
- Upgrade command and status consumers use explicit ACK and `MaxDeliver=-1`; PostgreSQL remains authoritative for HTTP/install attempt limits.
- License is a real service behind a task-owned HTTPS termination proxy; Control never uses a plaintext License URL.
- ControlInternal and Gateway use TLS 1.3 only. The task CA signs separate License, Control and Gateway `serverAuth` leaf certificates with exact DNS SANs. Gateway's separate `clientAuth` Control certificate contains exactly `spiffe://cdn-platform/gateway/control`; the Agent `clientAuth` certificate contains exactly `spiffe://cdn-platform/node/<node_uuid>`. Every task private key is mode `0600` and certificate generation output is never logged.
- Edge version 2 receives one atomically published, task-owned identity directory at `/etc/cdnca-edge-agent/identity`. The directory is mode `0700` and contains exactly owner-only `identity.json`, `client.pem`, `client-key.pem`, and `artifact-x25519-key.bin`. Metadata uses the production identity schema and fixed filenames; the certificate bundle, SPIFFE node, Ed25519 key, single `clientAuth` usage, SAN allow-set, current CA chain, raw 32-byte X25519 key and derived `x25519:<sha256>` key ID are validated before the Edge container starts. Every directory ancestor and identity member is rejected if it is a symlink, and every file and directory is fsynced before atomic publication.
- Edge and `cdnca-edge-agent-helper` run in the digest-pinned Linux systemd image. For the Agent service, helper service and helper socket separately, the driver requires the exact `/usr/lib/systemd/system` `FragmentPath` and binds the loaded unit bytes and SHA-256 to both the image-supplied copy and frozen packaging snapshot. The Agent service and helper socket must each be independently enabled and active; the socket-activated helper service must independently remain disabled and inactive before scenarios. The driver also requires `/run/cdnca-edge-agent/helper.sock`; private keys are owner-only.
- Edge starts from the signed initial artifact/SBOM/manifest/signature/public-key package through the image-supplied production installer. The helper binary and image-supplied units are installed in their production paths, `key-init` runs before the helper socket and Agent are enabled, and the initial `current` symlink must resolve to `UPGRADE_E2E_INITIAL_VERSION`.
- Before creating its work directory or mutating Docker, the driver atomically reserves the suffix/task identity in one canonical per-user system lock namespace rooted at the physical system temporary directory, independent of caller `TMPDIR`. The lock directory and owner record bind the OS UID, driver PID/start identity, task ID and script path; every release revalidates owner, mode and digest. A second invocation with the same suffix fails before any snapshot or other mutation.
- After reservation, the driver creates an immutable input snapshot of the complete License, Control, Gateway and Edge Go modules, local replacement modules, migrations, frozen manifests and NATS configuration. Safe no-follow copies, canonical repo-relative paths, complete inventories and before/copy/after digests reject symlink escapes and concurrent drift. Builds, migrations and resource configuration read only the snapshot, while a final full inventory comparison proves every live input remains byte-for-byte and set-for-set unchanged. Repository snapshots are scanned normally; only the four exact immutable installation/activation/control-signing/edge-signing secret snapshots are secret-source exclusions.
- The C manifest includes the versioned Edge release-build contract and inner recipe. The driver derives an exact build-source manifest from the existing immutable snapshot, reads the digest-pinned Go toolchain and builder identity from that contract, and invokes the same recipe used by the standalone release wrapper. Version, architecture, source provenance and fixed epoch come from the signed forward-bundle manifest; the build ID is deterministically derived from the version and source-manifest digest. This adds no external preflight key. The resulting ELF must match the forward bundle executable byte-for-byte by SHA-256 and size before any scenario starts.
- Before mutating Docker, the driver snapshots every container and network ID carrying the exact task label. Cleanup may remove only an ID returned by this invocation or an exact `post-minus-pre` labeled ID; it never adopts a same-label resource present in the snapshot. Every created container also has one verified role label used for dependency ordering, and any Docker inspection, listing, role, or final-count failure after creation is a cleanup failure. The reservation is released only after successful cleanup; an abnormal run retains it with the work directory for diagnosis.
- Container roles are taken only from the observed exact role label and are compared with the role captured at registration on every later inspection. Missing resources are distinguished from failed Docker probes, and every Docker info/inspect/list/probe is bounded by the driver timeout. Inspect, port, role, quiesce, stop and remove failures fail closed rather than being silently skipped.
- Docker-assigned host ports are recorded immediately after successful NATS and Redis registration. Before deleting anything, cleanup recovers every published port from every still-existing verified invocation-returned or `post-minus-pre` container, including containers left by a nonzero `docker run` or registration failure, and checks every recorded port for zero listeners.

The fixture runs through dedicated `NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION` login roles with grants limited to its setup tables. The five Control identity-chain tables needed only for authority setup receive a separate `INSERT`-only grant. After every setup readback and before the production processes start, the driver revokes only the direct table, sequence, schema, and database connection grants issued by this driver, then changes both fixture roles to `NOLOGIN`. This direct-grant revocation does not remove privileges inherited through `PUBLIC`, and the driver does not alter `PUBLIC` or production roles. `NOLOGIN` prevents direct login; it is not proof that the roles have no effective privileges. The fixture may create customers, licenses, installations, signing lineage, release artifacts, release-channel history, entitlement trust, node identity, node capability and online presence. It must not fabricate rollout commands, outbox messages, Agent status, acknowledgement rows, parent receipts, or terminal rollout state; the driver checks both runtime fact sets are empty immediately after fixture loading.

Scenario mutations use only the public Control HTTP create/start/rollback routes. PostgreSQL is observation-only after setup: both Control and License query helpers force `default_transaction_read_only=on`. The bearer token is held in a mode-`0600` temporary curl config and removed before the secret scan.

## Assertions

One invocation must prove all of the following against real processes:

1. Successful rollout: `accepted -> claimed -> installing -> healthy`, then `completed/upgraded`.
2. Automatic rollback: `accepted -> claimed -> installing -> rolling_back -> rolled_back`, then `completed/rolled_back`.
3. Explicit operator rollback is exactly `accepted -> claimed -> installing -> rolled_back` and reaches the signed rollback and terminal receipt contract.
4. With the helper state on a dedicated bounded `tmpfs`, a real write returns `ENOSPC` (the driver checks the write error, not only free-space telemetry). During the fault, no `installing` status, helper journal, current release, active state or `last-upgrade` LKG snapshot may change. After clearing the filler, a `SIGKILL` of the Agent main process must produce a different PID and `/proc` start identity, systemd must bring it back to `active`, and the same rollout must continue to its normal terminal result.
5. Agent restarts after accepted, claimed, installing, broker ACK and database ACK boundaries resume the same command and helper transaction.
6. Replay leaves byte-identical Control and License fact sets plus the Agent upgrade transaction/wire state and helper transaction/journal inventories.
7. Every command's persisted PubAck stream/sequence retrieves the exact JetStream subject, payload digest, message key, expected stream and message ID. Every status receipt exposes Control's persisted delivery stream, consumer and stream sequence; the driver retrieves that exact JetStream message and checks the v2 subject, canonical payload digest, message ID, message key, expected stream, last-subject sequence and per-command status ordering. Every persisted Edge acknowledgement file binds that same status identity, digest, PubAck stream/sequence and the exact canonical Ack bytes retained by Gateway's confirmation proof. The driver requires byte-identical Edge Ack files across an Agent restart, then verifies Gateway's final empty pending ledger and its exact CAS headers.
8. Before the driver accepts an observed `installing` checkpoint, the exact helper transaction directory and journal must exist and bind the same installer transaction. The production Agent first asks the helper to durably move that journal from `prepared` to `installing`, verifies the returned transaction identity, and only then persists and publishes the Agent `installing` status. A missing, unreadable, mismatched, or non-durable helper response fails closed without publishing `installing`.
9. License parent receipt progression is `fetched -> verified -> applied`; a later rollback extends that exact chain to `rolled_back`. Every receipt binds installation, grant, plan, command, artifact and observed status identity.
10. `unresolved`, `uncertain`, `failed`, and `rollback_failed` never falsely emit an `applied` or `rolled_back` parent receipt.
11. A recursive binary-safe scan of every task-owned file finds no configured runtime secret, generated private-key content, activation credential, grant secret, bearer token, API pepper or decrypted signing material. Pattern inputs are the exact per-service launcher value/file lists, including NATS URLs/credential files and TLS/private-key inputs, the Edge identity client and X25519 private keys, plus the generated-value bundle. Every nonempty value, including short values, is checked as raw bytes, canonical padded/unpadded base64 and base64url, lower/upper hex, and safely decoded forms without printing secret material. Edge, Gateway, Control, License, TLS proxy, NATS, Redis and PostgreSQL writers are quiesced before enumeration. The scan requires each file to remain readable, treats scan I/O errors as failures, and excludes only the four exact immutable runtime secret snapshots, seven authoritative private-key source files, exact pattern/report/list files, and five immutable binaries; copied/log/runtime occurrences and every repository snapshot remain scannable.

## Cleanup

Cleanup implements the actual reverse dependency order rather than merely documenting it: Edge Agent, helper service/socket and Edge container; Gateway; Control; TLS proxy; License; NATS; Redis; PostgreSQL; network; then task temporary files, including the task-owned Edge identity directory. Container role and exact task label are reverified before removal. Every independent role, host PID, process group, listener, socket and temporary-path attempt is best-effort even when another cleanup operation fails. A private process-group marker is reserved before spawn; the candidate PID/PGID is recorded immediately after spawn, and the marker remains as a fallback if registration is interrupted. Full registration adds the exact executable, work-directory marker and start identity, and failure terminates only the revalidated candidate group. Cleanup also discovers any marker-backed group that never reached the registration arrays, enumerates surviving process-group members even after the leader exits, and double-checks every member's marker, executable and start identity before signaling the group, so a reused unrelated PID or PGID is never signaled. Work directories are deleted only after process, socket, secret-scan and resource evidence is recorded inside the reservation. All resource, port, process-group, orphan and work-directory probes then run again; only a complete absent result releases the reservation. Any delete or post-delete probe failure retains the reservation and evidence for diagnosis. Non-Docker stop, listener, process, orphan, socket and temporary-path probes are status-checked and fail closed.

The final cleanup record must show containers, networks, listeners, processes, Unix sockets, temporary paths and `PPID=1` task orphans all equal to zero. Failure to inspect cleanup is a failure, not a pass.

## Batched validation

The owner completes a repair batch before running gates. During implementation, only narrow static searches or syntax-independent checks may confirm that a RED assertion is present; the full validation set runs once after all repairs: `bash -n`, ShellCheck, and exactly one `UPGRADE_E2E_STATIC_ONLY=1` invocation. A static PASS is not a runtime pass. No Docker, database, broker, browser, or global suite is started by this driver until the frozen runtime release permits it.

## Runtime execution

The driver contains no runtime stub or embedded `not-frozen` stop. A real run begins only after the external preflight validates the final `046/186` migration authorities, process-contract digest/schema, exact native systemd subjects, keyless signature, SLSA/SPDX predicates, NATS resources, fixtures, runtime trust/key files, three rollout bodies, signed initial package and both size-bound release bundles. A successful runtime run ends with `UPGRADE_PROCESS_E2E PASS license_head=046 control_head=186`; the static PASS does not make that runtime claim. Focused Agent tests prove the helper-journal-before-`installing` ordering and fail-closed recovery contract, but this driver does not claim a real registry, cosign, Docker, PostgreSQL or NATS pass until the coordinated runtime wave runs. Static-only validation remains the required no-resource gate while that release is not authorized.
