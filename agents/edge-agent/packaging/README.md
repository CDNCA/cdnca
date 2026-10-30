# edge-agent systemd package baseline

This directory contains the local-artifact installer and signed apt packaging
used on Debian 12 and Ubuntu 24.04. The installer itself never downloads a
release. Every install or upgrade ultimately consumes five local regular files:

- `edge-agent`: the Linux `amd64` or `arm64` executable;
- `edge-agent.spdx.json`: the release SBOM;
- `manifest`: the exact 16-line canonical release manifest;
- `manifest.sig`: a raw Ed25519 signature over the manifest bytes;
- a PEM Ed25519 release public key, verified out of band.

The first install pins the public key at
`/etc/cdnca-edge-agent/package-signing.pem`. Later operations reject a
different key. Key rotation therefore requires a separately reviewed trust
procedure rather than an upgrade flag.

## Canonical manifest v2

The signed manifest is UTF-8/ASCII compatible, newline-terminated, and has
exactly this order:

```text
manifest_version=2
release_sequence=42
version=1.2.3
artifact_path=edge-agent
artifact_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
artifact_size=12345678
sbom_path=edge-agent.spdx.json
sbom_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
sbom_size=45678
os=linux
arch=amd64
source_repository=https://example.invalid/cdnca.git
source_commit=0123456789abcdef0123456789abcdef01234567
build_time=2026-07-22T00:00:00Z
minimum_control_protocol=1.0
minimum_agent_protocol=1.0
```

Ed25519 signs the complete manifest bytes. The parser accepts only manifest v2
and this field order, so unknown fields, duplicate keys, missing fields, CRLF,
and non-canonical encodings fail closed. `release_sequence` is a positive,
strictly monotonic publication sequence. The highest accepted manifest is kept
at `/var/lib/cdnca-edge-agent-packaging/accepted-manifest`; an equal sequence
is allowed only for byte-identical idempotent reruns, and a lower sequence is
rejected even after explicit binary rollback or default uninstall.

Signature, hashes, sizes, provenance, build time, protocol minima, 64-bit ELF
type/machine, minimal SPDX 2.3 JSON fields, platform, architecture, input type,
link count, permissions, and size limits are checked before the installer
creates a lock or changes the destination filesystem. The installer records all
five input digests, acquires the package lock, copies those exact bytes into a
root-owned read-only package staging directory, compares every digest, and repeats
the complete signature, manifest, ELF, SBOM, replay, pinned-key, compatibility,
and version checks there. All subsequent probes, release copies, and commits use
only that staging directory. A separate version probe runs as the fixed
unprivileged identity `65534:65534`; upgrades also probe configuration as the
existing numeric `cdnca-edge` UID/GID. After copying, the installed release is
probed again as `cdnca-edge`. Every probe uses `setpriv` with empty supplementary
groups, an empty environment, `no_new_privs`, and the package-lock descriptor
closed; the root maintenance process never executes a release binary or exposes
its lock to one. The current control and Agent protocol
compatibility baseline is `1.0`; a release requiring a later minimum is rejected.

Target nodes require OpenSSL, GNU coreutils, `jq`, `perl`, `setpriv`, systemd
sysusers, and systemd tmpfiles. `jq` parses the signed SPDX document; `perl`
provides the small `renameat2(RENAME_EXCHANGE)` syscall bridge used for atomic
state restoration on the supported `amd64` and `arm64` Linux targets.

Before any package lock or destination mutation, installation and upgrade also
verify the exact supported host envelope: Ubuntu 24.04 (systemd 255+), Ubuntu
22.04 (249+), Ubuntu 20.04 (245+), Debian 10 (241+), 11 (247+), 12 (252+) or
13 (257+), Rocky/AlmaLinux/RHEL 8 (239+), 9 (252+) or 10 (257+), see
docs/install/os-support-matrix.md; Linux kernel 5.3 or newer, or an older kernel
that passes a live pidfd_open probe; cgroup v2 or v1 (legacy); and every
command used by the transaction, signature, identity and
systemd paths. Host failures use stable `HOST_*` reason codes. A signed release
whose minimum control or Agent protocol is newer than the installed baseline
uses `COMPAT_CONTROL_PROTOCOL_TOO_OLD` or `COMPAT_AGENT_PROTOCOL_TOO_OLD`;
release-sequence downgrade and same-sequence/different-content conflicts use
`COMPAT_RELEASE_SEQUENCE_REPLAY` and `COMPAT_RELEASE_SEQUENCE_CONFLICT`.
Free-form detail may change, but automation must branch only on these codes.

## Layout

```text
/usr/lib/cdnca-edge-agent/versions/<version>/
/usr/lib/cdnca-edge-agent/current -> versions/<version>
/usr/libexec/cdnca-edge-agent/
/etc/cdnca-edge-agent/{agent.env,config.json,identity,tls,trust}
/var/lib/cdnca-edge-agent/  # root-owned empty bind mountpoint
/var/lib/cdnca-edge/
/var/lib/cdnca-edge-agent-backups/active-state/  # canonical live payload
/var/lib/cdnca-edge-agent-backups/<timestamp>-<transaction>-<purpose>/
/var/log/cdnca-edge-agent/
```

`cdnca-edge` is a dedicated `nologin` system user. Identity, certificate, and
state directories are owner-only. Release directories and the pinned release
key are root-owned. `agent.env` contains only the configuration path; tokens,
private keys, and other credentials belong in owner-only files.

## Root runtime identity (native nodes)

Native nodes run the Agent as root because it manages the native OpenResty
worker (`cdnca-runtime`). The first install selects this with
`install.sh --runtime-identity root`; the default stays `cdnca-edge`. The
choice is recorded in the root-owned `0600` marker
`/var/lib/cdnca-edge-agent-packaging/runtime-identity` (content `root`; an
absent marker means `cdnca-edge`). It is authoritative once `current` exists:
upgrade, rollback, preflight and recovery inherit it, an explicit request must
match, `upgrade.sh` rejects the option, and an unreadable, unsafe or unknown
marker fails closed before any write. Purge removes it.

Root mode differs from the default only where the identity matters:

- The installed unit is `systemd/cdnca-edge-agent-root.service` (as
  `/usr/lib/systemd/system/cdnca-edge-agent.service`): `User=root`, same
  `ExecStartPre=preflight.sh`, `ExecStart=/usr/lib/cdnca-edge-agent/current/edge-agent`
  and fixed state bind; no capability bound or syscall filter, because the
  Agent controls systemd and OpenResty.
- Tmpfiles is `tmpfiles/cdnca-edge-agent-root.conf`: only the root-owned
  backup root. It never declares `/etc/cdnca-edge-agent/identity` (enrollment
  creates it and refuses an existing one) or `/var/lib/cdnca-edge` (the Agent
  owns its `root:cdnca-runtime 0710` worker-access mode, which a boot-time
  tmpfiles run must not reset).
- State, config and `/etc/cdnca-edge-agent` are `root:root 0700`; the
  configuration must be root-owned `0400`/`0600`.
- The version probe still runs as `65534:65534`/`cdnca-edge`. The
  configuration probe runs as root (empty groups, `no_new_privs`, empty
  environment): the service executes the same signature-verified release as
  root, so the probe grants nothing new.
- State trees may contain entries owned by other accounts (nginx chowns its
  temporary paths to the worker). The tree root must be `root:root 0700`;
  symlinks, special files, hard links, group/world-writable and
  setuid/setgid/sticky entries and filesystem crossings are still rejected.
- The `cdnca-edge` account is still created: it owns the helper socket.

## Commands

```sh
sudo agents/edge-agent/packaging/scripts/install.sh \
  --artifact /srv/releases/edge-agent \
  --sbom /srv/releases/edge-agent.spdx.json \
  --manifest /srv/releases/manifest \
  --signature /srv/releases/manifest.sig \
  --public-key /srv/release-keys/edge-agent-ed25519.pem

sudo /usr/libexec/cdnca-edge-agent/upgrade.sh \
  --artifact /srv/releases/edge-agent \
  --sbom /srv/releases/edge-agent.spdx.json \
  --manifest /srv/releases/manifest \
  --signature /srv/releases/manifest.sig \
  --public-key /srv/release-keys/edge-agent-ed25519.pem

sudo /usr/libexec/cdnca-edge-agent/rollback.sh --version 1.2.2
sudo /usr/libexec/cdnca-edge-agent/uninstall.sh
```

## Signed apt repository

`deb/build-repository.sh` converts release-build outputs into native
`cdnca-edge-agent_<version>_<arch>.deb` packages and one apt repository. Its
JSON input is `cdnca.edge.apt-repository/v1` and fixes the suite, component,
origin, label, publication/expiry epochs, release sequence, architecture and
absolute path for every release output. The publisher emits `Packages`,
`Packages.gz`, SHA-256 by-hash indexes, `Release`, `InRelease`, `Release.gpg`,
the public archive keyring and `cdnca.edge.apt-repository-provenance/v1`.
Repository directories are public `0755` and immutable files are `0444` so the
apt sandbox user can acquire them.

Publication is all-or-nothing per semantic version: every version must contain
exactly one `amd64` package and one `arm64` package under the same unique
release sequence. A missing architecture, a split sequence, or reuse of one
sequence for different versions fails before repository metadata is signed.

There are two independent signing domains. OpenPGP signs apt repository
metadata and binds downloaded `.deb` bytes to the repository. The release
Ed25519 key signs each canonical manifest inside the package and remains the
runtime installation authority. Passing one signature never bypasses the
other. Private keys stay outside the repository; only the apt public keyring
and release public key are published.

Configure a node with a keyring obtained through the release trust channel:

```sh
sudo install -o root -g root -m 0444 cdnca-archive-keyring.gpg \
  /usr/share/keyrings/cdnca-archive-keyring.gpg
printf '%s\n' \
  'deb [signed-by=/usr/share/keyrings/cdnca-archive-keyring.gpg] https://packages.example.invalid/edge stable main' |
  sudo tee /etc/apt/sources.list.d/cdnca-edge.list >/dev/null
sudo apt-get update
apt-cache policy cdnca-edge-agent
sudo apt-get install cdnca-edge-agent=1.2.3-1
```

The package `postinst` invokes the same signed installer or upgrader described
above. Root automation may bound health observation with
`CDNCA_EDGE_DEB_HEALTH_TIMEOUT` and `CDNCA_EDGE_DEB_HEALTH_STABLE`; both must
be unsigned decimal seconds and timeout must be positive. A failed health gate
returns a failing package configuration while the packaging transaction
restores the previous healthy `current`, state and service. Keep the previous
package version in the repository and reinstall it with
`apt-get install --allow-downgrades cdnca-edge-agent=<previous-debian-version>`
to restore dpkg coherence. Do not delete the transaction journal or rewrite
`current` manually.

Upgrade stops the service, backs up mutable Agent state, validates the new
binary against the installed configuration, atomically switches `current`,
restarts, and waits for stable systemd health. Package metadata is written to a
same-directory temporary file, synced, atomically renamed, and parent-synced,
so a killed copy cannot truncate an installed maintenance entrypoint. A failure restores the previous
link, state, complete installed package metadata set, and previous recovery
pointer before reloading systemd and restarting the previous version. Install,
upgrade, and explicit rollback share the durable transaction journal, so the
same recovery runs before the next package operation if the maintainer process
is killed. Before metadata changes, the journal snapshots the toolset that
created it. Every installed maintenance entrypoint checks for that root-owned
snapshot before sourcing the mutable installed library. It runs the snapshot in
recovery-only mode, then re-executes the original entrypoint after the coherent
old metadata set is restored; install and upgrade recovery-only runs still pass
the complete signed-input checks and unprivileged probes before taking the lock.
The lock itself uses util-linux `flock`, so SIGKILL cannot leave a
false active owner; `transaction.lock` may remain as an idle root-owned lock
file. A pre-publish `.transaction.<pid>` and metadata temporary files are tied
to that owner PID and removed only after strict path, regular-file, root-owner,
single-link, and non-group/world-writable checks by the next lock holder. Final
metadata still requires its declared fixed mode. `DESTDIR` must be clean and,
except for `/`, must not end in a slash. Explicit rollback is limited to the direct previous successful upgrade,
because that is the state backup whose compatibility can be established.

State backups, restore sources, and restore staging reject symlinks, special
files, hard links, group/world-writable entries, ownership outside
`cdnca-edge`, and any entry on a different filesystem from its tree root. The canonical live payload is
`/var/lib/cdnca-edge-agent-backups/active-state`; the edge service exposes it
at the unchanged `/var/lib/cdnca-edge-agent` home through a fixed systemd bind
mount. Restore copies and validates a state tree inside a sibling root-owned
`0700` staging wrapper, records that exact wrapper in the durable journal,
syncs it, then atomically exchanges it with `active-state` on the one common
mount. The helper never exchanges through the bind target.
The next lock holder recovers journal-bound staging and removes only validated,
numeric task-owned orphan wrappers before starting its own operation.
Content left by a failed release is isolated as a displaced tree rather than
trusted as a restore prerequisite. Release directories,
`current`, the recovery pointer, and `accepted-manifest` are synced before and
after their atomic rename commits.

The restricted updater accepts only the migrated layout. A fixed root package
installer migrates an existing legacy state directory while the Agent is
stopped. It persists `prepared`, `unit_installed`, `state_move_intent`, and
`activated` phases with the legacy device, inode, tree, and old/new unit facts.
It installs the bind unit before the atomic move, starts the unchanged old
release through that unit, and commits only after stable health. Recovery
requires exactly one journal-matching authoritative tree; double presence,
double absence, or fact mismatch fails closed. Revert restores the old unit and
atomically moves the same payload back to the legacy path.

Systemd tmpfiles declares only the common backup root; it never creates the
bind target, `active-state`, or their child directories. The root installer
owns those paths so rerunning `systemd-tmpfiles --create` cannot populate an
otherwise empty mountpoint or mask canonical state. The helper service refuses
socket activation unless `active-state` exists and the fixed migration journal
is absent. A legacy or interrupted layout therefore cannot create helper key or
journal state and must first be recovered by the root package installer.

Default uninstall retains configuration, identity, state, backups, logs, and
the accepted-manifest replay boundary. A failed service stop or disable aborts
before package files or metadata are removed.
Purge requires `--purge` plus an interactive phrase, or this exact automation
guard:

```sh
sudo /usr/libexec/cdnca-edge-agent/uninstall.sh \
  --purge --non-interactive \
  --confirm-purge DELETE-EDGE-IDENTITY-AND-STATE
```

Run `scripts/edge-agent-package-smoke.sh` for shellcheck and isolated Debian 12
and Ubuntu 24.04 smoke tests. The tests compile an ELF fixture that asserts its
real/effective UID/GID, empty supplementary groups, and `no_new_privs`. They use
`DESTDIR` and a task-owned service driver, so they never contact the host
systemd instance.

## Reproducible release build

`packaging/build/contract.json` is the versioned authority for the exact Go
toolchain, digest-pinned builder image, supported Linux architectures, source
roots, build flags and output set. `packaging/build/recipe.sh` is the inner
builder: it never starts Docker, accepts only an exact source inventory and C
manifest, rejects symlinks or source drift, embeds a canonical SemVer and build
ID, fixes `SOURCE_DATE_EPOCH`, and atomically publishes the ELF, SPDX 2.3 SBOM
and provenance only after every validation succeeds.

The public entrypoint is `scripts/edge-agent-release-build.sh`. It reads the
builder image from the contract, generates exact source and C manifests, and
runs the same inner recipe in the pinned Linux builder. The builder container
runs on its available architecture and Go cross-compiles the requested
`amd64` or `arm64` ELF; CI registers arm64 emulation for the pinned builder and
builds both outputs. A failed validation or build leaves the requested output
directory absent. The upgrade process E2E
also invokes this same recipe from its immutable C snapshot; the externally
signed forward bundle remains bound to the recipe-built executable by exact
SHA-256 and size.
