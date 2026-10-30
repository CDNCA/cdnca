# Edge Agent Debian packaging source gate

This gate validates the source-only OPS-11 Debian packaging closure without
Docker, apt networking, systemd, or host package installation. It builds
byte-identical amd64 and arm64 packages twice, inspects their maintainer
scripts and payload, publishes a locally signed apt repository, and verifies
the repository against an external pinned trust policy.

Run exactly once after the packaging inputs are frozen:

```sh
bash tests/edge-agent-deb-packaging-static/run.sh
```

Debian 12 and Ubuntu 24.04 fresh install, reboot, upgrade, injected preflight
failure, rollback, and purge remain Round 7 infrastructure scenarios.
