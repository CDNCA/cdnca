# Edge runtime security release static contract

Run the no-resource contract with:

```sh
EDGE_RUNTIME_SECURITY_RELEASE_STATIC_ONLY=1 ./tests/edge-runtime-security-release-e2e/run.sh
```

The check binds the current `runtime.env` source and image pins to the checked-in
runtime lock, verifies the upstream advisory snapshot, and requires the current
unsafe baseline to remain fail closed. Focused Go tests cover signed hotfix
manifests, supply-chain evidence, protocol regression evidence, compatibility,
one-to-two-node canaries, expansion, pause, and rollback reason codes.

This is not a production release pass. The coordinated runtime wave must use a
fixed OpenResty/Nginx source, build and sign the real image, generate and bind
its SPDX SBOM and provenance, scan it against a fresh vulnerability database,
run the protocol regressions, and exercise canary pause and rollback on isolated
nodes before the runtime lock can become release eligible.
