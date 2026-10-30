# Final acceptance wave

The one-shot macro acceptance command is:

```sh
bash tests/final-acceptance/run.sh
```

It attempts only the three unfinished runtime stages, at most once and in this
fixed order:

1. `SITE-04`: corrected OpenResty origin-route smoke.
2. `L4-01`: real Control commands through Gateway to Agent, including the
   late old rollout, exact status PubAck and final Control projection.
3. `OPS-08`: immutable upgrade process E2E.

`CACHE-03`, `L4-02`, `OBS-02` and `OBS-11` are already frozen and must not be
queued by this wrapper. `UX-01` belongs to the separate final browser wave and
is not run or statically substituted here.

All command, file, Docker, frozen source and environment presence checks finish
before the wrapper creates its temporary directory or invokes a stage. The
unified input preflight is a fail-closed barrier: any missing or unsafe input
blocks the wrapper before SITE-04, L4-01 or OPS-08 starts. In particular, the
OPS-08 `cosign` and 119-input contract, the L4-01 runner image and the UX-01
browser identities must all be frozen before this one-shot runtime wave. The
delegated drivers retain their deeper immutable-input, digest, credential and
resource preflights. The runtime wrapper does not rerun delegated static
contracts; those inputs are frozen before this wave and are checked only by
their real consumers.

Every stage emits exactly one terminal wrapper result:

- `FINAL_ACCEPTANCE stage=<id> PASS`
- `FINAL_ACCEPTANCE stage=<id> UNKNOWN reason=<stable reason>`

Any driver non-zero exit is reported as `UNKNOWN`; the wrapper never promotes a
partial run to success. The final line is either `FINAL_ACCEPTANCE ... PASS` or
`FINAL_ACCEPTANCE ... UNKNOWN`, with passed and unknown counts. A stage is not
retried within the wave. After any stage passes, do not rerun the wrapper as a
new wave merely to satisfy a later unavailable stage; supply the missing inputs
through the root-coordinated acceptance wave.

L4-01 invokes `tests/l401-process-e2e/run.sh` exactly once. That task-owned
driver creates its isolated PostgreSQL, NATS, Redis and Linux/OpenResty runner,
uses production Control publication/outbox paths to queue both commands, and
starts the Agent only inside the existing process E2E. It owns all generated
credentials and runtime inputs; the final wrapper no longer accepts external
`L401_*` authority. On every exit the delegated driver removes only its unique
labelled resources and emits
`cleanup=PASS containers=0 networks=0 images=0 processes=0`. OPS-08 still
requires the complete frozen input set documented by
`tests/upgrade-process-e2e/README.md`.

UX-01 runs once after this runtime wave, using the six disposable identity
storage-state files, Web/Operator base URLs, scenario-driver URL and protected
token file documented by `tests/browser-final-acceptance/README.md`.

## One-shot input preflight

Before authorizing either final wave, inspect every OPS-08 and UX-01 input in
one no-resource pass:

```sh
bash tests/final-acceptance/input-preflight.sh
```

The runtime wrapper invokes this same preflight automatically before Docker
inspection, temporary-directory creation or any stage. Missing UX-01 input
therefore blocks the runtime wave too: root freezes all runtime and browser
inputs first, then runs each final wave once without a partial retry cycle.

The preflight reads no token, password, cookie or storage-state content and
creates no output. It reports only stable input names and metadata status, then
exits `78` when anything is missing, unsafe or malformed. L4-01 requires the
digest-pinned, prefetched `L401_RUNNER_IMAGE` and its 64-hex
`L401_RUNNER_PROVENANCE_INPUT_SHA256` binding; this pass validates both without
pulling, building or inspecting Docker. OPS-08 is split into 19
external supply-chain facts and 21 local source inputs. When those facts and
`cosign` are available, the existing
`tests/upgrade-process-e2e/prepare-inputs.sh` atomically assembles the 100 local
runtime inputs; it never fabricates OCI digests, keyless signatures, SLSA
provenance or SPDX evidence.

UX-01 currently has 13 runner inputs, including the six disposable identity
storage-state files and the private public-login credential file. The scenario
driver has 10 launcher inputs and the public-auth bootstrap has seven inputs.
None can be generated safely offline: URLs and bearer files must be bound to
the task-owned services that consume them, while credentials, identity
bindings and storage states must come from real disposable Control, License,
Operator and public registration/login flows. Production accounts, shared
browser sessions, forged cookies and fixed OTP/reset tokens are forbidden.

The machine-readable classification is
`tests/final-acceptance/input-contract.json`. Its static drift check is:

```sh
bash tests/final-acceptance/input-preflight-contract_test.sh
```

The wrapper trap removes only its own `/tmp/cdnca-final-acceptance.*` logs.
Containers, networks, images, sockets, browsers and scenario data remain owned
and cleaned by the delegated driver that created them.

The no-resource wrapper check is:

```sh
FINAL_ACCEPTANCE_STATIC_ONLY=1 bash tests/final-acceptance/run.sh
```

This mode starts no Docker, OpenResty, systemd, NATS, PostgreSQL, ClickHouse or
browser process. Round-2 verification is limited to the single contract,
`bash -n`, ShellCheck and static affected gate; it does not rerun any runtime
stage, race suite, full suite or fresh review.
