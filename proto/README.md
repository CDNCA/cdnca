# Protobuf generation and compatibility

The files under `common/v1`, `agent/v1`, and `controlinternal/v1` are the
source contracts. Generated Go code lives in the independent module
`gen/go`; do not edit generated files by hand.

## Toolchain

- Buf CLI `v1.47.2`
- Remote plugin `buf.build/protocolbuffers/go:v1.36.10`
- Remote plugin `buf.build/grpc/go:v1.5.1`
- Go `1.24.x`

The plugin versions are pinned in `buf.gen.yaml`. Managed mode supplies the
Go import prefix without adding language-specific options to the source
contracts.

Install the pinned Buf CLI with the official Go module:

```sh
go install github.com/bufbuild/buf/cmd/buf@v1.47.2
export PATH="$(go env GOPATH)/bin:$PATH"
buf --version
```

The version command must print `1.47.2` before generation or compatibility
checks are run.

## Generate and verify

Run these commands from the repository root:

```sh
cd proto
buf format --diff --exit-code
buf lint
buf build
buf generate
buf breaking --against baseline/cdnca.bin

tmp_descriptor="$(mktemp)"
buf build -o "$tmp_descriptor"
cmp baseline/cdnca.bin "$tmp_descriptor"
rm "$tmp_descriptor"
shasum -a 256 -c baseline/cdnca.bin.sha256

cd gen/go
GOWORK=off go test ./...
GOWORK=off go vet ./...
```

After generation, return to the repository root. There,
`git diff --exit-code -- proto/gen/go` is the CI drift check once the generated
module is tracked.

## Refresh the compatibility baseline

The 2026-09-25 additive baseline includes `ACCESS_WINDOW_V1`, the v2
connection observation config identity, and independently negotiated telemetry
queue cursors. An absent optional connections cursor retains legacy sequencing;
new Agents require the Gateway acknowledgement before sending mixed queues.
Existing v1 positive/subscription constraints are unchanged. See
`../docs/runbooks/realtime-independent-source-20260925.md` for rollout/rollback.

`baseline/cdnca.bin` is a Buf image of the last reviewed wire contract. A
normal source edit must pass `buf breaking` against this file. Refresh it only
after an intentional compatibility review:

```sh
cd proto
buf build -o baseline/cdnca.bin
shasum -a 256 baseline/cdnca.bin > baseline/cdnca.bin.sha256
```

Commit the source changes, generated Go changes, and refreshed baseline in the
same reviewed change. Never refresh the baseline merely to make a breaking
check pass.
