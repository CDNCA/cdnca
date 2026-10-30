#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

for example_dir in \
  "${repo_root}/examples/plugins/webhook-audit-sink" \
  "${repo_root}/examples/plugins/webhook-v2-receiver"; do
  test -z "$(gofmt -d "${example_dir}"/*.go)"
  (
    cd "${example_dir}"
    GOWORK=off go test -count=1 ./...
    GOWORK=off go test -race -count=1 ./...
    GOWORK=off go vet ./...
  )
done

shellcheck "${repo_root}/scripts/plugin-example-smoke.sh" "${repo_root}/tests/plugin-example/ci.sh"
bash -n "${repo_root}/scripts/plugin-example-smoke.sh" "${repo_root}/tests/plugin-example/ci.sh"
node --check "${repo_root}/tests/plugin-example/validate-contracts.mjs"
node --check "${repo_root}/tests/plugin-example/webhook-client.mjs"
node "${repo_root}/scripts/validate-marketplace-contracts.mjs"
node "${repo_root}/tests/plugin-example/validate-contracts.mjs"
pnpm --package="markdownlint-cli2@0.18.1" dlx markdownlint-cli2 \
  --config "${repo_root}/docs/developer/.markdownlint-cli2.jsonc" \
  "${repo_root}/docs/developer/examples/webhook-audit-sink.md" \
  "${repo_root}/docs/developer/examples/webhook-v2-receiver.md" \
  "${repo_root}/docs/developer/plugin-integration.md"
"${repo_root}/scripts/plugin-example-smoke.sh"

echo "plugin example CI: passed"
