#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

node "$repo_root/tools/contract-doc-check/openapi-index.test.mjs"
node "$repo_root/tools/contract-doc-check/openapi-index.mjs" --repo-root "$repo_root" --check
exec node "$repo_root/tools/contract-doc-check/check.mjs" --repo-root "$repo_root" "$@"
