#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

readonly BUF_VERSION="1.47.2"
readonly PNPM_VERSION="10.15.0"
readonly REDOCLY_VERSION="1.34.5"

step() {
  printf '\n==> %s\n' "$1"
}

die() {
  printf 'ci-check: %s\n' "$1" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_env() {
  [[ -n "${!1:-}" ]] || die "required environment variable is not set: $1"
}

require_pnpm() {
  require_command pnpm
  local actual_version
  actual_version="$(pnpm --version)"
  [[ "$actual_version" == "$PNPM_VERSION" ]] ||
    die "pnpm $PNPM_VERSION is required, found $actual_version"
}

go_check() {
  local module="$1"
  local workspace="$2"

  require_command go

  step "go test: $module"
  if [[ "$workspace" == "off" ]]; then
    (cd "$REPO_ROOT/$module" && GOWORK=off go test -count=1 ./...)
  else
    (cd "$REPO_ROOT/$module" && go test -count=1 ./...)
  fi

  step "go vet: $module"
  if [[ "$workspace" == "off" ]]; then
    (cd "$REPO_ROOT/$module" && GOWORK=off go vet ./...)
  else
    (cd "$REPO_ROOT/$module" && go vet ./...)
  fi
}

go_race() {
  local module="$1"
  local workspace="$2"

  require_command go

  step "go race: $module"
  if [[ "$workspace" == "off" ]]; then
    (cd "$REPO_ROOT/$module" && GOWORK=off go test -race -count=1 ./...)
  else
    (cd "$REPO_ROOT/$module" && go test -race -count=1 ./...)
  fi
}

# Shared libraries (used by control-api through go.work); each is its own
# module with GOWORK=off.
readonly GO_LIBS=(libs/edgeconfig libs/entitlement libs/mail libs/marketproto libs/mtlstunnel libs/passwordpolicy libs/rulepack libs/sitetheme libs/themepack)

check_go_libs() {
  local module
  for module in "${GO_LIBS[@]}"; do go_check "$module" off; done
}

check_go_all() {
  go_check services/control-api workspace
  go_check services/agent-gateway off
  go_check agents/edge-agent workspace
  check_go_libs
}

check_frontend() {
  require_pnpm

  step "install frontend dependencies"
  (cd "$REPO_ROOT" && pnpm install --frozen-lockfile)

  # Every backend route has a page entry and every page call hits a real route
  # (allowlist: tests/ui-route-coverage/allowlist.json, one reason per gap).
  step "frontend route coverage"
  (cd "$REPO_ROOT" && node --test tests/ui-route-coverage/ui-route-coverage.test.mjs)

  # Shared theme/provider package used by the front ends (TS source, no build).
  step "frontend typecheck: @cdnca/ui"
  (cd "$REPO_ROOT" && pnpm --filter @cdnca/ui typecheck)

  local app
  for app in @cdnca/web; do
    step "frontend lint: $app"
    (cd "$REPO_ROOT" && pnpm --filter "$app" lint)
    step "frontend test: $app"
    (cd "$REPO_ROOT" && pnpm --filter "$app" exec vitest run --maxWorkers=1)
    step "frontend build: $app"
    (cd "$REPO_ROOT" && pnpm --filter "$app" build)
  done
}

check_proto() {
  require_command buf

  local actual_version
  actual_version="$(buf --version)"
  [[ "$actual_version" == "$BUF_VERSION" ]] ||
    die "buf $BUF_VERSION is required, found $actual_version"

  step "protobuf format"
  (cd "$REPO_ROOT/proto" && buf format --diff --exit-code)
  step "protobuf lint"
  (cd "$REPO_ROOT/proto" && buf lint)
  step "protobuf build"
  (cd "$REPO_ROOT/proto" && buf build >/dev/null)
  step "protobuf compatibility"
  (cd "$REPO_ROOT/proto" && buf breaking --against baseline/cdnca.bin)
  step "protobuf baseline checksum"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$REPO_ROOT/proto" && sha256sum -c baseline/cdnca.bin.sha256)
  else
    require_command shasum
    (cd "$REPO_ROOT/proto" && shasum -a 256 -c baseline/cdnca.bin.sha256)
  fi
}

check_openapi() {
  require_pnpm

  local openapi_files=()
  local file
  while IFS= read -r file; do
    openapi_files+=("$file")
  done < <(find "$REPO_ROOT/api/openapi" -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.json' \) | LC_ALL=C sort)
  ((${#openapi_files[@]} > 0)) || die "no OpenAPI descriptions found"

  step "OpenAPI structural validation"
  REDOCLY_TELEMETRY=off REDOCLY_SUPPRESS_UPDATE_NOTICE=true \
    pnpm --package="@redocly/cli@$REDOCLY_VERSION" dlx redocly lint \
      --extends=minimal "${openapi_files[@]}"
}

check_contracts() {
  require_command node
  require_pnpm

  step "OpenAPI index generator tests"
  (cd "$REPO_ROOT" && node tools/contract-doc-check/openapi-index.test.mjs)
  step "OpenAPI index drift"
  (cd "$REPO_ROOT" && node tools/contract-doc-check/openapi-index.mjs --check)
  step "install contract dependencies"
  (cd "$REPO_ROOT" && pnpm --filter cdnca install --frozen-lockfile --ignore-scripts)

  check_proto
  check_openapi
  step "marketplace JSON Schema contracts"
  (cd "$REPO_ROOT" && pnpm contracts:validate)
}

check_shell() {
  local file
  local shellcheck_available=false
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck_available=true
  fi

  while IFS= read -r file; do
    step "shell syntax: ${file#"$REPO_ROOT/"}"
    case "$(sed -n '1p' "$file")" in
      *bash*) bash -n "$file" ;;
      *) sh -n "$file" ;;
    esac
    if [[ "$shellcheck_available" == true ]]; then
      shellcheck --severity=error "$file"
    fi
  done < <(find \
    "$REPO_ROOT/scripts" \
    "$REPO_ROOT/agents/edge-agent/packaging" \
    "$REPO_ROOT/edge/openresty" \
    "$REPO_ROOT/tests" \
    -type f -name '*.sh' | LC_ALL=C sort)
}

# Release packaging, installer and deploy-script contracts (offline; Linux or
# docker for the root-only fixtures). The schema build test reads the real
# migration history, so CI checks out with full history.
check_release_scripts() {
  require_command node
  step "install preflight embedded copies"
  (cd "$REPO_ROOT" && node scripts/sync-install-preflight.mjs --check)
  step "release packaging and installer contracts"
  (cd "$REPO_ROOT" && node --test \
    scripts/native-release-package.test.mjs \
    scripts/native-initial-release-package.test.mjs \
    scripts/native-control-install-package.test.mjs \
    scripts/native-management-schema-build.test.mjs \
    scripts/edge-agent-release-build.test.mjs \
    tests/install-control-*.test.mjs \
    tests/control-optional-env-template.test.mjs \
    tests/install-preflight.test.mjs \
    tests/native-control-install-wiring.test.mjs \
    tests/native-control-install-verifier.test.mjs)
  step "installer static contracts"
  bash "$REPO_ROOT/tests/installers-static-test.sh"
}

check_plugin_example() {
  step "isolated plugin example"
  "$REPO_ROOT/tests/plugin-example/ci.sh"
}

integration_control_db() {
  require_command go
  require_env TEST_DATABASE_URL
  step "control-api PostgreSQL integration"
  (cd "$REPO_ROOT/services/control-api" && go test -race -tags=integration -count=1 ./...)
}

integration_messaging() {
  require_command go
  require_env TEST_DATABASE_URL
  require_env CDNCA_TEST_NATS_URL
  require_env CDNCA_TEST_REDIS_ADDR
  require_command redis-server

  step "control-api PostgreSQL/Redis/JetStream integration"
  (cd "$REPO_ROOT/services/control-api" && go test -race -tags=integration -count=1 ./internal/nodepresence)

  step "agent-gateway Redis/JetStream integration"
  (cd "$REPO_ROOT/services/agent-gateway" && GOWORK=off go test -race -tags=integration -count=1 ./...)
}

usage() {
  cat <<'EOF'
Usage: scripts/ci-check.sh [target]

Default target: all

Targets:
  all                     Contracts, shell, release scripts, plugin example, Go, and frontend checks
  contracts               Buf format/lint/build/breaking and OpenAPI validation
  shell                   Shell syntax and ShellCheck errors when available
  plugin-example          Isolated plugin example aggregate checks and HTTP smoke
  release-scripts         Release packaging, installer and deploy-script contracts
  go                      Test and vet all application modules and shared libs
  go-control              Test and vet control-api in the root workspace
  go-gateway              Test and vet agent-gateway with GOWORK=off
  go-edge                 Test and vet edge-agent in the root workspace
  go-libs                 Test and vet libs/* with GOWORK=off
  race-control            Race-test control-api
  race-gateway            Race-test agent-gateway with GOWORK=off
  race-edge               Race-test edge-agent
  frontend                Install, lint, test, and build the Web frontend
  integration-control-db  Control-api tests against TEST_DATABASE_URL
  integration-messaging   Tagged PG/Redis/JetStream suites; requires the
                          three integration URLs and a redis-server executable
EOF
}

case "${1:-all}" in
  all)
    check_contracts
    check_shell
    check_release_scripts
    check_plugin_example
    check_go_all
    check_frontend
    ;;
  contracts) check_contracts ;;
  shell) check_shell ;;
  release-scripts) check_release_scripts ;;
  plugin-example) check_plugin_example ;;
  go) check_go_all ;;
  go-control) go_check services/control-api workspace ;;
  go-gateway) go_check services/agent-gateway off ;;
  go-edge) go_check agents/edge-agent workspace ;;
  go-libs) check_go_libs ;;
  race-control) go_race services/control-api workspace ;;
  race-gateway) go_race services/agent-gateway off ;;
  race-edge) go_race agents/edge-agent workspace ;;
  frontend) check_frontend ;;
  integration-control-db) integration_control_db ;;
  integration-messaging) integration_messaging ;;
  -h|--help|help) usage ;;
  *)
    usage >&2
    die "unknown target: $1"
    ;;
esac
