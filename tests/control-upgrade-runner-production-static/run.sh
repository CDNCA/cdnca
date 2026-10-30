#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
control="$root/services/control-api"
failures=0

record() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "FAIL: $label" >&2
    failures=$((failures + 1))
  fi
}

contains() {
  grep -Fq -- "$2" "$1"
}

absent() {
  ! grep -Fq -- "$2" "$1"
}

if [[ "${HELM_COMPOSITION_ONLY:-}" == "1" ]]; then
  :
elif [[ "${FAILED_ONLY:-}" == "1" ]]; then
  record "Helm contract" bash -c 'cd "$1" && go test ./cmd/control-upgrade-runner -run TestControlUpgradeRunnerHelmContractIsLeastPrivilegeAndDurable -count=1' _ "$control"
elif [[ "${RED_ONLY:-}" == "1" ]]; then
  record "focused Go contract" bash -c 'cd "$1" && go test ./internal/controlplaneupgrade ./cmd/control-upgrade-runner -run "Production|KubernetesTargetUsesHTTPPlanSource" -count=1' _ "$control"
else
  record "affected Go tests" bash -c 'cd "$1" && go test ./internal/controlplaneupgrade ./cmd/control-upgrade-runner -count=1' _ "$control"
  record "affected Go vet" bash -c 'cd "$1" && go vet ./internal/controlplaneupgrade ./cmd/control-upgrade-runner' _ "$control"
fi

runner="$root/infra/helm/cdnca/templates/control-upgrade-runner.yaml"
control_api="$root/infra/helm/cdnca/templates/control-api.yaml"
openapi="$root/api/control-upgrade-plan.openapi.yaml"
schema="$root/infra/helm/cdnca/values.schema.json"
unit="$root/services/control-api/packaging/systemd/cdnca-control-upgrade-runner.service"
runbook="$root/docs/runbooks/control-plane-upgrade-runner.md"
production_values="$root/infra/helm/cdnca/values-production.yaml"
default_values="$root/infra/helm/cdnca/values.yaml"
main="$control/cmd/control-upgrade-runner/main.go"

if [[ "${FAILED_ONLY:-}" != "1" && "${HELM_COMPOSITION_ONLY:-}" != "1" ]]; then
for fragment in \
  CONTROL_UPGRADE_PLAN_SOURCE_URL \
  CONTROL_UPGRADE_PLAN_SOURCE_CA_FILE \
  CONTROL_UPGRADE_PLAN_SOURCE_CERT_FILE \
  CONTROL_UPGRADE_PLAN_SOURCE_KEY_FILE \
  CONTROL_UPGRADE_PLAN_SOURCE_TIMEOUT \
  CONTROL_UPGRADE_PLAN_SOURCE_MAX_BYTES \
  CONTROL_UPGRADE_PLAN_LKG_FILE \
  CONTROL_UPGRADE_POLL_INTERVAL \
  CONTROL_UPGRADE_CURRENT_VERSION \
  CONTROL_UPGRADE_STEP_TIMEOUT \
  CONTROL_UPGRADE_HEALTH_TIMEOUT \
  CONTROL_UPGRADE_IMAGE_PULL_SECRETS_JSON; do
  record "runner environment $fragment" contains "$runner" "$fragment"
done
record "Kubernetes selects HTTPS plan source" contains "$main" 'usesHTTPPlanSource(target)'
record "runner has no file plan source" absent "$runner" 'CONTROL_UPGRADE_PLAN_FILE'
record "source secret mount is read-only" contains "$runner" 'name: plan-source, mountPath: /var/run/secrets/cdnca/plan-source, readOnly: true'
record "LKG is PVC-backed" contains "$runner" 'CONTROL_UPGRADE_PLAN_LKG_FILE, value: /var/lib/cdnca-control-upgrade-volume/state/plan-lkg.json'
if grep -Eq '^[[:space:]]*(kind: Secret|data:|stringData:)' "$runner"; then
  echo "FAIL: runner template must not create or inline a Secret" >&2
  failures=$((failures + 1))
fi
for fragment in 'CapabilityBoundingSet=' 'AmbientCapabilities=' 'SystemCallFilter=@system-service' 'SystemCallErrorNumber=EPERM'; do
  record "systemd sandbox $fragment" contains "$unit" "$fragment"
done
record "runbook completion marker" grep -Eq 'OPS-06.*complete|OPS-06.*完成' "$runbook"
if grep -Fq 'OPS-06 仍只能保持 `partial`' "$runbook"; then
  echo "FAIL: runbook still marks OPS-06 partial" >&2
  failures=$((failures + 1))
fi
fi

if ! ruby -r yaml -e '
  control = File.read(ARGV.fetch(0))
  runner = File.read(ARGV.fetch(1))
  document = YAML.safe_load(File.read(ARGV.fetch(2)), aliases: true)
  block_pattern = /\{\{- if \.Values\.controlUpgradeRunner\.enabled \}\}(.*?)\{\{- end \}\}/m
  enabled = control.scan(block_pattern).flatten.join("\n")
  outside = control.gsub(block_pattern, "")
  required = [
    "CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED",
    "control-upgrade-plan-source",
    ".Values.controlUpgradeRunner.planSource.existingSecret",
    ".Values.controlUpgradeRunner.planSource.keys.internalToken"
  ]
  abort "enabled composition is incomplete" unless required.all? { |fragment| enabled.include?(fragment) }
  abort "disabled composition retains plan source" if required.any? { |fragment| outside.include?(fragment) }
  abort "plan source enabled env is duplicated" unless control.scan("CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED").length == 1
  mount_ok = control.scan("- name: control-upgrade-plan-source").length == 2 &&
    control.scan("/var/run/secrets/cdnca/control-upgrade-plan-source").length == 2 && control.include?("readOnly: true")
  abort "plan source mount is not exactly one read-only mount plus one volume" unless mount_ok
  abort "plan writer binding changed" unless control.include?("CONTROL_UPGRADE_PLAN_SECRET, value: {{ .Values.controlUpgradeRunner.planSecret.existingSecret | quote }}") &&
    control.include?("CONTROL_UPGRADE_PLAN_SECRET_KEY, value: {{ .Values.controlUpgradeRunner.planSecret.key | quote }}")
  [control, runner].each do |template|
    abort "token secret source diverged" unless template.include?(".Values.controlUpgradeRunner.planSource.existingSecret") &&
      template.include?(".Values.controlUpgradeRunner.planSource.keys.internalToken")
  end
  operation = document.dig("paths", "/v1/internal/control-upgrade/plan", "get")
  abort "internal GET plan route is missing" unless operation
  abort "internal plan security is not exclusive" unless operation["security"] == [{"internalBearer" => []}]
  expected = {
    "200" => "#/components/responses/InternalPlanOK",
    "304" => "#/components/responses/InternalPlanNotModified",
    "401" => "#/components/responses/InternalPlanUnauthorized",
    "404" => "#/components/responses/InternalPlanNotFound",
    "405" => "#/components/responses/InternalPlanMethodNotAllowed",
    "503" => "#/components/responses/InternalPlanUnavailable"
  }
  abort "internal plan responses diverged" unless operation.fetch("responses") == expected.transform_values { |ref| {"$ref" => ref} }
  abort "nonexistent internal plan 400 is documented" if operation.fetch("responses").key?("400")
  components = document.fetch("components")
  ok = components.dig("responses", "InternalPlanOK")
  cached = components.dig("responses", "InternalPlanNotModified")
  abort "plan cache headers are incomplete" unless ok.dig("headers", "ETag") && ok.dig("headers", "Cache-Control") &&
    cached.dig("headers", "ETag") && cached.dig("headers", "Cache-Control") && !cached.key?("content")
  %w[InternalPlanUnauthorized InternalPlanNotFound InternalPlanMethodNotAllowed InternalPlanUnavailable].each do |name|
    content = components.dig("responses", name, "content") || {}
    abort "#{name} is not exact text/plain" unless content.key?("text/plain") && !content.key?("application/json")
  end
' "$control_api" "$runner" "$openapi"; then
  echo "FAIL: Control API plan source Helm/OpenAPI composition" >&2
  failures=$((failures + 1))
fi

if ! (cd "$root" && ruby -r yaml -r json -e \
  'def merge_values(base, override)
     return override unless base.is_a?(Hash) && override.is_a?(Hash)
     base.merge(override) { |_key, left, right| merge_values(left, right) }
   end
   defaults = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: true)
   production = YAML.safe_load(File.read(ARGV.fetch(1)), aliases: true)
   print JSON.generate(merge_values(defaults, production))' "$default_values" "$production_values" | \
  node -e '
    const fs = require("fs");
    const Ajv = require("ajv");
    const addFormats = require("ajv-formats");
    const schema = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    delete schema.$schema;
    const values = JSON.parse(fs.readFileSync(0, "utf8"));
    const ajv = new Ajv({allErrors: true, strict: false});
    addFormats(ajv);
    const runnerSchema = {...schema.definitions.controlUpgradeRunner, definitions: schema.definitions};
    const validate = ajv.compile(runnerSchema);
    if (!validate(values.controlUpgradeRunner)) throw new Error(`production controlUpgradeRunner: ${ajv.errorsText(validate.errors)}`);
    const missing = JSON.parse(JSON.stringify(values.controlUpgradeRunner));
    delete missing.planSource;
    if (validate(missing)) throw new Error("schema accepted missing planSource");
    const invalid = JSON.parse(JSON.stringify(values.controlUpgradeRunner));
    invalid.planSource.url = "http://control.invalid/v1/internal/control-upgrade/plan";
    if (validate(invalid)) throw new Error("schema accepted non-HTTPS planSource URL");
  ' "$schema"); then
  echo "FAIL: production values/schema plan source contract" >&2
  failures=$((failures + 1))
fi

if ((failures > 0)); then
  echo "CONTROL_UPGRADE_RUNNER_PRODUCTION_STATIC FAIL ($failures checks)" >&2
  exit 1
fi

echo "CONTROL_UPGRADE_RUNNER_PRODUCTION_STATIC PASS"
