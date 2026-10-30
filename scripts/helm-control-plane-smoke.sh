#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
CHART_DIR="$ROOT_DIR/infra/helm/cdnca"
PRODUCTION_VALUES="$CHART_DIR/values-production.yaml"
MODE=${1:---all}
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-helm-smoke.XXXXXX")
CLUSTER_NAME="cdnca-smoke-$$"
CLUSTER_DRIVER=""
CLUSTER_CREATED=false
ORIGINAL_CONTEXT=""

cleanup() {
  if [ "$CLUSTER_CREATED" = true ]; then
    if [ "$CLUSTER_DRIVER" = kind ]; then
      kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    elif [ "$CLUSTER_DRIVER" = k3d ]; then
      k3d cluster delete "$CLUSTER_NAME" >/dev/null 2>&1 || true
    fi
  fi
  if [ -n "$ORIGINAL_CONTEXT" ]; then
    kubectl config use-context "$ORIGINAL_CONTEXT" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

usage() {
  echo "usage: $0 [--static|--cluster|--all]" >&2
  exit 2
}

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 2
  }
}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

expect_kind_count() {
  manifest=$1
  kind=$2
  expected=$3
  actual=$(awk -v expected_kind="$kind" '$0 == "kind: " expected_kind { count++ } END { print count + 0 }' "$manifest")
  [ "$actual" -eq "$expected" ] || fail "$kind count is $actual, want $expected"
}

# expect_kind_names: the metadata.name of every resource of kind, sorted,
# equals the space separated names (sorted).
expect_kind_names() {
  manifest=$1
  kind=$2
  want=$(printf '%s\n' $3 | sort | tr '\n' ' ')
  actual=$(awk -v expected_kind="$kind" '
    /^---/ { current = ""; next }
    $0 == "kind: " expected_kind { current = expected_kind; next }
    /^kind: / { current = ""; next }
    current != "" && /^  name: / { print $2; current = "" }
  ' "$manifest" | sort | tr '\n' ' ')
  [ "$actual" = "$want" ] || fail "$kind names are '$actual', want '$want'"
}

# expect_upgrade_rbac: the runner Role touches no Secret; the plan writer
# Role touches only the upgrade plan Secret by name, never list/watch/create/delete.
expect_upgrade_rbac() {
  ruby -ryaml -e '
    docs = YAML.load_stream(File.read(ARGV[0])).compact.select { |d| d["kind"] == "Role" }
    roles = docs.to_h { |d| [d.dig("metadata", "name"), d["rules"] || []] }
    runner = roles.fetch("cdnca-control-upgrade-runner")
    abort "FAIL: runner Role reaches secrets" if runner.any? { |r| (r["resources"] || []).include?("secrets") || (r["resources"] || []).include?("*") }
    writer = roles.fetch("cdnca-control-api-upgrade-plan-writer")
    ok = writer.all? { |r| r["resources"] == ["secrets"] && r["resourceNames"] == ["cdnca-control-upgrade-plan"] && (r["verbs"] - ["get", "update", "patch"]).empty? }
    abort "FAIL: plan writer Role is wider than the upgrade plan Secret (get/update/patch)" unless ok && !writer.empty?
  ' "$1" || fail "upgrade RBAC rules"
}

expect_at_least() {
  manifest=$1
  pattern=$2
  minimum=$3
  actual=$(awk -v pattern="$pattern" 'index($0, pattern) { count++ } END { print count + 0 }' "$manifest")
  [ "$actual" -ge "$minimum" ] || fail "'$pattern' count is $actual, want at least $minimum"
}

expect_ingress_path_backend() {
  manifest=$1
  path=$2
  service=$3
  binding=$(awk -v target_path="$path" '
    $1 == "-" && $2 == "path:" { selected = ($3 == target_path); next }
    selected && $1 == "pathType:" { path_type = $2; next }
    selected && $1 == "name:" { print path_type "|" $2; exit }
  ' "$manifest")
  [ "$binding" = "Prefix|$service" ] || fail "$path binding is '$binding', want Prefix|$service"
}

expect_template_failure() {
  description=$1
  shift
  if helm template reject "$CHART_DIR" "$@" >"$TMP_DIR/rejected.yaml" 2>"$TMP_DIR/rejected.err"; then
    fail "$description was accepted"
  fi
}

expect_plugin_failure() {
  description=$1
  shift
  expect_template_failure "$description" -f "$PRODUCTION_VALUES" -f "$PLUGIN_WEBHOOK_VALUES" "$@"
}

expect_absent() {
  manifest=$1
  pattern=$2
  if grep -Fq "$pattern" "$manifest"; then
    fail "$manifest unexpectedly contains '$pattern'"
  fi
}

expect_cidr_ports() {
  manifest=$1
  cidr=$2
  expected=$3
  actual=$(awk -v target="\"$cidr\"" '
    $1 == "cidr:" && $2 == target { selected = 1; next }
    selected && ($0 == "---" || ($1 == "-" && $2 == "to:")) { exit }
    selected && $1 == "-" && $2 == "port:" {
      ports = ports separator $3
      separator = ","
    }
    END { print ports }
  ' "$manifest")
  [ "$actual" = "$expected" ] || fail "$cidr ports are '$actual', want '$expected'"
}

expect_package_commerce_wiring() {
  manifest=$1
  expected_http=$2
  expected_worker=$3
  ruby - "$manifest" "$expected_http" "$expected_worker" <<'RUBY'
require "yaml"

def check(condition, message)
  abort "FAIL: #{message}" unless condition
end

documents = YAML.load_stream(File.read(ARGV.fetch(0))).compact
deployment = documents.find do |document|
  document["kind"] == "Deployment" &&
    document.dig("metadata", "name") == "cdnca-control-api"
end
check(deployment, "control-api Deployment is missing")
container = Array(deployment.dig("spec", "template", "spec", "containers")).find do |item|
  item["name"] == "control-api"
end
check(container, "control-api container is missing")

expected_http = ARGV.fetch(1)
expected_worker = ARGV.fetch(2)
env = Array(container["env"])
package_env = env.select { |item| item["name"].to_s.start_with?("PACKAGE_COMMERCE_") }
runtime_enabled = package_env.select { |item| item["name"] == "PACKAGE_COMMERCE_RUNTIME_ENABLED" }
check(
  runtime_enabled == [{"name" => "PACKAGE_COMMERCE_RUNTIME_ENABLED", "value" => expected_http}],
  "PACKAGE_COMMERCE_RUNTIME_ENABLED must be the exact #{expected_http.inspect} scalar",
)

# provider callbacks (docs/runbooks/native-install-runtime-contract.md):
# always the scalar flag; off in every rendered set, so no keyring entry
callbacks = package_env.select { |item| item["name"] == "PACKAGE_COMMERCE_PROVIDER_CALLBACKS_ENABLED" }
check(callbacks == [{"name" => "PACKAGE_COMMERCE_PROVIDER_CALLBACKS_ENABLED", "value" => "false"}],
  "PACKAGE_COMMERCE_PROVIDER_CALLBACKS_ENABLED must be the exact \"false\" scalar")
check(package_env.none? { |item| item["name"] == "PACKAGE_COMMERCE_PROVIDER_KEYRING_JSON" },
  "disabled provider callbacks must not expose the keyring")
cursor_key = package_env.select { |item| item["name"] == "PACKAGE_COMMERCE_CURSOR_KEY_BASE64" }
if expected_http == "true"
  check(cursor_key.length == 1, "enabled package commerce must expose one cursor-key environment entry")
  check(
    cursor_key.first == {
      "name" => "PACKAGE_COMMERCE_CURSOR_KEY_BASE64",
      "valueFrom" => {
        "secretKeyRef" => {
          "name" => "cdnca-control-api-runtime",
          "key" => "package-commerce-cursor-key-base64",
        },
      },
    },
    "package commerce cursor key must use the existing runtime Secret key",
  )
else
  check(cursor_key.empty?, "disabled package commerce must not expose its cursor key")
end

worker_env = package_env.select { |item| item["name"].to_s.start_with?("PACKAGE_COMMERCE_WORKER_") }
expected_worker_env = {
  "PACKAGE_COMMERCE_WORKER_ENABLED" => expected_worker,
}
if expected_worker == "true"
  expected_worker_env.merge!({
    "PACKAGE_COMMERCE_WORKER_NATS_URL" => "tls://nats.package-commerce.svc.cluster.local:4222",
    "PACKAGE_COMMERCE_WORKER_NATS_NAME" => 'cdnca-package-commerce-worker-$(POD_UID)',
    "PACKAGE_COMMERCE_WORKER_NATS_CREDS_FILE" => "/var/run/secrets/cdnca/package-commerce-worker-nats/runtime.creds",
    "PACKAGE_COMMERCE_WORKER_NATS_CA_FILE" => "/var/run/secrets/cdnca/package-commerce-worker-nats/ca.crt",
    "PACKAGE_COMMERCE_WORKER_NATS_STREAM" => "PACKAGE_COMMERCE",
    "PACKAGE_COMMERCE_WORKER_OWNER" => 'package-commerce-worker-$(POD_UID)',
    "PACKAGE_COMMERCE_WORKER_NATS_CONNECT_TIMEOUT" => "5s",
    "PACKAGE_COMMERCE_WORKER_NATS_OPERATION_TIMEOUT" => "5s",
    "PACKAGE_COMMERCE_WORKER_NATS_RECONNECT_WAIT" => "1s",
    "PACKAGE_COMMERCE_WORKER_NATS_DRAIN_TIMEOUT" => "10s",
    "PACKAGE_COMMERCE_WORKER_BATCH_SIZE" => "64",
    "PACKAGE_COMMERCE_WORKER_LEASE_DURATION" => "1m",
    "PACKAGE_COMMERCE_WORKER_PUBLISH_TIMEOUT" => "5s",
    "PACKAGE_COMMERCE_WORKER_SETTLE_TIMEOUT" => "5s",
    "PACKAGE_COMMERCE_WORKER_RETRY_MAX_ATTEMPTS" => "5",
    "PACKAGE_COMMERCE_WORKER_RETRY_BASE_DELAY" => "1s",
    "PACKAGE_COMMERCE_WORKER_RETRY_MAX_DELAY" => "30s",
    "PACKAGE_COMMERCE_WORKER_IDLE_POLL" => "250ms",
    "PACKAGE_COMMERCE_WORKER_ERROR_BACKOFF" => "1s",
    "PACKAGE_COMMERCE_WORKER_SHUTDOWN_TIMEOUT" => "30s",
  })
end
actual_worker_env = {}
worker_env.each do |item|
  name = item["name"]
  check(expected_worker_env.key?(name), "unexpected package commerce worker env #{name}")
  check(item.keys.sort == ["name", "value"], "#{name} must use a scalar value")
  check(!actual_worker_env.key?(name), "duplicate package commerce worker env #{name}")
  actual_worker_env[name] = item["value"]
end
check(actual_worker_env == expected_worker_env, "package commerce worker env does not match")

pod_spec = deployment.dig("spec", "template", "spec")
volumes = Array(pod_spec["volumes"]).select { |item| item["name"] == "package-commerce-worker-nats" }
mounts = Array(container["volumeMounts"]).select { |item| item["name"] == "package-commerce-worker-nats" }
if expected_worker == "true"
  check(package_env.length == 24, "enabled package commerce must expose exactly 24 environment entries")
  check(volumes.length == 1, "enabled package commerce worker must expose one NATS volume")
  check(mounts == [{
    "name" => "package-commerce-worker-nats",
    "mountPath" => "/var/run/secrets/cdnca/package-commerce-worker-nats",
    "readOnly" => true,
  }], "package commerce worker NATS mount does not match")
  projected = volumes.first["projected"]
  check(projected["defaultMode"] == 0o440, "package commerce worker NATS volume must use mode 0440")
  sources = Array(projected["sources"]).map do |source|
    secret = source.fetch("secret")
    item = Array(secret["items"]).fetch(0)
    [secret["name"], item["key"], item["path"]]
  end.sort
  check(sources == [
    ["cdnca-package-commerce-nats-ca", "ca.crt", "ca.crt"],
    ["cdnca-package-commerce-nats-credentials", "runtime.creds", "runtime.creds"],
  ], "package commerce worker NATS Secret refs do not match")
  pod_uid = env.select { |item| item["name"] == "POD_UID" }
  check(pod_uid == [{
    "name" => "POD_UID",
    "valueFrom" => {"fieldRef" => {"fieldPath" => "metadata.uid"}},
  }], "package commerce worker must derive its owner from metadata.uid")
else
  expected_count = expected_http == "true" ? 4 : 3
  check(package_env.length == expected_count, "disabled package commerce worker exposed unexpected environment")
  check(volumes.empty?, "disabled package commerce worker must not expose its NATS volume")
  check(mounts.empty?, "disabled package commerce worker must not expose its NATS mount")
end
RUBY
}

expect_package_commerce_failure() {
  description=$1
  shift
  expect_template_failure "$description" -f "$PRODUCTION_VALUES" "$@"
}

expect_plugin_wiring() {
  manifest=$1
  ruby - "$manifest" <<'RUBY'
require "yaml"

def check(condition, message)
  abort "FAIL: #{message}" unless condition
end

documents = YAML.load_stream(File.read(ARGV.fetch(0))).compact
deployments = documents.select do |document|
  document["kind"] == "Deployment" &&
    document.dig("metadata", "name") == "cdnca-control-api"
end
check(deployments.length == 1, "expected one control-api Deployment")
pod_spec = deployments.first.dig("spec", "template", "spec")
check(pod_spec.is_a?(Hash), "control-api pod spec is missing")

containers = Array(pod_spec["containers"]).select { |item| item["name"] == "control-api" }
check(containers.length == 1, "expected one control-api container")
container = containers.first

volumes = Array(pod_spec["volumes"]).select { |item| item["name"] == "plugin-webhook-nats" }
check(volumes.length == 1, "expected one plugin-webhook-nats volume")
projected = volumes.first["projected"]
check(projected.is_a?(Hash), "plugin-webhook-nats must be projected")
check(projected["defaultMode"] == 0o440, "plugin-webhook-nats defaultMode must be 0440")
actual_sources = Array(projected["sources"]).map do |source|
  check(source.keys == ["secret"], "plugin-webhook-nats sources must be Secrets")
  secret = source["secret"]
  items = Array(secret["items"])
  check(items.length == 1, "each plugin-webhook-nats Secret must expose one item")
  [secret["name"], items.first["key"], items.first["path"]]
end.sort
expected_sources = [
  ["cdnca-plugin-webhook-nats-ca", "root-ca.pem", "ca.crt"],
  ["cdnca-plugin-webhook-nats-credentials", "client.creds", "runtime.creds"],
]
check(actual_sources == expected_sources, "plugin-webhook-nats Secret refs do not match")

wrapping_volumes = Array(pod_spec["volumes"]).select { |item| item["name"] == "plugin-webhook-wrapping-key" }
check(wrapping_volumes.length == 1, "expected one plugin-webhook-wrapping-key volume")
wrapping_volume = wrapping_volumes.first
check(wrapping_volume.keys.sort == ["name", "secret"], "plugin-webhook-wrapping-key must be a Secret volume")
wrapping_secret = wrapping_volume["secret"]
check(wrapping_secret["secretName"] == "cdnca-plugin-webhook-wrapping-key", "wrapping-key Secret name does not match")
check(wrapping_secret["defaultMode"] == 0o440, "plugin-webhook-wrapping-key defaultMode must be 0440")
wrapping_items = Array(wrapping_secret["items"])
check(wrapping_items == [{"key" => "active.key", "path" => "wrapping.key"}], "wrapping-key Secret item does not match")

mounts = Array(container["volumeMounts"]).select { |item| item["name"] == "plugin-webhook-nats" }
check(mounts.length == 1, "expected one plugin-webhook-nats mount")
check(
  mounts.first["mountPath"] == "/var/run/secrets/cdnca/plugin-webhook-nats",
  "plugin-webhook-nats mount path does not match",
)
check(mounts.first["readOnly"] == true, "plugin-webhook-nats mount must be read-only")

wrapping_mounts = Array(container["volumeMounts"]).select { |item| item["name"] == "plugin-webhook-wrapping-key" }
check(wrapping_mounts.length == 1, "expected one plugin-webhook-wrapping-key mount")
check(
  wrapping_mounts.first == {
    "name" => "plugin-webhook-wrapping-key",
    "mountPath" => "/var/run/secrets/cdnca/plugin-webhook",
    "readOnly" => true,
  },
  "plugin-webhook-wrapping-key mount does not match",
)

expected_env = {
  "PLUGIN_WEBHOOK_RUNTIME_ENABLED" => "true",
  "PLUGIN_WEBHOOK_NATS_URL" => "tls://nats.plugin.svc.cluster.local:4222",
  "PLUGIN_WEBHOOK_REPLICAS" => "3",
  "PLUGIN_WEBHOOK_NATS_CREDS_FILE" => "/var/run/secrets/cdnca/plugin-webhook-nats/runtime.creds",
  "PLUGIN_WEBHOOK_NATS_CA_FILE" => "/var/run/secrets/cdnca/plugin-webhook-nats/ca.crt",
  "PLUGIN_WEBHOOK_NATS_NAME" => 'cdnca-plugin-webhook-runtime-$(POD_UID)',
  "PLUGIN_WEBHOOK_NATS_RECONNECT_MIN" => "1500ms",
  "PLUGIN_WEBHOOK_NATS_RECONNECT_MAX" => "2s",
  "PLUGIN_WEBHOOK_SECRET_KEY_ID" => "plugin-webhook-kek-v1",
  "PLUGIN_WEBHOOK_SECRET_KEY_FILE" => "/var/run/secrets/cdnca/plugin-webhook/wrapping.key",
  "PLUGIN_WEBHOOK_ATTESTATION_KEY_ID" => "plugin-webhook-runtime-attestation-v1",
  "PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE" => "/var/run/secrets/cdnca/plugin-webhook-attestation/attestation.pem",
}
env = Array(container["env"])
plugin_env = env.select { |item| item["name"].to_s.start_with?("PLUGIN_WEBHOOK_") }
check(plugin_env.length == expected_env.length, "plugin webhook env set does not match")
actual_env = {}
plugin_env.each do |item|
  name = item["name"]
  check(expected_env.key?(name), "unexpected plugin webhook env #{name}")
  check(item.keys.sort == ["name", "value"], "#{name} must use a non-secret scalar value")
  check(!actual_env.key?(name), "duplicate plugin webhook env #{name}")
  actual_env[name] = item["value"]
end
check(actual_env == expected_env, "plugin webhook env values do not match")
check(env.none? { |item| item["name"] == "PLUGIN_WEBHOOK_SECRET_KEY_BASE64" }, "wrapping key must not enter base64 env")

pod_uid = env.select { |item| item["name"] == "POD_UID" }
expected_pod_uid = {
  "name" => "POD_UID",
  "valueFrom" => {"fieldRef" => {"fieldPath" => "metadata.uid"}},
}
check(pod_uid == [expected_pod_uid], "POD_UID must use metadata.uid fieldRef")

secret_names = expected_sources.map(&:first) << wrapping_secret["secretName"]
secret_keys = expected_sources.map { |item| item[1] } << wrapping_items.first["key"]
env.each do |item|
  secret_ref = item.dig("valueFrom", "secretKeyRef")
  next unless secret_ref
  check(!secret_names.include?(secret_ref["name"]), "plugin Secret must not enter env")
  check(!secret_keys.include?(secret_ref["key"]), "plugin Secret key must not enter env")
end
Array(container["envFrom"]).each do |item|
  secret_ref = item["secretRef"]
  next unless secret_ref
  check(!secret_names.include?(secret_ref["name"]), "plugin Secret must not enter envFrom")
end
RUBY
}

expect_plugin_secret_refs_are_strings() {
  manifest=$1
  ruby - "$manifest" <<'RUBY'
require "yaml"

def check(condition, message)
  abort "FAIL: #{message}" unless condition
end

documents = YAML.load_stream(File.read(ARGV.fetch(0))).compact
deployment = documents.find do |document|
  document["kind"] == "Deployment" &&
    document.dig("metadata", "name") == "cdnca-control-api"
end
check(deployment, "control-api Deployment is missing from scalar Secret ref render")
volumes = Array(deployment.dig("spec", "template", "spec", "volumes"))
nats = volumes.find { |item| item["name"] == "plugin-webhook-nats" }
wrapping = volumes.find { |item| item["name"] == "plugin-webhook-wrapping-key" }
check(nats && wrapping, "plugin webhook Secret volumes are missing from scalar render")

sources = Array(nats.dig("projected", "sources"))
actual = sources.map do |source|
  secret = source["secret"]
  [secret["name"], secret.dig("items", 0, "key")]
end
actual << [wrapping.dig("secret", "secretName"), wrapping.dig("secret", "items", 0, "key")]
expected = [["123", "true"], ["false", "null"], ["456", "789"]]
check(actual == expected, "scalar-looking plugin Secret names and keys must remain strings")
RUBY
}

prepare_kubeconform_schemas() {
  if [ -n "${KUBECONFORM_SCHEMA_DIR:-}" ]; then
    SCHEMA_DIR=$KUBECONFORM_SCHEMA_DIR
    return
  fi
  require curl
  SCHEMA_DIR="$TMP_DIR/kubeconform-schemas"
  mkdir -p "$SCHEMA_DIR"
  schema_base=${KUBECONFORM_SCHEMA_BASE:-https://cdn.jsdelivr.net/gh/yannh/kubernetes-json-schema@987aa4ee419358d6ae108f54f6c42f4e90f22b70/v1.31.0-standalone-strict}
  for schema in \
    deployment-apps-v1 \
    service-v1 \
    ingress-networking-v1 \
    poddisruptionbudget-policy-v1 \
    horizontalpodautoscaler-autoscaling-v2 \
    job-batch-v1 \
    networkpolicy-networking-v1 \
    serviceaccount-v1 \
    persistentvolumeclaim-v1 \
    role-rbac-v1 \
    rolebinding-rbac-v1
  do
    curl -fsSL --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 1 \
      "$schema_base/$schema.json" -o "$SCHEMA_DIR/$schema.json"
  done
}

run_static() {
  require helm
  require kubeconform
  require ruby

  "$ROOT_DIR/scripts/helm-production-workloads-static.sh"

  echo "==> helm lint"
  helm lint "$CHART_DIR"
  helm lint "$CHART_DIR" -f "$CHART_DIR/values-development.yaml"
  helm lint "$CHART_DIR" -f "$CHART_DIR/values-ha.yaml"
  helm lint "$CHART_DIR" -f "$PRODUCTION_VALUES"

  echo "==> helm template"
  helm template cdnca "$CHART_DIR" --namespace cdnca >"$TMP_DIR/default.yaml"
  helm template cdnca "$CHART_DIR" --namespace cdnca \
    -f "$CHART_DIR/values-development.yaml" >"$TMP_DIR/development.yaml"
  helm template cdnca "$CHART_DIR" --namespace cdnca \
    -f "$CHART_DIR/values-ha.yaml" >"$TMP_DIR/ha.yaml"
  helm template cdnca "$CHART_DIR" --namespace cdnca \
    -f "$PRODUCTION_VALUES" >"$TMP_DIR/production.yaml"

  PLUGIN_WEBHOOK_VALUES="$TMP_DIR/plugin-webhook-values.yaml"
  cat >"$PLUGIN_WEBHOOK_VALUES" <<'EOF'
pluginWebhook:
  enabled: true
  wrappingKey:
    id: plugin-webhook-kek-v1
    secret:
      name: cdnca-plugin-webhook-wrapping-key
      key: active.key
  attestationKey:
    id: plugin-webhook-runtime-attestation-v1
    secret:
      name: cdnca-plugin-webhook-attestation-key
      key: attestation.pem
  nats:
    url: tls://nats.plugin.svc.cluster.local:4222
    credentialsSecret:
      name: cdnca-plugin-webhook-nats-credentials
      key: client.creds
    caSecret:
      name: cdnca-plugin-webhook-nats-ca
      key: root-ca.pem
    jetStreamReplicas: 3
    reconnect:
      min: 1500ms
      max: 2s
    egressCIDRs: [10.40.0.128/25]
EOF
  helm template cdnca "$CHART_DIR" --namespace cdnca \
    -f "$PRODUCTION_VALUES" -f "$PLUGIN_WEBHOOK_VALUES" >"$TMP_DIR/plugin-enabled.yaml"
  grep -q PLUGIN_WEBHOOK_ATTESTATION_NEXT "$TMP_DIR/plugin-enabled.yaml" &&
    fail "unstaged attestation key rendered NEXT variables"
  helm template cdnca "$CHART_DIR" --namespace cdnca \
    -f "$PRODUCTION_VALUES" -f "$PLUGIN_WEBHOOK_VALUES" \
    --set-string pluginWebhook.attestationKey.next.id=plugin-webhook-runtime-attestation-v2 \
    --set-string pluginWebhook.attestationKey.next.secret.name=cdnca-plugin-webhook-attestation-key-v2 \
    >"$TMP_DIR/plugin-attestation-next.yaml"
  for expected in 'name: PLUGIN_WEBHOOK_ATTESTATION_NEXT_KEY_ID' '"plugin-webhook-runtime-attestation-v2"' \
    '/var/run/secrets/cdnca/plugin-webhook-attestation-next/attestation.pem' \
    'secretName: "cdnca-plugin-webhook-attestation-key-v2"'; do
    grep -qF -- "$expected" "$TMP_DIR/plugin-attestation-next.yaml" || fail "staged attestation key render lacks $expected"
  done
  helm template cdnca "$CHART_DIR" --namespace cdnca \
    -f "$PRODUCTION_VALUES" -f "$PLUGIN_WEBHOOK_VALUES" \
    --set-string 'networkPolicy.controlExternalEgress.cidrs[0]=2001:db8::/32' \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=2001:db9:0:80::/57' \
    >"$TMP_DIR/plugin-enabled-ipv6.yaml"
  helm template cdnca "$CHART_DIR" --namespace cdnca \
    -f "$PRODUCTION_VALUES" -f "$PLUGIN_WEBHOOK_VALUES" \
    --set-string pluginWebhook.nats.credentialsSecret.name=123 \
    --set-string pluginWebhook.nats.credentialsSecret.key=true \
    --set-string pluginWebhook.nats.caSecret.name=false \
    --set-string pluginWebhook.nats.caSecret.key=null \
    --set-string pluginWebhook.wrappingKey.secret.name=456 \
    --set-string pluginWebhook.wrappingKey.secret.key=789 \
    >"$TMP_DIR/plugin-enabled-scalar-secret-refs.yaml"

  echo "==> kubeconform"
  prepare_kubeconform_schemas
  schema_location="$SCHEMA_DIR/{{.ResourceKind}}{{.KindSuffix}}.json"
  kubeconform -strict -summary -n 1 -schema-location "$schema_location" -kubernetes-version 1.31.0 "$TMP_DIR/default.yaml"
  kubeconform -strict -summary -n 1 -schema-location "$schema_location" -kubernetes-version 1.31.0 "$TMP_DIR/development.yaml"
  kubeconform -strict -summary -n 1 -schema-location "$schema_location" -kubernetes-version 1.31.0 "$TMP_DIR/ha.yaml"
  kubeconform -strict -summary -n 1 -schema-location "$schema_location" -kubernetes-version 1.31.0 "$TMP_DIR/production.yaml"
  kubeconform -strict -summary -n 1 -schema-location "$schema_location" -kubernetes-version 1.31.0 "$TMP_DIR/plugin-enabled.yaml"
  kubeconform -strict -summary -n 1 -schema-location "$schema_location" -kubernetes-version 1.31.0 "$TMP_DIR/plugin-enabled-ipv6.yaml"
  kubeconform -strict -summary -n 1 -schema-location "$schema_location" -kubernetes-version 1.31.0 "$TMP_DIR/plugin-enabled-scalar-secret-refs.yaml"

  echo "==> rendered policy checks"
  # Production enables the control upgrade runner (values-production.yaml
  # controlUpgradeRunner, docs/runbooks/control-plane-upgrade-runner.md): its
  # Deployment, two ServiceAccounts, RWO PVC and the runner / upgrade plan
  # writer Role+RoleBinding. agent-gateway-metrics is the correlation metrics
  # Service (docs/runbooks/edge-correlation-observability.md), the identity
  # verification issuer Service is IAM-10 (controlApi.identityVerification.issuer).
  expect_kind_count "$TMP_DIR/production.yaml" Deployment 4
  expect_kind_names "$TMP_DIR/production.yaml" Deployment \
    "cdnca-agent-gateway cdnca-control-api cdnca-control-upgrade-runner cdnca-web"
  expect_kind_count "$TMP_DIR/production.yaml" Service 5
  expect_kind_names "$TMP_DIR/production.yaml" Service \
    "cdnca-agent-gateway cdnca-agent-gateway-metrics cdnca-control-api cdnca-control-api-identity-verification-issuer cdnca-web"
  expect_kind_count "$TMP_DIR/production.yaml" Ingress 1
  expect_kind_count "$TMP_DIR/production.yaml" PodDisruptionBudget 3
  expect_kind_count "$TMP_DIR/production.yaml" HorizontalPodAutoscaler 3
  expect_kind_count "$TMP_DIR/production.yaml" Job 1
  expect_kind_count "$TMP_DIR/production.yaml" NetworkPolicy 4
  expect_kind_names "$TMP_DIR/production.yaml" NetworkPolicy \
    "cdnca-agent-gateway cdnca-agent-gateway-metrics cdnca-control-api cdnca-web"
  expect_kind_count "$TMP_DIR/production.yaml" ServiceAccount 5
  expect_kind_names "$TMP_DIR/production.yaml" ServiceAccount \
    "cdnca-agent-gateway cdnca-control-api cdnca-control-upgrade-runner cdnca-control-upgrade-runner-migration cdnca-web"
  expect_kind_count "$TMP_DIR/production.yaml" Secret 0
  expect_kind_count "$TMP_DIR/production.yaml" StatefulSet 0
  expect_kind_names "$TMP_DIR/production.yaml" PersistentVolumeClaim "cdnca-control-upgrade-runner"
  expect_kind_names "$TMP_DIR/production.yaml" Role "cdnca-control-api-upgrade-plan-writer cdnca-control-upgrade-runner"
  expect_kind_names "$TMP_DIR/production.yaml" RoleBinding "cdnca-control-api-upgrade-plan-writer cdnca-control-upgrade-runner"
  expect_kind_count "$TMP_DIR/production.yaml" ClusterRole 0
  expect_upgrade_rbac "$TMP_DIR/production.yaml"
  expect_at_least "$TMP_DIR/production.yaml" "automountServiceAccountToken: false" 10
  expect_at_least "$TMP_DIR/production.yaml" "allowPrivilegeEscalation: false" 5
  expect_at_least "$TMP_DIR/production.yaml" "readOnlyRootFilesystem: true" 5
  expect_at_least "$TMP_DIR/production.yaml" "runAsNonRoot: true" 10
  expect_at_least "$TMP_DIR/production.yaml" "startupProbe:" 3
  expect_at_least "$TMP_DIR/production.yaml" "readinessProbe:" 3
  expect_at_least "$TMP_DIR/production.yaml" "livenessProbe:" 3
  expect_at_least "$TMP_DIR/production.yaml" "secretKeyRef:" 20
  # external Secret changes roll by rolloutNonce, the chart never hashes
  # Secret material (docs/runbooks/kubernetes-control-plane.md step 3)
  expect_at_least "$TMP_DIR/production.yaml" "cdnca.io/secret-rollout:" 3
  expect_absent "$TMP_DIR/production.yaml" "checksum/external-secrets:"

  # PVC / Role / RoleBinding are allowed only by name (expect_kind_names above)
  if grep -Eq '^kind: (DaemonSet|StatefulSet|Secret|ClusterRole|ClusterRoleBinding)$' "$TMP_DIR/production.yaml"; then
    fail "chart rendered a forbidden stateful, credential, or RBAC resource"
  fi
  if grep -Eq '(^|[[:space:]])(privileged:[[:space:]]*true|hostNetwork:[[:space:]]*true|hostPID:[[:space:]]*true|hostIPC:[[:space:]]*true|hostPath:)' "$TMP_DIR/production.yaml"; then
    fail "chart rendered privileged or host-level access"
  fi
  if grep -Eq 'image:[[:space:]]*[^[:space:]]+:[Ll][Aa][Tt][Ee][Ss][Tt]([[:space:]]|$)' "$TMP_DIR/production.yaml"; then
    fail "chart rendered a latest image tag"
  fi
  if grep -Eq 'cidr:[[:space:]]*"?(0\.0\.0\.0/0|::/0)"?' "$TMP_DIR/production.yaml"; then
    fail "chart rendered an Internet-wide NetworkPolicy CIDR"
  fi
  # the upgrade runner is single-replica Recreate and has no HPA (runbook)
  pinned=$(awk '/^---/ { kind = ""; name = "" } /^kind: / { kind = $2 } kind != "" && name == "" && /^  name: / { name = $2 }
    /^  replicas:/ { print kind "/" name }' "$TMP_DIR/production.yaml" | tr '\n' ' ')
  [ "$pinned" = "Deployment/cdnca-control-upgrade-runner " ] ||
    fail "HPA-managed production Deployments must not pin spec.replicas (pinned: $pinned)"
  digest_images=$(awk '$1 == "image:" && index($2, "@sha256:") { count++ } END { print count + 0 }' "$TMP_DIR/production.yaml")
  [ "$digest_images" -eq 5 ] || fail "production render has $digest_images digest image references, want 5 including the migration and the upgrade runner"
  expect_at_least "$TMP_DIR/production.yaml" "args: [\"migrate\", \"up\"]" 1
  expect_at_least "$TMP_DIR/production.yaml" "helm.sh/hook: pre-install,pre-upgrade" 1
  expect_at_least "$TMP_DIR/production.yaml" "backoffLimit: 0" 1
  expect_absent "$TMP_DIR/production.yaml" "initContainers:"
  # cdncaCE ships no license service or operator console workloads.
  for manifest in "$TMP_DIR/default.yaml" "$TMP_DIR/development.yaml" "$TMP_DIR/ha.yaml" "$TMP_DIR/production.yaml"; do
    expect_absent "$manifest" "license-service"
    expect_absent "$manifest" "operator-console"
    expect_absent "$manifest" "LICENSE_MIGRATION_DATABASE_URL"
    expect_absent "$manifest" "LICENSE_RUNTIME_DATABASE_ROLE"
    expect_at_least "$manifest" "name: ENTITLEMENT_TRUSTED_KEYS_FILE" 1
    expect_at_least "$manifest" "name: CONTROL_INSTALLATION_PRIVATE_KEY_FILE" 1
  done
  # control-api talks to an external license service: the URL is configurable
  # and omitted when empty (default and development overlays).
  expect_absent "$TMP_DIR/default.yaml" "name: LICENSE_SERVICE_URL"
  expect_absent "$TMP_DIR/development.yaml" "name: LICENSE_SERVICE_URL"
  expect_at_least "$TMP_DIR/production.yaml" "value: \"https://license.example.invalid\"" 1
  expect_at_least "$TMP_DIR/ha.yaml" "value: \"https://license.example.invalid\"" 1
  expect_ingress_path_backend "$TMP_DIR/production.yaml" "/v1" "cdnca-control-api"
  expect_ingress_path_backend "$TMP_DIR/ha.yaml" "/v1" "cdnca-control-api"

  expect_package_commerce_wiring "$TMP_DIR/default.yaml" false false
  expect_package_commerce_wiring "$TMP_DIR/development.yaml" false false
  expect_package_commerce_wiring "$TMP_DIR/ha.yaml" false false
  expect_package_commerce_wiring "$TMP_DIR/production.yaml" true true
  expect_absent "$TMP_DIR/production.yaml" "VITE_PACKAGE_COMMERCE"

  for manifest in "$TMP_DIR/default.yaml" "$TMP_DIR/development.yaml" "$TMP_DIR/ha.yaml" "$TMP_DIR/production.yaml"; do
    expect_absent "$manifest" "PLUGIN_WEBHOOK_"
    expect_absent "$manifest" "plugin-webhook-nats"
    expect_absent "$manifest" "plugin-webhook-wrapping-key"
  done
  expect_kind_count "$TMP_DIR/plugin-enabled.yaml" Secret 0
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_RUNTIME_ENABLED" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_NATS_CREDS_FILE" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_NATS_CA_FILE" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: POD_UID" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "fieldPath: metadata.uid" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_NATS_NAME" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_NATS_RECONNECT_MIN" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_NATS_RECONNECT_MAX" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_SECRET_KEY_ID" 1
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "name: PLUGIN_WEBHOOK_SECRET_KEY_FILE" 1
  expect_absent "$TMP_DIR/plugin-enabled.yaml" "PLUGIN_WEBHOOK_SECRET_KEY_BASE64"
  expect_at_least "$TMP_DIR/plugin-enabled.yaml" "value: cdnca-plugin-webhook-runtime-\$(POD_UID)" 1
  expect_absent "$TMP_DIR/plugin-enabled.yaml" "cdnca-plugin-webhook-runtime/\$(POD_UID)"
  expect_plugin_wiring "$TMP_DIR/plugin-enabled.yaml"
  expect_plugin_secret_refs_are_strings "$TMP_DIR/plugin-enabled-scalar-secret-refs.yaml"
  expect_cidr_ports "$TMP_DIR/plugin-enabled.yaml" "10.40.0.128/25" "4222"
  expect_cidr_ports "$TMP_DIR/plugin-enabled-ipv6.yaml" "2001:db9:0:80::/57" "4222"

  echo "==> schema and semantic rejection checks"
  expect_template_failure "latest image tag" --set-string controlApi.image.tag=latest
  for component in controlApi agentGateway web; do
    expect_template_failure "production $component without immutable digest" \
      -f "$PRODUCTION_VALUES" --set-string "$component.image.digest="
  done
  expect_template_failure "production without Metrics Server attestation" \
    -f "$PRODUCTION_VALUES" --set production.metricsServerAvailable=false
  expect_template_failure "production without PostgreSQL egress" \
    -f "$PRODUCTION_VALUES" --set-json 'networkPolicy.dataStores.postgresql.cidrs=[]'
  expect_template_failure "Internet-wide egress" --set-string 'networkPolicy.controlExternalEgress.cidrs[0]=0.0.0.0/0'
  expect_template_failure "LoadBalancer without source ranges" --set-string agentGateway.service.type=LoadBalancer
  expect_template_failure "PDB above minimum replicas" --set controlApi.pdb.minAvailable=2
  expect_template_failure "colliding control-api ports" --set controlApi.service.internalGRPCPort=8080

  expect_package_commerce_failure "package commerce HTTP without worker" \
    --set controlApi.packageCommerce.worker.enabled=false
  expect_package_commerce_failure "package commerce worker without control-api" \
    --set controlApi.enabled=false
  expect_package_commerce_failure "package commerce worker missing NATS URL" \
    --set-string controlApi.packageCommerce.worker.nats.url=
  expect_package_commerce_failure "package commerce worker non-TLS NATS URL" \
    --set-string controlApi.packageCommerce.worker.nats.url=nats://nats.package-commerce.svc.cluster.local:4222
  expect_package_commerce_failure "package commerce worker NATS IP literal" \
    --set-string controlApi.packageCommerce.worker.nats.url=tls://10.20.0.10:4222
  expect_package_commerce_failure "package commerce worker NATS userinfo" \
    --set-string controlApi.packageCommerce.worker.nats.url=tls://user@nats.package-commerce.svc.cluster.local:4222
  expect_package_commerce_failure "package commerce worker missing credentials Secret" \
    --set-string controlApi.packageCommerce.worker.nats.credentialsSecret.existingSecret=
  expect_package_commerce_failure "package commerce worker missing CA Secret" \
    --set-string controlApi.packageCommerce.worker.nats.caSecret.existingSecret=
  expect_package_commerce_failure "package commerce worker invalid stream" \
    --set-string controlApi.packageCommerce.worker.nats.stream=package-commerce
  expect_package_commerce_failure "package commerce worker invalid credentials Secret key" \
    --set-string controlApi.packageCommerce.worker.nats.credentialsSecret.key=nested/runtime.creds

  expect_package_commerce_failure "template-level package commerce HTTP without worker" --skip-schema-validation \
    --set controlApi.packageCommerce.worker.enabled=false
  expect_package_commerce_failure "template-level package commerce worker missing NATS URL" --skip-schema-validation \
    --set-string controlApi.packageCommerce.worker.nats.url=
  expect_package_commerce_failure "template-level package commerce worker missing credentials Secret" --skip-schema-validation \
    --set-string controlApi.packageCommerce.worker.nats.credentialsSecret.existingSecret=
  expect_package_commerce_failure "template-level package commerce worker invalid CA Secret key" --skip-schema-validation \
    --set-string controlApi.packageCommerce.worker.nats.caSecret.key=nested/ca.crt

  expect_plugin_failure "enabled missing NATS URL" \
    --set-string pluginWebhook.nats.url=
  expect_plugin_failure "enabled missing wrapping-key ID" \
    --set-string pluginWebhook.wrappingKey.id=
  expect_plugin_failure "enabled missing attestation-key ID" --skip-schema-validation \
    --set-string pluginWebhook.attestationKey.id=
  grep -q 'pluginWebhook.attestationKey.id is required' "$TMP_DIR/rejected.err" ||
    fail "missing attestation-key ID did not explain itself"
  expect_plugin_failure "enabled missing attestation-key Secret" --skip-schema-validation \
    --set-string pluginWebhook.attestationKey.secret.name=
  grep -q 'pluginWebhook.attestationKey.secret.name is required' "$TMP_DIR/rejected.err" ||
    fail "missing attestation-key Secret did not explain itself"
  expect_plugin_failure "staged attestation key reusing the current ID" \
    --set-string pluginWebhook.attestationKey.next.id=plugin-webhook-runtime-attestation-v1 \
    --set-string pluginWebhook.attestationKey.next.secret.name=cdnca-plugin-webhook-attestation-key-v2
  expect_plugin_failure "staged attestation key without a Secret" \
    --set-string pluginWebhook.attestationKey.next.id=plugin-webhook-runtime-attestation-v2
  expect_plugin_failure "invalid wrapping-key ID" \
    --set-string 'pluginWebhook.wrappingKey.id=invalid key'
  expect_plugin_failure "enabled missing wrapping-key Secret name" \
    --set-string pluginWebhook.wrappingKey.secret.name=
  expect_plugin_failure "enabled missing wrapping-key Secret key" \
    --set-string pluginWebhook.wrappingKey.secret.key=
  expect_plugin_failure "invalid wrapping-key Secret key" \
    --set-string pluginWebhook.wrappingKey.secret.key=nested/wrapping.key
  expect_plugin_failure "enabled missing credentials Secret name" \
    --set-string pluginWebhook.nats.credentialsSecret.name=
  expect_plugin_failure "enabled missing credentials Secret key" \
    --set-string pluginWebhook.nats.credentialsSecret.key=
  expect_plugin_failure "enabled missing CA Secret name" \
    --set-string pluginWebhook.nats.caSecret.name=
  expect_plugin_failure "enabled missing CA Secret key" \
    --set-string pluginWebhook.nats.caSecret.key=
  expect_plugin_failure "production JetStream replicas other than 3" \
    --set pluginWebhook.nats.jetStreamReplicas=2
  expect_plugin_failure "enabled missing dedicated NATS egress CIDR" \
    --set-json 'pluginWebhook.nats.egressCIDRs=[]'
  expect_plugin_failure "same IPv4 shared/plugin CIDR" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=10.20.0.0/24'
  expect_plugin_failure "plugin IPv4 subnet inside shared CIDR" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=10.20.0.128/25'
  expect_plugin_failure "shared IPv4 subnet inside plugin CIDR" \
    --set-string 'networkPolicy.controlExternalEgress.cidrs[0]=10.20.0.128/25' \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=10.20.0.0/24'
  expect_plugin_failure "plugin IPv6 subnet inside shared CIDR" \
    --set-string 'networkPolicy.controlExternalEgress.cidrs[0]=2001:db8::/32' \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=2001:db8:1::/48'
  expect_plugin_failure "shared IPv6 subnet inside plugin CIDR" \
    --set-string 'networkPolicy.controlExternalEgress.cidrs[0]=2001:db8:1::/48' \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=2001:db8::/32'
  expect_plugin_failure "duplicate plugin CIDR" \
    --set-string 'pluginWebhook.nats.egressCIDRs[1]=10.40.0.128/25'
  expect_plugin_failure "overlapping plugin CIDRs" \
    --set-string 'pluginWebhook.nats.egressCIDRs[1]=10.40.0.128/26'
  expect_plugin_failure "IPv4 CIDR host bits" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=10.40.0.129/25'
  expect_plugin_failure "IPv6 CIDR host bits" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=2001:db9::1/64'
  expect_plugin_failure "IPv6 partial-prefix host bits" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=2001:db9:0:81::/57'
  expect_plugin_failure "non-canonical IPv6 leading zero" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=2001:0db9::/32'
  expect_plugin_failure "non-canonical IPv6 zero compression" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=2001:db9:0:0:0:0:0:0/32'
  expect_plugin_failure "invalid plugin CIDR" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=not-a-cidr'
  expect_plugin_failure "IPv4 CIDR octet out of range" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=999.40.0.0/24'
  expect_plugin_failure "non-canonical IPv4 leading zero" \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=010.40.0.0/24'
  expect_plugin_failure "reconnect min above max" \
    --set-string pluginWebhook.nats.reconnect.min=2s \
    --set-string pluginWebhook.nats.reconnect.max=1500ms
  expect_plugin_failure "zero reconnect duration" \
    --set-string pluginWebhook.nats.reconnect.min=0ms
  expect_plugin_failure "reconnect duration above 5m" \
    --set-string pluginWebhook.nats.reconnect.max=300001ms
  expect_plugin_failure "reconnect duration overflow" \
    --set-string pluginWebhook.nats.reconnect.max=999999999999999999999999999999999999m

  long_label=$(awk 'BEGIN { for (i = 0; i < 63; i++) printf "a" }')
  long_host="$long_label.$long_label.$long_label.$long_label"
  long_nats_label="${long_label}a"
  long_key_id=$(awk 'BEGIN { for (i = 0; i < 129; i++) printf "a" }')
  long_secret_key=$(awk 'BEGIN { for (i = 0; i < 254; i++) printf "a" }')
  expect_plugin_failure "wrapping-key ID above 128 bytes" \
    --set-string "pluginWebhook.wrappingKey.id=$long_key_id"
  expect_plugin_failure "invalid wrapping-key Secret name" \
    --set-string pluginWebhook.wrappingKey.secret.name=INVALID_secret
  expect_plugin_failure "wrapping-key Secret DNS name above 253 bytes" \
    --set-string "pluginWebhook.wrappingKey.secret.name=$long_host"
  expect_plugin_failure "wrapping-key Secret key above 253 bytes" \
    --set-string "pluginWebhook.wrappingKey.secret.key=$long_secret_key"
  expect_plugin_failure "invalid credentials Secret name" \
    --set-string pluginWebhook.nats.credentialsSecret.name=INVALID_secret
  expect_plugin_failure "invalid CA Secret name" \
    --set-string pluginWebhook.nats.caSecret.name=-invalid
  expect_plugin_failure "Secret DNS label above 63 bytes" \
    --set-string pluginWebhook.nats.credentialsSecret.name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  expect_plugin_failure "Secret DNS name above 253 bytes" \
    --set-string "pluginWebhook.nats.credentialsSecret.name=$long_host"

  expect_plugin_failure "NATS DNS host above 253 bytes" \
    --set-string "pluginWebhook.nats.url=tls://$long_host:4222"
  expect_plugin_failure "NATS DNS label above 63 bytes" \
    --set-string "pluginWebhook.nats.url=tls://$long_nats_label.example:4222"
  expect_plugin_failure "NATS URL userinfo" \
    --set-string pluginWebhook.nats.url=tls://user@nats.plugin.svc.cluster.local:4222
  expect_plugin_failure "NATS URL query" \
    --set-string 'pluginWebhook.nats.url=tls://nats.plugin.svc.cluster.local:4222?x=1'
  expect_plugin_failure "NATS URL path" \
    --set-string pluginWebhook.nats.url=tls://nats.plugin.svc.cluster.local:4222/path
  expect_plugin_failure "NATS URL fragment" \
    --set-string 'pluginWebhook.nats.url=tls://nats.plugin.svc.cluster.local:4222#x'
  expect_plugin_failure "NATS URL list" \
    --set-string 'pluginWebhook.nats.url=tls://nats.one.local:4222\,tls://nats.two.local:4222'
  expect_plugin_failure "NATS URL IP literal" \
    --set-string pluginWebhook.nats.url=tls://10.40.0.10:4222
  expect_plugin_failure "NATS URL localhost" \
    --set-string pluginWebhook.nats.url=tls://localhost:4222
  expect_plugin_failure "NATS URL uppercase" \
    --set-string pluginWebhook.nats.url=tls://NATS.plugin.svc.cluster.local:4222
  expect_plugin_failure "NATS URL wrong port" \
    --set-string pluginWebhook.nats.url=tls://nats.plugin.svc.cluster.local:4223

  expect_plugin_failure "template-level invalid CIDR" --skip-schema-validation \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=not-a-cidr'
  expect_plugin_failure "template-level non-canonical IPv4 CIDR" --skip-schema-validation \
    --set-string 'pluginWebhook.nats.egressCIDRs[0]=010.40.0.0/24'
  expect_plugin_failure "template-level duplicate CIDR" --skip-schema-validation \
    --set-string 'pluginWebhook.nats.egressCIDRs[1]=10.40.0.128/25'
  expect_plugin_failure "template-level reconnect overflow" --skip-schema-validation \
    --set-string pluginWebhook.nats.reconnect.max=999999999999999999999999999999999999m
  expect_plugin_failure "template-level invalid Secret name" --skip-schema-validation \
    --set-string pluginWebhook.nats.credentialsSecret.name=INVALID_secret
  expect_plugin_failure "template-level overlong Secret name" --skip-schema-validation \
    --set-string "pluginWebhook.nats.credentialsSecret.name=$long_host"
  expect_plugin_failure "template-level overlong NATS host" --skip-schema-validation \
    --set-string "pluginWebhook.nats.url=tls://$long_host:4222"
  expect_plugin_failure "template-level missing wrapping-key ID" --skip-schema-validation \
    --set-string pluginWebhook.wrappingKey.id=
  expect_plugin_failure "template-level invalid wrapping-key ID" --skip-schema-validation \
    --set-string 'pluginWebhook.wrappingKey.id=invalid key'
  expect_plugin_failure "template-level overlong wrapping-key ID" --skip-schema-validation \
    --set-string "pluginWebhook.wrappingKey.id=$long_key_id"
  expect_plugin_failure "template-level missing wrapping-key Secret name" --skip-schema-validation \
    --set-string pluginWebhook.wrappingKey.secret.name=
  expect_plugin_failure "template-level invalid wrapping-key Secret name" --skip-schema-validation \
    --set-string pluginWebhook.wrappingKey.secret.name=INVALID_secret
  expect_plugin_failure "template-level overlong wrapping-key Secret name" --skip-schema-validation \
    --set-string "pluginWebhook.wrappingKey.secret.name=$long_host"
  expect_plugin_failure "template-level missing wrapping-key Secret key" --skip-schema-validation \
    --set-string pluginWebhook.wrappingKey.secret.key=
  expect_plugin_failure "template-level invalid wrapping-key Secret key" --skip-schema-validation \
    --set-string pluginWebhook.wrappingKey.secret.key=nested/wrapping.key
  expect_plugin_failure "template-level overlong wrapping-key Secret key" --skip-schema-validation \
    --set-string "pluginWebhook.wrappingKey.secret.key=$long_secret_key"
  expect_plugin_failure "template-level invalid credentials Secret key" --skip-schema-validation \
    --set-string pluginWebhook.nats.credentialsSecret.key=nested/runtime.creds
  expect_plugin_failure "template-level overlong credentials Secret key" --skip-schema-validation \
    --set-string "pluginWebhook.nats.credentialsSecret.key=$long_secret_key"
  expect_plugin_failure "template-level invalid CA Secret key" --skip-schema-validation \
    --set-string pluginWebhook.nats.caSecret.key=nested/ca.crt
  expect_plugin_failure "template-level overlong CA Secret key" --skip-schema-validation \
    --set-string "pluginWebhook.nats.caSecret.key=$long_secret_key"

  echo "Static Helm acceptance passed."
}

select_cluster_driver() {
  if command -v kind >/dev/null 2>&1; then
    CLUSTER_DRIVER=kind
  elif command -v k3d >/dev/null 2>&1; then
    CLUSTER_DRIVER=k3d
  else
    return 1
  fi
}

build_smoke_image() {
  require docker
  require go
  cat >"$TMP_DIR/main.go" <<'EOF'
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	addresses := []string{}
	for _, key := range []string{
		"HTTP_ADDR", "CONTROL_INTERNAL_GRPC_ADDR", "CDNCA_GATEWAY_ENROLLMENT_ADDR",
		"CDNCA_GATEWAY_AGENT_ADDR", "CDNCA_GATEWAY_HEALTH_ADDR",
	} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			addresses = append(addresses, value)
		}
	}
	if len(addresses) == 0 {
		addresses = append(addresses, ":8080")
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte(`{"status":"ok"}`))
	})
	errors := make(chan error, len(addresses))
	for _, address := range addresses {
		go func(listenAddress string) {
			errors <- http.ListenAndServe(listenAddress, handler)
		}(address)
	}
	if err := <-errors; err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
EOF
  cat >"$TMP_DIR/Dockerfile" <<'EOF'
FROM scratch
USER 65532:65532
COPY smoke-server /smoke-server
ENTRYPOINT ["/smoke-server"]
EOF
  CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o "$TMP_DIR/smoke-server" "$TMP_DIR/main.go"
  docker build -q -t "$CLUSTER_NAME:task" "$TMP_DIR" >/dev/null
}

create_cluster() {
  ORIGINAL_CONTEXT=$(kubectl config current-context 2>/dev/null || true)
  if [ "$CLUSTER_DRIVER" = kind ]; then
    kind create cluster --name "$CLUSTER_NAME" --wait 180s
    CLUSTER_CREATED=true
    kind load docker-image "$CLUSTER_NAME:task" --name "$CLUSTER_NAME"
  else
    k3d cluster create "$CLUSTER_NAME" --agents 1 --wait --timeout 180s
    CLUSTER_CREATED=true
    k3d image import "$CLUSTER_NAME:task" --cluster "$CLUSTER_NAME"
  fi
}

create_smoke_secrets() {
  namespace=$1
  kubectl -n "$namespace" create secret generic cdnca-customer-datastores \
    --from-literal=database-url=postgres://smoke.invalid/control \
    --from-literal=redis-url=redis://smoke.invalid:6379 \
    --from-literal=nats-url=nats://smoke.invalid:4222 \
    --from-literal=clickhouse-url=http://smoke.invalid:8123 >/dev/null
  kubectl -n "$namespace" create secret generic cdnca-control-api-runtime \
    --from-literal=access-token-secret=smoke-access-token-secret-32-bytes \
    --from-literal=api-key-pepper-base64=c21va2UtcGVwcGVy \
    --from-literal=dns-credential-key-id=smoke-dns \
    --from-literal=dns-credential-key-base64=c21va2UtZG5zLWtleQ== \
    --from-literal=entitlement-trusted-keys.json='{}' \
    --from-literal=installation-id=00000000-0000-0000-0000-000000000001 \
    --from-literal=installation-private-key.pem=smoke \
    --from-literal=activation-credential=smoke \
    --from-literal=control-server.crt=smoke \
    --from-literal=control-server.key=smoke \
    --from-literal=gateway-client-ca.crt=smoke \
    --from-literal=node-ca-chain.crt=smoke \
    --from-literal=node-ca.key=smoke \
    --from-literal=package-commerce-cursor-key-base64=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= >/dev/null
  kubectl -n "$namespace" create secret generic cdnca-package-commerce-nats-credentials \
    --from-literal=runtime.creds=smoke >/dev/null
  kubectl -n "$namespace" create secret generic cdnca-package-commerce-nats-ca \
    --from-literal=ca.crt=smoke >/dev/null
  kubectl -n "$namespace" create secret generic cdnca-agent-gateway-runtime \
    --from-literal=tls.crt=smoke \
    --from-literal=tls.key=smoke \
    --from-literal=agent-client-ca.crt=smoke \
    --from-literal=control-client.crt=smoke \
    --from-literal=control-client.key=smoke \
    --from-literal=control-server-ca.crt=smoke >/dev/null
}

write_cluster_values() {
  cat >"$TMP_DIR/cluster-values.yaml" <<EOF
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
networkPolicy:
  gatewaySourceCIDRs: []
  controlExternalEgress: {cidrs: []}
  gatewayExternalEgress: {cidrs: []}
customerIngress: {enabled: false}
controlApi:
  image: {repository: $CLUSTER_NAME, tag: task, digest: "", pullPolicy: IfNotPresent}
  migrations: {enabled: false}
  resources: &serviceResources
    requests: {cpu: 10m, memory: 16Mi}
    limits: {cpu: 100m, memory: 64Mi}
agentGateway:
  image: {repository: $CLUSTER_NAME, tag: task, digest: "", pullPolicy: IfNotPresent}
  service:
    type: ClusterIP
    externalTrafficPolicy: Cluster
    loadBalancerSourceRanges: []
  resources: *serviceResources
web:
  image: {repository: $CLUSTER_NAME, tag: task, digest: "", pullPolicy: IfNotPresent}
  resources: &frontendResources
    requests: {cpu: 5m, memory: 8Mi}
    limits: {cpu: 50m, memory: 32Mi}
EOF
}

wait_for_workloads() {
  namespace=$1
  for component in control-api agent-gateway web; do
    kubectl -n "$namespace" rollout status "deployment/cdnca-smoke-$component" --timeout=300s
  done
}

run_cluster() {
  require helm
  require kubectl
  select_cluster_driver || {
    echo "SKIP: neither kind nor k3d is installed; real-cluster smoke was not run." >&2
    [ "$MODE" = "--cluster" ] && exit 2
    return 0
  }

  echo "==> task-owned $CLUSTER_DRIVER cluster"
  build_smoke_image
  create_cluster
  namespace=cdnca-smoke
  kubectl create namespace "$namespace" >/dev/null
  kubectl label namespace "$namespace" \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/enforce-version=latest >/dev/null
  create_smoke_secrets "$namespace"
  write_cluster_values

  echo "==> install and readiness"
  helm upgrade --install cdnca-smoke "$CHART_DIR" \
    --namespace "$namespace" \
    -f "$PRODUCTION_VALUES" \
    -f "$TMP_DIR/cluster-values.yaml" \
    --wait --timeout 8m
  wait_for_workloads "$namespace"

  [ "$(kubectl -n "$namespace" get deployment -o name | wc -l | tr -d ' ')" -eq 3 ] || fail "cluster does not have three Deployments"
  [ "$(kubectl -n "$namespace" get serviceaccount -l app.kubernetes.io/instance=cdnca-smoke -o name | wc -l | tr -d ' ')" -eq 3 ] || fail "cluster does not have three workload ServiceAccounts"
  [ "$(kubectl -n "$namespace" get pdb -o name | wc -l | tr -d ' ')" -eq 3 ] || fail "cluster does not have three PDBs"
  [ "$(kubectl -n "$namespace" get hpa -o name | wc -l | tr -d ' ')" -eq 3 ] || fail "cluster does not have three HPAs"
  [ "$(kubectl -n "$namespace" get networkpolicy -o name | wc -l | tr -d ' ')" -eq 3 ] || fail "cluster does not have three NetworkPolicies"

  for pdb in $(kubectl -n "$namespace" get pdb -o name); do
    disruptions=$(kubectl -n "$namespace" get "$pdb" -o jsonpath='{.status.disruptionsAllowed}')
    [ "${disruptions:-0}" -ge 1 ] || fail "$pdb has no allowed voluntary disruption"
  done

  echo "==> rolling update"
  before_hash=$(kubectl -n "$namespace" get pods -l app.kubernetes.io/component=control-api -o jsonpath='{.items[0].metadata.labels.pod-template-hash}')
  helm upgrade cdnca-smoke "$CHART_DIR" \
    --namespace "$namespace" \
    -f "$PRODUCTION_VALUES" \
    -f "$TMP_DIR/cluster-values.yaml" \
    --set-string controlApi.rolloutNonce=smoke-rollout \
    --set-string agentGateway.rolloutNonce=smoke-rollout \
    --set-string web.rolloutNonce=smoke-rollout \
    --wait --timeout 8m
  wait_for_workloads "$namespace"
  after_hash=$(kubectl -n "$namespace" get pods -l app.kubernetes.io/component=control-api -o jsonpath='{.items[0].metadata.labels.pod-template-hash}')
  [ "$before_hash" != "$after_hash" ] || fail "control-api pod template hash did not change"

  echo "==> delete one Pod and recover"
  victim=$(kubectl -n "$namespace" get pods -l app.kubernetes.io/component=control-api -o jsonpath='{.items[0].metadata.name}')
  victim_uid=$(kubectl -n "$namespace" get pod "$victim" -o jsonpath='{.metadata.uid}')
  kubectl -n "$namespace" delete pod "$victim" --wait=true >/dev/null
  kubectl -n "$namespace" rollout status deployment/cdnca-smoke-control-api --timeout=300s
  if kubectl -n "$namespace" get pods -l app.kubernetes.io/component=control-api -o jsonpath='{range .items[*]}{.metadata.uid}{"\n"}{end}' | grep -Fqx "$victim_uid"; then
    fail "deleted control-api Pod UID is still present"
  fi

  kubectl -n "$namespace" get deployment,pod,pdb,hpa,service,networkpolicy
  echo "Real-cluster Helm acceptance passed on $CLUSTER_DRIVER."
}

case "$MODE" in
  --static)
    run_static
    ;;
  --cluster)
    run_cluster
    ;;
  --all)
    run_static
    run_cluster
    ;;
  *)
    usage
    ;;
esac
