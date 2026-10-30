#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
chart_dir="$repo_dir/infra/helm/cdnca"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-traffic-package-session.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

command -v helm >/dev/null 2>&1 || {
  echo "helm is required" >&2
  exit 1
}
command -v ruby >/dev/null 2>&1 || {
  echo "ruby is required" >&2
  exit 1
}

helm lint "$chart_dir" >/dev/null
helm lint "$chart_dir" -f "$chart_dir/values-production.yaml" >/dev/null
helm lint "$chart_dir" \
  --set controlApi.trafficPackage.workload.enabled=true \
  --set controlApi.trafficPackage.cursorKeySecret.existingSecret=cdnca-traffic-package-cursor \
  --set controlApi.trafficPackage.workload.mtlsSecret.existingSecret=cdnca-traffic-package-mtls >/dev/null
helm lint "$chart_dir" \
  --set controlApi.trafficPackage.enabled=true \
  --set controlApi.trafficPackage.workload.enabled=true \
  --set controlApi.trafficPackage.cursorKeySecret.existingSecret=cdnca-traffic-package-cursor \
  --set controlApi.trafficPackage.workload.mtlsSecret.existingSecret=cdnca-traffic-package-mtls >/dev/null
helm template traffic-package-default "$chart_dir" >"$tmp_dir/default.yaml"
helm template traffic-package-production "$chart_dir" \
  -f "$chart_dir/values-production.yaml" >"$tmp_dir/production.yaml"
helm template traffic-package-workload "$chart_dir" \
  --set controlApi.trafficPackage.workload.enabled=true \
  --set controlApi.trafficPackage.cursorKeySecret.existingSecret=cdnca-traffic-package-cursor \
  --set controlApi.trafficPackage.workload.mtlsSecret.existingSecret=cdnca-traffic-package-mtls \
  >"$tmp_dir/workload.yaml"
helm template traffic-package-both "$chart_dir" \
  --set controlApi.trafficPackage.enabled=true \
  --set controlApi.trafficPackage.workload.enabled=true \
  --set controlApi.trafficPackage.cursorKeySecret.existingSecret=cdnca-traffic-package-cursor \
  --set controlApi.trafficPackage.workload.mtlsSecret.existingSecret=cdnca-traffic-package-mtls \
  >"$tmp_dir/both.yaml"

expect_template_failure() {
  name=$1
  shift
  if helm template "$name" "$chart_dir" "$@" >"$tmp_dir/$name.out" 2>"$tmp_dir/$name.err"; then
    echo "FAIL: $name unexpectedly rendered" >&2
    exit 1
  fi
}

expect_template_failure traffic-package-missing-cursor \
  --set controlApi.trafficPackage.enabled=true
expect_template_failure traffic-package-missing-mtls \
  --set controlApi.trafficPackage.workload.enabled=true \
  --set controlApi.trafficPackage.cursorKeySecret.existingSecret=cdnca-traffic-package-cursor
expect_template_failure traffic-package-port-collision \
  --set controlApi.trafficPackage.workload.enabled=true \
  --set controlApi.trafficPackage.workload.port=8080 \
  --set controlApi.trafficPackage.cursorKeySecret.existingSecret=cdnca-traffic-package-cursor \
  --set controlApi.trafficPackage.workload.mtlsSecret.existingSecret=cdnca-traffic-package-mtls

ruby - "$tmp_dir/default.yaml" "$tmp_dir/production.yaml" \
  "$tmp_dir/workload.yaml" "$tmp_dir/both.yaml" <<'RUBY'
require "yaml"

def check(condition, message)
  abort "FAIL: #{message}" unless condition
end

def documents(path)
  YAML.load_stream(File.read(path)).compact
end

def assert_shape(path, session_enabled, workload_enabled)
  manifests = documents(path)
  control = manifests.find do |document|
    document["kind"] == "Deployment" &&
      document.dig("metadata", "labels", "app.kubernetes.io/component") == "control-api"
  end
  check(control, "control-api Deployment missing from #{path}")
  container = Array(control.dig("spec", "template", "spec", "containers")).find do |item|
    item["name"] == "control-api"
  end
  check(container, "control-api container missing from #{path}")
  environment = Array(container["env"]).to_h { |entry| [entry["name"], entry] }
  check(environment.dig("TRAFFIC_PACKAGE_RUNTIME_ENABLED", "value") == session_enabled,
    "session flag mismatch in #{path}")
  check(environment.dig("TRAFFIC_PACKAGE_WORKLOAD_RUNTIME_ENABLED", "value") == workload_enabled,
    "workload flag mismatch in #{path}")

  cursor = environment["TRAFFIC_PACKAGE_CURSOR_KEY_BASE64"]
  if session_enabled == "true" || workload_enabled == "true"
    expected_cursor_secret = path.end_with?("production.yaml") ?
      "cdnca-control-api-traffic-package" : "cdnca-traffic-package-cursor"
    check(cursor&.dig("valueFrom", "secretKeyRef", "name") == expected_cursor_secret,
      "cursor Secret name mismatch")
    check(cursor&.dig("valueFrom", "secretKeyRef", "key") == "cursor-key-base64",
      "cursor Secret key mismatch")
    check(!cursor.key?("value"), "cursor must not use a literal value")
  else
    check(cursor.nil?, "disabled runtime must not render a cursor key")
  end

  workload_port = Array(container["ports"]).find { |port| port["name"] == "traffic-package" }
  workload_mount = Array(container["volumeMounts"]).find { |mount| mount["name"] == "traffic-package-workload" }
  volumes = Array(control.dig("spec", "template", "spec", "volumes"))
  workload_volume = volumes.find { |volume| volume["name"] == "traffic-package-workload" }
  services = manifests.select do |document|
    document["kind"] == "Service" &&
      document.dig("metadata", "name").to_s.end_with?("-traffic-package-workload")
  end
  if workload_enabled == "true"
    check(environment.dig("TRAFFIC_PACKAGE_WORKLOAD_MTLS_LISTEN_ADDR", "value") == "0.0.0.0:9544",
      "workload listen address mismatch in #{path}")
    check(environment.dig("TRAFFIC_PACKAGE_WORKLOAD_MTLS_SERVER_CERT_FILE", "value") ==
      "/var/run/secrets/cdnca/traffic-package-workload/server.crt", "workload certificate path mismatch")
    check(environment.dig("TRAFFIC_PACKAGE_WORKLOAD_MTLS_SERVER_PRIVATE_KEY_FILE", "value") ==
      "/var/run/secrets/cdnca/traffic-package-workload/server.key", "workload private key path mismatch")
    check(environment.dig("TRAFFIC_PACKAGE_WORKLOAD_MTLS_CLIENT_CA_FILE", "value") ==
      "/var/run/secrets/cdnca/traffic-package-workload/client-ca.crt", "workload client CA path mismatch")
    check(workload_port&.fetch("containerPort") == 9544, "workload container port mismatch")
    check(workload_mount&.fetch("mountPath") == "/var/run/secrets/cdnca/traffic-package-workload",
      "workload certificate mount mismatch")
    check(workload_volume&.dig("secret", "secretName") == "cdnca-traffic-package-mtls",
      "workload certificate Secret mismatch")
    check(services.length == 1 && services.first.dig("spec", "ports", 0, "port") == 9544,
      "workload Service mismatch")
  else
    check(workload_port.nil?, "disabled workload rendered a container port")
    check(workload_mount.nil?, "disabled workload rendered a certificate mount")
    check(workload_volume.nil?, "disabled workload rendered a certificate volume")
    check(services.empty?, "disabled workload rendered a Service")
  end
end

assert_shape(ARGV.fetch(0), "false", "false")
assert_shape(ARGV.fetch(1), "true", "false")
assert_shape(ARGV.fetch(2), "false", "true")
assert_shape(ARGV.fetch(3), "true", "true")
RUBY
