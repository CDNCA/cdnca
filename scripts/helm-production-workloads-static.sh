#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
CHART_DIR="$ROOT_DIR/infra/helm/cdnca"

ruby - "$CHART_DIR" <<'RUBY'
require "json"
require "yaml"

def check(condition, message)
  abort "FAIL: #{message}" unless condition
end

def deep_merge(base, overlay)
  return overlay unless base.is_a?(Hash) && overlay.is_a?(Hash)

  base.merge(overlay) do |_key, left, right|
    deep_merge(left, right)
  end
end

chart_dir = ARGV.fetch(0)
defaults = YAML.safe_load(File.read(File.join(chart_dir, "values.yaml")), aliases: false)
production_overlay = YAML.safe_load(File.read(File.join(chart_dir, "values-production.yaml")), aliases: false)
values = deep_merge(defaults, production_overlay)
schema = JSON.parse(File.read(File.join(chart_dir, "values.schema.json")))

production = values.fetch("production")
check(production.fetch("enabled") == true, "production overlay must enable production validation")
check(production.fetch("metricsServerAvailable") == true, "production must attest the Metrics API prerequisite")

components = %w[controlApi agentGateway web]
components.each do |name|
  component = values.fetch(name)
  check(component.fetch("enabled") == true, "#{name} must be enabled in production")
  check(component.fetch("autoscaling").fetch("enabled") == true, "#{name} must enable autoscaling in production")
  check(component.fetch("autoscaling").fetch("minReplicas") >= 2, "#{name} must keep at least two production replicas")
  check(component.fetch("pdb").fetch("enabled") == true, "#{name} must enable a production PDB")
  check(component.fetch("pdb").fetch("minAvailable") < component.fetch("autoscaling").fetch("minReplicas"), "#{name} PDB must leave one voluntary disruption available at the HPA floor")
  digest = component.fetch("image").fetch("digest")
  check(digest.match?(/\Asha256:[0-9a-f]{64}\z/), "#{name} must use an immutable lowercase SHA-256 digest")
  repository = component.fetch("image").fetch("repository")
  check(!repository.match?(/(?:busybox|curlimages|alpine|pause|smoke|health)/i), "#{name} must use its production image, not a temporary health image")
end

topology = values.fetch("topologySpreadConstraints")
%w[topology.kubernetes.io/zone kubernetes.io/hostname].each do |key|
  matches = topology.select { |constraint| constraint.fetch("topologyKey") == key }
  check(matches.length == 1, "production topology must define #{key} exactly once")
  check(matches.first.fetch("maxSkew") == 1, "production #{key} maxSkew must be one")
  check(matches.first.fetch("whenUnsatisfiable") == "DoNotSchedule", "production #{key} spread must fail closed")
end

schema_production = schema.fetch("properties").fetch("production")
check(schema_production == {"$ref" => "#/definitions/production"}, "schema must expose the production contract")
check(schema.fetch("allOf").any? { |rule| rule.dig("if", "properties", "production", "properties", "enabled", "const") == true }, "schema must condition production validation")

network = values.fetch("networkPolicy")
check(network.fetch("controlExternalEgress").fetch("ports") == [443], "control generic egress must be HTTPS-only")
check(network.fetch("gatewayExternalEgress").fetch("cidrs").empty?, "gateway generic egress must be empty")
check(!network.key?("licenseExternalEgress"), "community edition must not render license-service egress")
expected_stores = {
  "postgresql" => 5432,
  "redis" => 6379,
  "nats" => 4222,
  "clickhouse" => 8123,
}
expected_stores.each do |name, port|
  store = network.fetch("dataStores").fetch(name)
  check(store.fetch("port") == port, "#{name} NetworkPolicy port must be exact")
  check(!store.fetch("cidrs").empty?, "#{name} production CIDRs must be explicit")
end

templates = {
  "control" => File.read(File.join(chart_dir, "templates/control-api.yaml")),
  "gateway" => File.read(File.join(chart_dir, "templates/agent-gateway.yaml")),
  "frontends" => File.read(File.join(chart_dir, "templates/frontends.yaml")),
  "pdb" => File.read(File.join(chart_dir, "templates/poddisruptionbudgets.yaml")),
  "hpa" => File.read(File.join(chart_dir, "templates/horizontalpodautoscalers.yaml")),
  "network" => File.read(File.join(chart_dir, "templates/networkpolicies.yaml")),
  "migrations" => File.read(File.join(chart_dir, "templates/migrations.yaml")),
  "helpers" => File.read(File.join(chart_dir, "templates/_helpers.tpl")),
}

%w[control gateway frontends].each do |name|
  source = templates.fetch(name)
  %w[startupProbe readinessProbe livenessProbe].each do |probe|
    check(source.include?("#{probe}:"), "#{name} workload template must define #{probe}")
  end
  check(source.include?("minReadySeconds:"), "#{name} workload template must delay availability")
  check(source.include?("maxUnavailable: 0") && source.include?("maxSurge: 1"), "#{name} workload template must preserve capacity while rolling")
  check(source.include?("cdnca.io/secret-rollout:"), "#{name} workload template must expose an explicit rollout nonce")
end
check(templates.fetch("frontends").include?('"web"'), "frontend probe template must cover the Web workload")
check(!File.exist?(File.join(chart_dir, "templates/license-service.yaml")), "community edition must not ship a license-service template")
check(!templates.values.join("\n").match?(/\.Values\.licenseService\b|operatorConsole|operator-console|"license-service"/), "community edition templates must not reference the license service or operator console")
frontends = templates.fetch("frontends")
check(frontends.include?('mountPath: /run/cdnca-gateway'), "customer Web must mount the Gateway CA directory")
check(frontends.include?('secretName: {{ $root.Values.agentGateway.runtimeSecret.existingSecret }}'), "customer Web must use the configured Gateway runtime Secret")
check(frontends.include?('key: {{ $root.Values.agentGateway.runtimeSecret.keys.controlServerCA }}'), "customer Web must project the configured Gateway CA key")
check(frontends.include?('path: root-ca-cert.pem'), "customer Web must expose the CA under the nginx alias filename")

backend_probes = {
  "control" => "http",
  "gateway" => "health",
}
backend_probes.each do |name, port|
  source = templates.fetch(name)
  check(source.match?(/startupProbe:.*?path: \/health\/ready.*?port: #{port}/m), "#{name} startup must use dependency-aware readiness")
  check(source.match?(/readinessProbe:.*?path: \/health\/ready.*?port: #{port}/m), "#{name} readiness must use the dependency-aware endpoint")
  check(source.match?(/livenessProbe:.*?path: \/health\/live.*?port: #{port}/m), "#{name} liveness must stay independent of dependency health")
end

all_templates = templates.values.join("\n")
check(!all_templates.match?(/\blookup\s+"v1"\s+"Secret"/), "Helm must not read external Secret data")
check(!all_templates.include?("checksum/external-secrets:"), "Secret rotation must use an explicit rollout nonce, not a data checksum")
check(!all_templates.match?(/^kind: Secret$/), "chart must not create Secrets")
check(!all_templates.match?(/^\s*(?:data|stringData):\s*$/), "chart must not inline Secret payloads")

topology_helper = templates.fetch("helpers")
check(topology_helper.include?('define "cdnca.topologySpreadConstraints"'), "topology spread helper must remain shared")
check(topology_helper.include?("labelSelector:") && topology_helper.include?('include "cdnca.selectorLabels"'), "topology spread must target only the component Pods")

pdb = templates.fetch("pdb")
check(pdb.include?("unhealthyPodEvictionPolicy: AlwaysAllow"), "PDB must allow failed Pods to be evicted while preserving healthy quorum")
check(pdb.include?("minAvailable:"), "PDB must protect a minimum healthy quorum")

check(!templates.fetch("control").include?("initContainers:"), "control migration must not race in each Deployment replica")
migrations = templates.fetch("migrations")
check(migrations.scan(/^kind: Job$/).length == 1, "exactly one migration Job is required")
check(migrations.scan(/helm\.sh\/hook: pre-install,pre-upgrade/).length == 1, "the migration Job must block install and upgrade")
check(migrations.scan(/^  backoffLimit: 0$/).length == 1, "the migration Job must fail closed without retry ambiguity")
check(migrations.scan(/args: \["migrate", "up"\]/).length == 1, "the migration Job must execute migrate up")

hpa = templates.fetch("hpa")
check(hpa.include?("autoscaling/v2"), "HPA must use autoscaling/v2")
check(hpa.include?("name: cpu") && hpa.include?("name: memory"), "HPA must use CPU and memory metrics")
check(hpa.include?("scaleUp:") && hpa.include?("scaleDown:"), "HPA must define bounded scale behavior")
check(hpa.include?("stabilizationWindowSeconds:") && hpa.include?("periodSeconds:"), "HPA must bound scaling churn")

network_source = templates.fetch("network")
%w[postgresql redis nats clickhouse].each do |name|
  check(network_source.include?("networkPolicy.dataStores.#{name}"), "NetworkPolicy must render the #{name} flow explicitly")
end

puts "OPS-13 production workload source/schema static gate passed."
RUBY
