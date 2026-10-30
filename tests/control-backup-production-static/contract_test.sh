#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd -P)
driver="$root/services/control-api/cmd/control-recovery-driver"
backup="$root/infra/helm/cdnca/templates/control-backup-cronjob.yaml"
restore="$root/infra/helm/cdnca/templates/control-restore-job.yaml"
network="$root/infra/helm/cdnca/templates/control-backup-networkpolicy.yaml"
values="$root/infra/helm/cdnca/values.yaml"
schema="$root/infra/helm/cdnca/values.schema.json"

test -d "$driver"
grep -RFq 'cdnca.control-recovery-driver.plan/v1' "$driver"
grep -RFq 'operation_outcome_uncertain' "$driver"
grep -RFq 'dns_cutover_timeout' "$driver"
grep -RFq 'agent_reconnect_timeout' "$driver"
grep -RFq 'io.nats.jetstream.api.v1.stream_snapshot_response' "$driver"
grep -RFq 'io.nats.jetstream.api.v1.stream_restore_response' "$driver"
grep -RFq 'topology_file' "$driver"

grep -Fq 'control-backup --plan' "$backup"
grep -Fq 'control-recovery-driver' "$backup"
grep -Fq 'control-restore --plan' "$restore"
grep -Fq 'control-recovery-driver' "$restore"
grep -Fq 'deployments/scale' "$backup"
grep -Fq 'resourceNames:' "$backup"
grep -Fq 'serviceAccountToken:' "$backup"
grep -Fq 'kubernetesAPI' "$network"
grep -Fq '.Values.controlBackupNetworkPolicy.nats' "$network"
grep -Fq 'agentProbe' "$network"
grep -Fq 'topologyFile: /opt/cdnca/contracts/nats-resources.json' "$values"
grep -Fq '"operationId"' "$schema"
grep -Fq '"kubernetesAPI"' "$schema"

if grep -Eq 'control-backup[[:space:]]+(backup|remote-fetch|restore)' "$backup" "$restore"; then
  echo 'legacy recovery CLI composition is forbidden' >&2
  exit 1
fi

if grep -Eq -- '--(password|token|secret|private-key)([= ]|$)' "$backup" "$restore"; then
  echo 'sensitive material must not be passed in argv' >&2
  exit 1
fi

ruby "$root/tests/control-backup-production-static/helm_contract_test.rb"

printf '%s\n' 'CONTROL_BACKUP_PRODUCTION_STATIC PASS'
