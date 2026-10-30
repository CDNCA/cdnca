#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PACKAGE="${ROOT}/services/control-api/internal/rechargepayment"
OPENAPI="${ROOT}/api/control-recharge-payments.openapi.yaml"
CONTRACT="${ROOT}/api/control-recharge-payments.contract.test.mjs"
RUNBOOK="${ROOT}/docs/runbooks/recharge-payment-lifecycle.md"

fail() {
  printf 'BILL-11/12 recharge payment source gate failed: %s\n' "$*" >&2
  exit 1
}

for file in "${PACKAGE}/model.go" "${PACKAGE}/engine.go" "${PACKAGE}/service.go" \
  "${PACKAGE}/ledger_adapter.go" "${PACKAGE}/approval_adapter.go" "${OPENAPI}" "${CONTRACT}" "${RUNBOOK}"; do
  [ -f "${file}" ] && [ ! -L "${file}" ] || fail "missing regular source ${file}"
done

if [ -n "$(gofmt -l "${PACKAGE}"/*.go)" ]; then
  fail 'Go source is not formatted'
fi

(cd "${ROOT}/services/control-api" && go test ./internal/rechargepayment -count=1)
(cd "${ROOT}/services/control-api" && go vet ./internal/rechargepayment)
node "${CONTRACT}"

for marker in provider_account_id payload_sha256 signature_sha256 reconcile_required; do
  grep -Fq "${marker}" "${OPENAPI}" || fail "OpenAPI lacks ${marker}"
done
for marker in migration151 migration133 migration100 Serializable append-only; do
  grep -Fq "${marker}" "${RUNBOOK}" || fail "runbook lacks ${marker}"
done
if grep -R -E -- 'raw_(payload|signature)|provider_secret|private_key' "${OPENAPI}" "${RUNBOOK}" >/dev/null; then
  fail 'secret-bearing API or runbook field found'
fi

printf 'RECHARGE_PAYMENT_SOURCE_STATIC PASS\n'
