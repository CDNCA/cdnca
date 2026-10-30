#!/usr/bin/env bash

set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
contract=$root/contract.json

for file in README.md contract.json go.mod main.go runner.go run.sh; do
	test -f "$root/$file"
done

jq -e '
  .schema == "cdnca:dns-provider-sandbox-e2e-contract:v1" and
  [.providers[].code] == ["cloudflare","aliyun","huawei","dnspod_cn","dns_com","dns_la"] and
  ([.providers[] | select(.alias == true)] | length) == 0 and
  all(.providers[];
    .operations == ["create","read","update","rate_limit","delete","readback"] and
    .credential_schema == (.credential_schema | unique) and
    (.credential_schema | length) > 0 and
    .retry_after == true
  ) and
  ([.providers[] | select(.line == true and .weight == true) | .code] == ["dnspod_cn"])
' "$contract" >/dev/null

grep -Fq 'preflightAll' "$root/main.go"
grep -Fq 'runAll' "$root/main.go"
grep -Fq 'dnsproviderremote.NewReconcileRemote' "$root/runner.go"
grep -Fq 'dnsproviderlive.Run' "$root/runner.go"
grep -Fq 'CDNCA_DNS_SANDBOX_MUTATION_ACK' "$root/run.sh"

if grep -R -nE '(set -x|curl .*-(v|i)|echo .*CREDENTIAL|printf .*CREDENTIAL)' \
	"$root/run.sh" "$root/main.go" "$root/runner.go"; then
	echo 'unsafe secret output pattern' >&2
	exit 1
fi

echo 'dns-provider-sandbox-e2e static contract: PASS'
