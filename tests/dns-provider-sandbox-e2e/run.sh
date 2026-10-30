#!/usr/bin/env bash

set -euo pipefail

if (( $# != 0 )); then
	exit 2
fi
if [[ ${CDNCA_DNS_SANDBOX_MUTATION_ACK-} != round7-six-provider-disposable-zones ]]; then
	exit 2
fi
if [[ -z ${CDNCA_DNS_SANDBOX_CONFIG_FILE-} ]]; then
	exit 2
fi
if [[ ${CDNCA_DNS_SANDBOX_CONFIG_FILE} != /* || ! -f ${CDNCA_DNS_SANDBOX_CONFIG_FILE} ||
	-L ${CDNCA_DNS_SANDBOX_CONFIG_FILE} || ! -r ${CDNCA_DNS_SANDBOX_CONFIG_FILE} ]]; then
	exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! -r $root/contract.json ]]; then
	exit 2
fi
cd "$root"
GOWORK=off exec go run .
