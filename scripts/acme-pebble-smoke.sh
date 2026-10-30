#!/bin/sh
set -eu

pebble_tag='v2.10.1'
pebble_commit='b1e1ca4f3c30abb64111adaca4544bc5374cc306'
pebble_archive_sha256='3f571a36d138bc0987637e4d2a30a57ceaa91ee134362cf725aba3393634d4f3'

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
task_tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-acme-pebble.XXXXXX")
pebble_pid=''
challenge_pid=''

cleanup() {
	if [ -n "$pebble_pid" ]; then
		kill "$pebble_pid" 2>/dev/null || true
		wait "$pebble_pid" 2>/dev/null || true
	fi
	if [ -n "$challenge_pid" ]; then
		kill "$challenge_pid" 2>/dev/null || true
		wait "$challenge_pid" 2>/dev/null || true
	fi
	rm -rf -- "$task_tmp"
}
trap cleanup EXIT INT TERM

for command in git go curl shasum awk; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "required command is unavailable: $command" >&2
		exit 1
	fi
done

mkdir "$task_tmp/pebble"
git -C "$task_tmp/pebble" init --quiet
git -C "$task_tmp/pebble" remote add origin https://github.com/letsencrypt/pebble.git
git -C "$task_tmp/pebble" fetch --quiet --depth 1 origin "refs/tags/$pebble_tag"
git -C "$task_tmp/pebble" checkout --quiet --detach "$pebble_commit"
actual_commit=$(git -C "$task_tmp/pebble" rev-parse HEAD)
if [ "$actual_commit" != "$pebble_commit" ]; then
	echo "Pebble commit mismatch: got $actual_commit" >&2
	exit 1
fi
actual_archive_sha256=$(git -C "$task_tmp/pebble" archive --format=tar HEAD | shasum -a 256 | awk '{print $1}')
if [ "$actual_archive_sha256" != "$pebble_archive_sha256" ]; then
	echo "Pebble source digest mismatch: got $actual_archive_sha256" >&2
	exit 1
fi

mkdir -p "$task_tmp/bin"
(
	cd "$task_tmp/pebble"
	GOWORK=off go build -trimpath -o "$task_tmp/bin/pebble" ./cmd/pebble
	GOWORK=off go build -trimpath -o "$task_tmp/bin/pebble-challtestsrv" ./cmd/pebble-challtestsrv
)

"$task_tmp/bin/pebble-challtestsrv" \
	-defaultIPv4 127.0.0.1 \
	-defaultIPv6 '' \
	-dnsserver 127.0.0.1:8053 \
	-doh '' \
	-http01 127.0.0.1:5002 \
	-https01 '' \
	-tlsalpn01 '' \
	-management 127.0.0.1:8055 \
	>"$task_tmp/challtestsrv.log" 2>&1 &
challenge_pid=$!

# ACME_PEBBLE_EAB=1: Pebble requires External Account
# Binding, as ZeroSSL and Google Trust Services do; the smoke checks the
# worker refuses without credentials and registers and issues with them.
pebble_config=test/config/pebble-config.json
eab_kid='kid-1'
eab_hmac='zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W'
if [ "${ACME_PEBBLE_EAB:-0}" = 1 ]; then
	# Pebble's own EAB configuration (kid-1 is one of its MAC keys).
	pebble_config=test/config/pebble-config-external-account-bindings.json
fi

(
	cd "$task_tmp/pebble"
	exec env PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 \
		"$task_tmp/bin/pebble" \
		-config "$pebble_config" \
		-dnsserver 127.0.0.1:8053
) >"$task_tmp/pebble.log" 2>&1 &
pebble_pid=$!

ready='false'
attempt=0
while [ "$attempt" -lt 80 ]; do
	if curl --insecure --fail --silent --max-time 1 \
		https://127.0.0.1:14000/dir >/dev/null 2>&1 && \
		curl --fail --silent --max-time 1 -X POST \
		-H 'Content-Type: application/json' -d '{"token":"readiness"}' \
		http://127.0.0.1:8055/del-http01 >/dev/null 2>&1; then
		ready='true'
		break
	fi
	if ! kill -0 "$pebble_pid" 2>/dev/null || ! kill -0 "$challenge_pid" 2>/dev/null; then
		break
	fi
	attempt=$((attempt + 1))
	sleep 0.25
done

if [ "$ready" != 'true' ]; then
	echo 'Pebble did not become ready' >&2
	tail -n 80 "$task_tmp/pebble.log" >&2 || true
	tail -n 80 "$task_tmp/challtestsrv.log" >&2 || true
	exit 1
fi

echo "ACME_SMOKE pebble_tag=$pebble_tag commit=$pebble_commit source_sha256=$pebble_archive_sha256"
if ! (
	cd "$repo_root/services/control-api"
	if [ "${ACME_PEBBLE_EAB:-0}" = 1 ]; then
		set -- -eab-kid "$eab_kid" -eab-hmac "$eab_hmac"
	else
		set --
	fi
	GOWORK=off go run ./internal/acmeworker/cmd/acme-pebble-smoke \
		-directory https://127.0.0.1:14000/dir \
		-management http://127.0.0.1:8055 \
		-dns-server 127.0.0.1:8053 "$@"
); then
	tail -n 100 "$task_tmp/pebble.log" >&2 || true
	tail -n 100 "$task_tmp/challtestsrv.log" >&2 || true
	exit 1
fi
