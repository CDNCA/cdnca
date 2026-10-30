# Sourced by tests/dynroute-e2e/run.sh (DYNROUTE_E2E_PRESTART) with $WORK set: builds and starts the license
# process, waits for its handoff and exports the installation the node must name.
echo "[license-ban-e2e] license process"
GOWORK=off go test -C "$LICENSE_BAN_E2E_ROOT/services/license-service" -c -o "$WORK/bin/license.test" ./internal/httpapi
(cd "$LICENSE_BAN_E2E_ROOT/services/license-service/internal/httpapi" && LICENSE_BAN_E2E_DIR="$WORK" \
  LICENSE_TEST_DATABASE_URL="$LICENSE_BAN_E2E_LICENSE_DATABASE_URL" LICENSE_TEST_MIGRATION_TIMEOUT=5m \
  exec "$WORK/bin/license.test" -test.run '^TestLicenseBanLicenseProcess$' -test.count=1 -test.v -test.timeout 45m) \
  >"$WORK/license.log" 2>&1 &
LICENSE_BAN_E2E_LICENSE_PID=$!
PIDS+=("$LICENSE_BAN_E2E_LICENSE_PID")
for _ in $(seq 1 600); do
  [ -f "$WORK/license-ban.json" ] && break
  kill -0 "$LICENSE_BAN_E2E_LICENSE_PID" 2>/dev/null || break
  sleep 1
done
if [ ! -f "$WORK/license-ban.json" ]; then
  grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /' >&2
  echo "[license-ban-e2e] license process did not become ready" >&2
  exit 1
fi
DYNROUTE_E2E_INSTALLATION_ID=$(jq -r .installation_id "$WORK/license-ban.json")
export DYNROUTE_E2E_INSTALLATION_ID
