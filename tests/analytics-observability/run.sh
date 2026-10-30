#!/usr/bin/env bash
set -u

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
failed=0
passed=0
skipped=0
unresolved=0
mandatory_skipped=0

for probe in authority_capture_migration_smoke.sh static_contract_audit.sh clickhouse_smoke-static \
  clickhouse_smoke.sh jetstream_smoke.sh chain_smoke.sh; do
  printf 'RUN %s\n' "${probe}"
  if [[ ${probe} == clickhouse_smoke-static ]]; then
    "${script_dir}/clickhouse_smoke.sh" --static-contract
  else
    "${script_dir}/${probe}"
  fi
  status=$?
  case ${status} in
    0) passed=$((passed + 1)) ;;
    77) skipped=$((skipped + 1)) ;;
    *) failed=$((failed + 1)) ;;
  esac
done

source_probe=authority_capture_source_red.sh
printf 'RUN %s\n' "${source_probe}"
"${script_dir}/${source_probe}"
source_status=$?
case ${source_status} in
  0) passed=$((passed + 1)) ;;
  77)
    skipped=$((skipped + 1))
    mandatory_skipped=$((mandatory_skipped + 1))
    printf 'SKIP %s: mandatory source contract was not executed; suite exit will be 77\n' "${source_probe}" >&2
    ;;
  *)
    failed=$((failed + 1))
    printf 'FAIL %s: exit=%d\n' "${source_probe}" "${source_status}" >&2
    ;;
esac

printf 'analytics-observability summary: passed=%d failed=%d skipped=%d unresolved=%d mandatory_skipped=%d\n' \
  "${passed}" "${failed}" "${skipped}" "${unresolved}" "${mandatory_skipped}"
if [[ ${failed} -ne 0 || ${unresolved} -ne 0 ]]; then
  exit 1
fi
if [[ ${mandatory_skipped} -ne 0 ]]; then
  exit 77
fi
if [[ ${passed} -eq 0 && ${skipped} -ne 0 ]]; then
  exit 77
fi
