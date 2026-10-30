#!/usr/bin/env bash
# 停 up.sh 起的全部进程并删本地 PG 实例与状态目录（只动本任务的 pid 文件与 ui-click PG）。
# UICLICK_KEEP_STATE=1 只停进程、保留状态目录（密钥/env/身份）。
set -uo pipefail
S="${UICLICK_STATE:-/tmp/uiclick-state}"
for name in front market license control nats; do
  [ -f "$S/$name.pid" ] && kill "$(cat "$S/$name.pid")" 2>/dev/null; rm -f "$S/$name.pid"
done
[ -f "$S/redis.pid" ] && kill "$(cat "$S/redis.pid")" 2>/dev/null; rm -f "$S/redis.pid"
docker rm -f cdnca-ui-click-ch >/dev/null 2>&1
[ -n "${CDNCA_PG_NATIVE:-}" ] && "$CDNCA_PG_NATIVE" stop ui-click >/dev/null 2>&1
[ "${UICLICK_KEEP_STATE:-}" = 1 ] || rm -rf "$S"
echo "[ui-click down] 已停止"
