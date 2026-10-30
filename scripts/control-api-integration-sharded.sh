#!/usr/bin/env bash
# control-api 重集成包一键跑：建一次“迁移到发布头”的模板库，再把包内测试分片并行跑。
#
# 只对用 databasetest.ClonedMigratedPool（TEST_DATABASE_TEMPLATE）建库的测试有效，
# 例如 edgepublish、edgedeployment、cachecontrol、acmeedge、packagecommerce 等；
# 其余测试照常从 1 号迁移，但仍能享受分片并行。
#
# 用法：
#   TEST_DATABASE_URL=postgres://cdnca@127.0.0.1:<port>/cdnca_integration?sslmode=disable \
#     scripts/control-api-integration-sharded.sh [-n 分片数] [-r 测试正则] [-t 超时] [包 ...]
#   包默认 ./internal/edgepublish/；分片数默认 2；超时默认 120m（每个分片）。
#
# 环境变量：
#   TEST_DATABASE_URL       必填。连接用户要能 CREATE DATABASE，且服务器上已建好 control-api
#                           集成测试的角色基线（cdnca_control_app 等，见 tests/postgres-integration/run.sh）。
#   CLONE_STRATEGY          克隆策略，wal_log（PG 默认）或 file_copy；默认 file_copy，见下方说明。
#   SHARD_WRAPPER           每个分片命令前缀，例如排队包装脚本。
#   LOG_DIR                 日志目录，默认 ${TMPDIR:-/tmp}/control-api-shards.<时间戳>。
#
# 模板库名为 cdnca_tpl_<迁移内容哈希前 12 位>：迁移文件不变就复用，改了就新建（旧模板不自动删，
# 用 `DROP DATABASE cdnca_tpl_xxx` 手动清）。克隆后 ClonedMigratedPool 会再执行一次 Migrate 校验校验和。
set -euo pipefail

shards=2 run='.' timeout=120m
while getopts 'n:r:t:h' option; do
  case $option in
  n) shards=$OPTARG ;;
  r) run=$OPTARG ;;
  t) timeout=$OPTARG ;;
  *) sed -n '2,24p' "$0"; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
packages=("$@")
[ ${#packages[@]} -gt 0 ] || packages=(./internal/edgepublish/)
[[ $shards =~ ^[1-9][0-9]?$ ]] || { echo "invalid shard count: $shards" >&2; exit 2; }
: "${TEST_DATABASE_URL:?TEST_DATABASE_URL is required}"
command -v psql >/dev/null || { echo "psql is required" >&2; exit 2; }

root=$(cd "$(dirname "$0")/.." && pwd)
service=$root/services/control-api
log_dir=${LOG_DIR:-${TMPDIR:-/tmp}/control-api-shards.$(date +%Y%m%d%H%M%S)}
mkdir -p "$log_dir"

# --- 模板库 -----------------------------------------------------------------
head=$(find "$service/migrations" -maxdepth 1 -name '*.up.sql' | wc -l | tr -d ' ')
digest=$(cat "$service"/migrations/*.sql | shasum -a 256 | cut -c1-12)
template=cdnca_tpl_$digest
url_for() { # url_for <database> [extra query]
  python3 - "$TEST_DATABASE_URL" "$1" "${2:-}" <<'PY'
import sys, urllib.parse as u
p = u.urlsplit(sys.argv[1]); q = p.query
if sys.argv[3]: q = (q + '&' if q else '') + sys.argv[3]
print(u.urlunsplit((p.scheme, p.netloc, '/' + sys.argv[2], q, '')))
PY
}
psql_admin() { psql -X -q -v ON_ERROR_STOP=1 "$TEST_DATABASE_URL" "$@"; }

ready=$(psql_admin -Atc "SELECT 1 FROM pg_database WHERE datname='$template'")
if [ "$ready" != 1 ]; then
  echo "building template $template (migrations 1..$head)"
  building=${template}_building
  psql_admin -c "DROP DATABASE IF EXISTS $building WITH (FORCE)"
  psql_admin -c "CREATE DATABASE $building TEMPLATE template0"
  psql -X -q -v ON_ERROR_STOP=1 "$(url_for "$building")" -c 'CREATE SCHEMA migrated'
  start=$(date +%s)
  CDNCA_BUILD_MIGRATION_TEMPLATE=$head TEST_DATABASE_URL=$(url_for "$building" search_path=migrated) \
    go -C "$service" test -p 1 -tags integration -count=1 -timeout 60m \
    -run '^TestBuildMigrationTemplate$' ./migrations/ >"$log_dir/template.log" 2>&1 ||
    { echo "template build failed, see $log_dir/template.log" >&2; exit 1; }
  # 改名是原子的：中途失败不会留下名字像“就绪”的半成品模板。
  psql_admin -c "ALTER DATABASE $building RENAME TO $template"
  echo "template ready in $(($(date +%s) - start))s"
else
  echo "reusing template $template"
fi

# --- 克隆策略 -----------------------------------------------------------------
# PG15+ 默认 STRATEGY=WAL_LOG 把整库写进 WAL，负载高时单次克隆约 40 秒；FILE_COPY 先做一次检查点
# 再按文件复制，测试库（fsync=off）上通常快得多。克隆语句在 databasetest/template.go 里，读这个变量。
export TEST_DATABASE_TEMPLATE_STRATEGY=${CLONE_STRATEGY:-file_copy}
export TEST_DATABASE_TEMPLATE=$template

# --- 分片 -----------------------------------------------------------------
status=0
for package in "${packages[@]}"; do
  name=$(echo "$package" | tr -c 'a-zA-Z0-9\n' '_')
  tests=$(go -C "$service" test -tags integration -list "$run" "$package" | grep -E '^(Test|Example|Fuzz)' || true)
  [ -n "$tests" ] || { echo "$package: no tests match $run"; continue; }
  count=$(echo "$tests" | wc -l | tr -d ' ')
  echo "$package: $count tests in $shards shards, logs in $log_dir"
  pids=()
  for shard in $(seq 0 $((shards - 1))); do
    selected=$(echo "$tests" | awk -v n="$shards" -v s="$shard" '(NR - 1) % n == s' | paste -sd'|' -)
    [ -n "$selected" ] || continue
    ${SHARD_WRAPPER:-} go -C "$service" test -p 1 -tags integration -count=1 -timeout "$timeout" \
      -run "^($selected)\$" "$package" -v >"$log_dir/$name.shard$shard.log" 2>&1 &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do wait "$pid" || status=1; done
  for log in "$log_dir/$name".shard*.log; do
    echo "--- $(basename "$log")"
    grep -E '^(--- FAIL|ok|FAIL|panic:)' "$log" || true
  done
done
[ $status -eq 0 ] && echo "all shards passed" || echo "some shards failed (logs: $log_dir)"
exit $status
