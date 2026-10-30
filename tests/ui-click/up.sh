#!/usr/bin/env bash
# 本机 UI 巡检全栈（ui-click）：原生 PG17 + redis + nats-server + control-api/license-service/market-service
# + 四端 dist 静态/代理（front.mjs）+ 五类身份种子（seed.mjs）。不用 docker、不构建镜像。
#
#   tests/ui-click/up.sh        起栈（已起则跳过对应步骤）；首次会 go build 与 vite build（经 heavy.sh）
#   tests/ui-click/down.sh      停全部进程、删 PG 数据目录与状态目录
#
# 端口（全部 127.0.0.1）：PG 55990、ClickHouse 58123（docker --rm cdnca-ui-click-ch）、redis 56379、nats 54222、control 58080/59091、license 58081/58083、
#   market 59443/59445/58090、web 55101、运营后台+门户+统一登录 55102、卖家站 55103。
# 状态目录 $UICLICK_STATE（默认 /tmp/uiclick-state，仓库外）：密钥、env、日志、identities.json（本地测试口令）。
# 与生产的差异（报告里按“环境”归类，不算产品缺陷）：ClickHouse 有表无数据（未起节点/采集）、
#   未起对象存储（品牌资源/错误页运行时关，/v1/brand-assets/* 404）、主控未激活授权（LICENSE_SERVICE_URL 未配）、
#   统一登录图形验证码在本地库关闭（login_settings.captcha_required=false，只改本地库）。
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
S="${UICLICK_STATE:-/tmp/uiclick-state}"
B="${UICLICK_BIN:-/tmp/uiclick-bin}"
PG=/opt/homebrew/opt/postgresql@17/bin
PGURL=postgres://cdnca@127.0.0.1:55990
HEAVY="${CDNCA_HEAVY:-env}"
mkdir -p "$S/secrets" "$S/logs" "$S/nats" "$B"; chmod 700 "$S"
log() { printf '[ui-click up] %s\n' "$*"; }
alive() { [ -f "$S/$1.pid" ] && kill -0 "$(cat "$S/$1.pid")" 2>/dev/null; }
start() { # start <name> <envfile|-> <cmd...>
  local name=$1 envf=$2; shift 2
  alive "$name" && return 0
  if [ "$envf" = - ]; then (cd /tmp && exec "$@") >"$S/logs/$name.log" 2>&1 &
  else (cd /tmp && exec "$S/run-env.sh" "$envf" "$@") >"$S/logs/$name.log" 2>&1 & fi
  echo $! >"$S/$name.pid"
}
wait_url() { for _ in $(seq 1 60); do curl -fsS -m 2 "$1" >/dev/null 2>&1 && return 0; sleep 1; done; log "等待超时 $1（看 $S/logs）"; return 1; }
r32() { openssl rand -base64 32 | tr -d '\n'; }

# ---- 1 构建 ----
if [ ! -x "$B/control-api" ] || [ "${UICLICK_REBUILD:-}" = 1 ]; then
  log "go build 三服务"
  go -C "$ROOT/services/control-api" build -o "$B/control-api" ./cmd/control-api
  GOWORK=off go -C "$ROOT/services/license-service" build -o "$B/" ./cmd/license-service ./cmd/license-bootstrap
  GOWORK=off go -C "$ROOT/services/market-service" build -o "$B/" ./cmd/market-service
fi
if [ ! -x "$B/nats-server" ]; then
  log "nats-server（Go 模块缓存 v2.11.4）"
  GOFLAGS=-mod=mod GOPROXY=off GOWORK=off go -C "$(go env GOMODCACHE)/github.com/nats-io/nats-server/v2@v2.11.4" build -o "$B/nats-server" .
fi
if [ ! -x "$B/natsprov" ]; then
  T="$ROOT/services/agent-gateway/.uiclick-natsprov"; mkdir -p "$T"; cp "$ROOT/tests/ui-click/natsprov/main.go" "$T/"
  GOWORK=off go -C "$ROOT/services/agent-gateway" build -o "$B/natsprov" ./.uiclick-natsprov; rm -rf "$T"
fi
[ -d "$ROOT/node_modules" ] || pnpm -C "$ROOT" install --frozen-lockfile --prefer-offline
for a in web operator-console license-portal seller-portal; do
  if [ ! -f "$ROOT/apps/$a/dist/index.html" ] || [ "${UICLICK_REBUILD:-}" = 1 ]; then log "vite build $a"; "$HEAVY" pnpm -C "$ROOT/apps/$a" exec vite build >"$S/logs/build-$a.log" 2>&1; fi
done

# ---- 2 密钥与 env（只生成一次）----
cat >"$S/run-env.sh" <<'EOF'
#!/bin/bash
# run-env.sh <envfile> <cmd...>：逐行原样导出 KEY=VALUE（不经 shell 解析，值里有 & ' 等）再 exec。
f=$1; shift
while IFS= read -r line; do case "$line" in ''|'#'*) continue;; esac; export "${line%%=*}=${line#*=}"; done <"$f"
exec "$@"
EOF
chmod 700 "$S/run-env.sh"
if [ ! -f "$S/control.env" ]; then
  log "生成本地 PKI 与 env"
  ( cd "$S/secrets"
    ca() { openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' -subj "/CN=$1" -keyout "$2-key.pem" -out "$2-cert.pem" >/dev/null 2>&1; }
    ca 'uiclick root' root; ca 'uiclick gw client' gwca; ca 'uiclick node' node-ca
    openssl req -new -newkey rsa:2048 -nodes -keyout server-key.pem -subj /CN=localhost -out s.csr >/dev/null 2>&1
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >s.ext
    openssl x509 -req -in s.csr -CA root-cert.pem -CAkey root-key.pem -CAcreateserial -days 30 -extfile s.ext -out server-cert.pem >/dev/null 2>&1
    rm -f s.csr s.ext
    for k in installation-key webhook-key lic-sign offline-root seller-token edge-signing-key; do openssl genpkey -algorithm ED25519 -out "$k.pem"; done
    openssl rand -base64 32 >market-seed; openssl rand -hex 32 >downstream-secret; openssl rand -hex 32 >seller-digest
    printf '%s' "UiClick-$(openssl rand -hex 6)-Local!" >owner-pw
    chmod 600 ./* )
  X=$S/secrets
  pub() { openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n'; }
  lic_priv=$( (openssl pkey -in "$X/lic-sign.pem" -outform DER | tail -c 32; openssl pkey -in "$X/lic-sign.pem" -pubout -outform DER | tail -c 32) | base64 | tr -d '\n')
  bill_pub=$(pub "$X/lic-sign.pem" | tr -d '=' | tr '+/' '-_')
  off_pub=$(pub "$X/offline-root.pem" | tr -d '=')
  seller_seed=$(openssl pkey -in "$X/seller-token.pem" -outform DER | tail -c 32 | base64)
  # 主控授权信任公钥（授权端签名钥，base64url 无填充；entitlementguard.DecodeTrustedKeys）。
  printf '{"keys":[{"key_id":"local-license-v1","public_key":"%s"}]}\n' "$(pub "$X/lic-sign.pem" | tr -d '=' | tr '+/' '-_')" >"$X/entitlement-trusted-keys.json"
  chmod 400 "$X/entitlement-trusted-keys.json"
  cat >"$S/control.env" <<EOF
DATABASE_URL=$PGURL/cdnca_control?sslmode=disable&options=-c%20search_path%3Dcontrol
HTTP_ADDR=127.0.0.1:58080
CONTROL_INTERNAL_GRPC_ADDR=127.0.0.1:59091
ACCESS_TOKEN_SECRET=$(openssl rand -hex 32)
COOKIE_SECURE=false
API_KEY_PEPPER_VERSION=local-v1
API_KEY_PEPPER_BASE64=$(r32)
DNS_CREDENTIAL_KEY_ID=local-v1
DNS_CREDENTIAL_KEY_BASE64=$(r32)
IMPERSONATION_HMAC_KEY_BASE64=$(r32)
OBSERVABILITY_LOG_CURSOR_KEY_BASE64=$(r32)
OPENRESTY_SECURITY_SECRET_KEY_BASE64=$(r32)
MFA_ENABLED=true
MFA_ENCRYPTION_ACTIVE_KEY_ID=local-v1
MFA_ENCRYPTION_KEYS_JSON={"local-v1":"$(r32)"}
CONTROL_INSTALLATION_ID=70000000-0000-4000-8000-000000000001
CONTROL_INSTALLATION_NAME=cdnca local ui-click
CONTROL_INSTALLATION_PRIVATE_KEY_FILE=$X/installation-key.pem
CONTROL_VERSION=1.0.35
CONTROL_INTERNAL_SERVER_CERT_FILE=$X/server-cert.pem
CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE=$X/server-key.pem
CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE=$X/gwca-cert.pem
CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN=spiffe://cdnca/local/agent-gateway
NODE_CA_CERTIFICATE_CHAIN_FILE=$X/node-ca-cert.pem
NODE_CA_PRIVATE_KEY_FILE=$X/node-ca-key.pem
EDGE_DEPLOYMENT_NATS_URL=nats://127.0.0.1:54222
NODE_PRESENCE_NATS_URL=
NODE_PRESENCE_REDIS_URL=
REDIS_URL=redis://127.0.0.1:56379
PLUGIN_WEBHOOK_ATTESTATION_KEY_ID=local-plugin-webhook-attestation-v1
PLUGIN_WEBHOOK_ATTESTATION_PRIVATE_KEY_FILE=$X/webhook-key.pem
ANALYTICS_QUERY_ENABLED=true
ANALYTICS_INGEST_ENABLED=false
CLICKHOUSE_URL=http://127.0.0.1:58123
CLICKHOUSE_DATABASE=cdnca
CLICKHOUSE_USERNAME=cdnca
CLICKHOUSE_PASSWORD=uiclick-ch
ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID=local-v1
ANALYTICS_LOGS_CURSOR_KEYS_JSON={"local-v1":"$(r32)"}
ANNOUNCEMENT_ENABLED=true
ANNOUNCEMENT_EXTERNAL_CHANNEL=disabled
ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID=announcement-v1
ANNOUNCEMENT_CURSOR_KEYS_JSON={"announcement-v1":"$(r32)"}
NODE_SCHEDULING_RUNTIME_ENABLED=true
PROMOTION_HTTP_ENABLED=true
PROMOTION_HTTP_CURSOR_KEY_ID=promotion-v1
PROMOTION_HTTP_CURSOR_KEY_BASE64=$(r32)
TRAFFIC_PACKAGE_RUNTIME_ENABLED=true
TRAFFIC_PACKAGE_CURSOR_KEY_BASE64=$(r32)
JOB_QUERY_ENABLED=true
JOB_QUERY_CURSOR_ACTIVE_KEY_ID=jobs-v1
JOB_QUERY_CURSOR_KEYS_JSON={"jobs-v1":"$(r32)"}
CNAME_ALLOCATION_HMAC_KEY_ID=cname-allocation-v1
CNAME_ALLOCATION_HMAC_KEY=$(r32)
ENTITLEMENT_TRUSTED_KEYS_FILE=$X/entitlement-trusted-keys.json
SYSTEM_CONFIGURATION_RUNTIME_ENABLED=true
EDGE_PUBLISH_RUNTIME_ENABLED=true
EDGE_PUBLISH_SIGNER_PROVIDER=file
EDGE_PUBLISH_CURSOR_ACTIVE_KEY_ID=local-v1
EDGE_PUBLISH_CURSOR_KEYS_JSON={"local-v1":"$(r32)"}
EDGE_PUBLISH_SIGNING_KEY_ID=local-edge-artifact
EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE=$X/edge-signing-key.pem
PACKAGE_USAGE_RUNTIME_ENABLED=true
PACKAGE_USAGE_CURSOR_KEY_BASE64=$(r32)
PACKAGE_COMMERCE_RUNTIME_ENABLED=true
PACKAGE_COMMERCE_CURSOR_KEY_BASE64=$(r32)
PAYMENT_CHANNELS_ENABLED=true
PAYMENT_CHANNELS_NOTIFY_BASE=https://cdnca-local.example.test
PAYMENT_CHANNELS_RETURN_URL=https://cdnca-local.example.test/dashboard/
EOF
  # 套餐交易 worker（同 scripts/native-runtime/configure-control-runtime.py FIXED_ENV）。
  for kv in ENABLED=true NATS_URL=nats://127.0.0.1:54222 NATS_STREAM=PACKAGE_COMMERCE NATS_CREDS_FILE= NATS_CA_FILE= \
    NATS_CONNECT_TIMEOUT=2s NATS_OPERATION_TIMEOUT=2s NATS_RECONNECT_WAIT=250ms NATS_DRAIN_TIMEOUT=2s BATCH_SIZE=8 \
    LEASE_DURATION=30s PUBLISH_TIMEOUT=2s SETTLE_TIMEOUT=2s RETRY_MAX_ATTEMPTS=5 RETRY_BASE_DELAY=1s RETRY_MAX_DELAY=5s \
    IDLE_POLL=250ms ERROR_BACKOFF=1s SHUTDOWN_TIMEOUT=3s NATS_NAME=cdnca-package-commerce OWNER=package-commerce-1; do
    printf 'PACKAGE_COMMERCE_WORKER_%s\n' "$kv" >>"$S/control.env"; done
  # 其余运行时开关与 compose.full.yaml 的 control-api 一致（关闭），已在上面打开的除外。
  sed -n '/^  control-api:/,/^  control-ready:/p' "$ROOT/compose.full.yaml" | grep -E '^ +[A-Z_]+_ENABLED: "?(true|false)"?$' |
    sed -E 's/^ +([A-Z_]+): "?([a-z]+)"?$/\1=\2/' | while IFS= read -r kv; do
      grep -q "^${kv%%=*}=" "$S/control.env" || printf '%s\n' "$kv" >>"$S/control.env"; done
  cat >"$S/license.env" <<EOF
LICENSE_CONTROL_API_VERSION=0.1.0
LICENSE_DATABASE_URL=postgres://cdnca_license_runtime:lr@127.0.0.1:55990/cdnca_license?sslmode=disable&options=-c%20search_path%3Dlicense
LICENSE_BILLING_CALLBACK_DATABASE_URL=postgres://cdnca_license_callback:lc@127.0.0.1:55990/cdnca_license?sslmode=disable&options=-c%20search_path%3Dlicense
LICENSE_BILLING_PROVIDER_KEYS_JSON=[{"provider":"billing.local","provider_account_id":"local-account","provider_config_revision":1,"verification_key_id":"local-billing-v1","public_key":"$bill_pub"}]
LICENSE_TOTP_KEY_ID=local-v1
LICENSE_TOTP_KEYS_JSON={"local-v1":"$(r32)"}
LICENSE_CREDENTIAL_KEY_ID=local-v1
LICENSE_CREDENTIAL_KEYS_JSON={"local-v1":"$(r32)"}
LICENSE_IDENTITY_TOKEN_KEY_ID=local-v1
LICENSE_IDENTITY_TOKEN_KEYS_JSON={"local-v1":"$(r32)"}
LICENSE_SIGNING_PROVIDER=raw
LICENSE_SIGNING_KEY_ID=local-license-v1
LICENSE_SIGNING_PRIVATE_KEY_BASE64=$lic_priv
LICENSE_SIGNER_REVOCATION_ATTEMPT_HMAC_KEY_BASE64=$(r32)
LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_TRUST_JSON={"schema":"cdnca.signer-revocation-checkpoint-offline-root-trust/v1","active":{"key_id":"local-offline-root-v1","generation":1,"public_key_base64":"$off_pub"},"verify_only":[]}
LICENSE_ALLOW_INITIAL_SIGNER_BOOTSTRAP=true
LICENSE_LISTEN_ADDRESS=127.0.0.1:58081
LICENSE_HEALTH_ADDRESS=127.0.0.1:58083
LICENSE_OPERATOR_ORIGIN=http://localhost:55102
LICENSE_PORTAL_ORIGIN=http://localhost:55102
LICENSE_ALLOW_INSECURE_OPERATOR_COOKIE=true
LICENSE_SMTP_ADDRESS=localhost:52525
LICENSE_SMTP_FROM=cdnca-local@example.test
LICENSE_SELLER_SECRET_BASE64=$(r32)
LICENSE_SELLER_PUBLIC_ORIGIN=http://localhost:55103
LICENSE_SELLER_TOKEN_KEY_ID=local-seller-v1
LICENSE_SELLER_TOKEN_SEED_BASE64=$seller_seed
EOF
  cat >"$S/market.env" <<EOF
MARKET_DATABASE_URL=$PGURL/cdnca_market?sslmode=disable&options=-c%20search_path%3Dmarket
MARKET_LISTEN_ADDR=127.0.0.1:59443
MARKET_HEALTH_ADDR=127.0.0.1:58090
MARKET_TLS_CERT_FILE=$X/server-cert.pem
MARKET_TLS_KEY_FILE=$X/server-key.pem
MARKET_INSTALLATION_CA_FILE=$X/root-cert.pem
MARKET_LICENSE_KEYS_JSON=[{"key_id":"local-license-v1","public_key":"$(pub "$X/lic-sign.pem")"}]
MARKET_SIGNING_KEY_ID=market-local-v1
MARKET_SIGNING_KEY_FILE=$X/market-seed
MARKET_DOWNSTREAM_SECRET_FILE=$X/downstream-secret
MARKET_PLUGIN_STORE_DIR=$S/market-plugins
MARKET_SELLER_LISTEN_ADDR=127.0.0.1:59445
MARKET_SELLER_DIGEST_KEY_FILE=$X/seller-digest
MARKET_SELLER_PUBLIC_ORIGIN=http://localhost:55103
MARKET_SELLER_LOGIN_ORIGIN=http://localhost:55102
MARKET_SELLER_TOKEN_KEYS_JSON=[{"key_id":"local-seller-v1","public_key":"$(pub "$X/seller-token.pem")"}]
EOF
  mkdir -p "$S/market-plugins"; chmod 600 "$S"/*.env
fi

# ---- 3 依赖进程 ----
if ! "$PG/pg_isready" -h 127.0.0.1 -p 55990 -q; then
  log "PG17 ui-click:55990"; "${CDNCA_PG_NATIVE:?set CDNCA_PG_NATIVE}" start ui-click 55990 >/dev/null
  "$PG/psql" -X -q "$PGURL/postgres" -c "drop database cdnca_integration" -c "create database cdnca_control" \
    -c "create database cdnca_license" -c "create database cdnca_market" -c "revoke create on database cdnca_control from public" \
    -c "create role cdnca_license_runtime login password 'lr'" -c "create role cdnca_license_callback login password 'lc'"
  "$PG/psql" -X -q "$PGURL/cdnca_control" -c "create schema control"
  "$PG/psql" -X -q "$PGURL/cdnca_license" -c "create schema license"
  "$PG/psql" -X -q "$PGURL/cdnca_market" -c "create schema market"
  "$S/run-env.sh" "$S/control.env" "$B/control-api" migrate up >"$S/logs/migrate-control.log" 2>&1
  env LICENSE_MIGRATION_DATABASE_URL="$PGURL/cdnca_license?sslmode=disable&options=-c%20search_path%3Dlicense" \
    LICENSE_RUNTIME_DATABASE_ROLE=cdnca_license_runtime LICENSE_BILLING_CALLBACK_DATABASE_ROLE=cdnca_license_callback \
    "$B/license-service" migrate up >"$S/logs/migrate-license.log" 2>&1
  # 本地库关闭统一登录图形验证码（巡检脚本无法识别图片；生产默认开，部署后按 runbook 保持开启）。
  "$PG/psql" -X -q "$PGURL/cdnca_license" -c "update license.login_settings set captcha_required=false, revision=revision+1, updated_at=now() where id=1"
  NEW_DB=1
fi
# ClickHouse：本机无原生包，复用已有镜像起一个 --rm 容器（名 cdnca-ui-click-ch），账本迁移器原生 python 跑。
if ! curl -fsS -m 2 http://127.0.0.1:58123/ping >/dev/null 2>&1; then
  log "ClickHouse 容器 cdnca-ui-click-ch:58123"
  docker run -d --rm --name cdnca-ui-click-ch -p 127.0.0.1:58123:8123 -e CLICKHOUSE_DB=cdnca -e CLICKHOUSE_USER=cdnca \
    -e CLICKHOUSE_PASSWORD=uiclick-ch --ulimit nofile=262144:262144 clickhouse/clickhouse-server:25.3.6.56-alpine >/dev/null
  wait_url http://127.0.0.1:58123/ping
  CLICKHOUSE_MIGRATE_MIGRATIONS="$ROOT/infra/clickhouse/migrations" CLICKHOUSE_MIGRATE_URL=http://127.0.0.1:58123 \
    CLICKHOUSE_MIGRATE_DATABASE=cdnca CLICKHOUSE_MIGRATE_USER=cdnca CLICKHOUSE_MIGRATE_PASSWORD=uiclick-ch \
    python3 -I -B "$ROOT/scripts/clickhouse-migrate/cdnca-clickhouse-migrate.py" migrate >"$S/logs/migrate-ch.log" 2>&1
fi
redis-cli -p 56379 ping >/dev/null 2>&1 || redis-server --port 56379 --bind 127.0.0.1 --save '' --appendonly no --daemonize yes \
  --logfile "$S/logs/redis.log" --pidfile "$S/redis.pid"
start nats - "$B/nats-server" -js -sd "$S/nats" -a 127.0.0.1 -p 54222
sleep 1
# 流与消费者按原生安装的 NATS 拓扑（scripts/native-runtime/native-nats-profile.json，默认值合并）创建。
mkdir -p "$S/streams"
python3 - "$ROOT/scripts/native-runtime/native-nats-profile.json" "$S/streams" <<'PY2'
import json, sys
profile = json.load(open(sys.argv[1])); out = sys.argv[2]
sd, cd = dict(profile["stream_defaults"]), dict(profile["consumer_defaults"])
for i, stream in enumerate(profile["streams"]):
    json.dump({**sd, **stream}, open(f"{out}/s{i:02d}-{stream['name']}.json", "w"))
for i, consumer in enumerate(profile["consumers"]):
    json.dump({"stream_name": consumer["stream"], "config": {**cd, **consumer["config"]}}, open(f"{out}/c{i:02d}.json", "w"))
PY2
"$B/natsprov" nats://127.0.0.1:54222 "$S"/streams/s*.json "$S"/streams/c*.json >"$S/logs/natsprov.log"

# ---- 4 三服务 + 前端 ----
start control "$S/control.env" "$B/control-api" serve; wait_url http://127.0.0.1:58080/health/ready
start license "$S/license.env" "$B/license-service" serve; wait_url http://127.0.0.1:58083/health/ready
start market "$S/market.env" "$B/market-service"; wait_url http://127.0.0.1:58090/healthz
start front - node "$ROOT/tests/ui-click/front.mjs"; wait_url http://localhost:55101/dashboard/

# ---- 5 种子 ----
if [ "${NEW_DB:-}" = 1 ] || [ ! -f "$S/identities.json" ]; then
  printf 'BOOTSTRAP_PASSWORD=%s\n' "$(cat "$S/secrets/owner-pw")" >"$S/bootstrap.env"; grep '^DATABASE_URL=' "$S/control.env" >>"$S/bootstrap.env"
  "$S/run-env.sh" "$S/bootstrap.env" "$B/control-api" bootstrap-user -username admin -display-name '平台管理员' -email admin@example.test -existing-ok
  { grep -E '^LICENSE_(DATABASE_URL|CREDENTIAL|TOTP|IDENTITY)' "$S/license.env"
    echo "LICENSE_MIGRATION_DATABASE_URL=$PGURL/cdnca_license?sslmode=disable&options=-c%20search_path%3Dlicense"; } >"$S/lb.env"
  "$S/run-env.sh" "$S/lb.env" "$B/license-bootstrap" -username owner -display-name '运营负责人' -email owner@example.test \
    -password-file "$S/secrets/owner-pw" || true
  rm -f "$S/bootstrap.env"
  UICLICK_STATE="$S" node "$ROOT/tests/ui-click/seed.mjs"
fi
log "就绪：web http://localhost:55101/dashboard/  运营/门户 http://localhost:55102/  卖家站 http://localhost:55103/  身份 $S/identities.json"
