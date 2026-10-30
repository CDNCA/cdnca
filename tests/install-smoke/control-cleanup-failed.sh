#!/usr/bin/env bash
# AUDIT-1029 ①-12 容器演练：Ubuntu 24.04 真 systemd（屏蔽 systemd-binfmt 等）+ 发行版 PostgreSQL 16 / Redis。
# 阶段一：记录建立后才装上并启动 PostgreSQL、Redis（同安装器的依赖安装），模拟主控在
# “建库之后”失败；清理前预检端口被占，--cleanup-failed --yes 后两服务停止并停用、数据目录保留、
# 真实预检端口检查通过。
# 阶段一b：清理后原命令重装第二轮：已装但停用的依赖记 service-inactive=，依赖 helper
# 已装分支重新启用并启动；第二轮再失败再清理，依赖服务照样停用，端口预检仍通过。
# 阶段二（①-12 原有）：PostgreSQL、Redis 安装前已在运行，另放用户自己的库与安装前已有目录；原命令被拒并提示
# --cleanup-failed；无终端无 --yes 拒绝；--yes 只清本次创建的东西，依赖服务继续运行。
# 阶段三：RustFS 状态/账户/证书/单元、/usr/local/cdnca-control 与 ClamAV drop-in 写完后失败；
# 清理后真实 RustFS 全新安装门禁与空机门禁通过；本镜像依赖包未装上，ClamAV drop-in 被清（包已装时保留见单测）。
# 阶段一/一b/二模拟“依赖 helper 跑完（step=dependencies_ready）之后”失败：依赖软件包与数据目录保留；依赖没装完时
# 卸载本次装上的依赖包、删其数据目录（社区版）由单测覆盖。
# 用法：bash tests/install-smoke/control-cleanup-failed.sh
set -Eeuo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=cdnca-install-smoke-cleanup:$$
NAME=cdnca-control-cleanup-$$
CTX=$(mktemp -d)
cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; docker rmi "$IMAGE" >/dev/null 2>&1 || true; rm -rf "$CTX"; }
trap cleanup EXIT
cat >"$CTX/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04
# PostgreSQL/Redis 只下载不装：阶段一要在安装记录建立之后才装上（离线，--no-download）。
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus nftables procps ca-certificates python3 >/dev/null && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends --download-only postgresql redis-server >/dev/null && \
    rm -f /etc/apt/apt.conf.d/docker-clean
RUN for u in systemd-binfmt.service proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount systemd-firstboot.service \
      systemd-udevd.service systemd-udev-trigger.service systemd-networkd-wait-online.service getty.target console-getty.service; do \
      ln -sf /dev/null /etc/systemd/system/$u; done
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKER
docker build -q -t "$IMAGE" "$CTX" >/dev/null
docker run -d --rm --name "$NAME" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec "$IMAGE" >/dev/null
for _ in $(seq 1 60); do docker exec "$NAME" systemctl is-system-running 2>/dev/null | grep -Eq 'running|degraded' && break; sleep 1; done
docker cp "$ROOT/scripts/install-control.sh" "$NAME:/root/install-control.sh"
docker cp "$ROOT/scripts/native-runtime/install-ubuntu-dependencies.sh" "$NAME:/root/install-ubuntu-dependencies.sh"
docker cp "$ROOT/scripts/native-runtime/install-rustfs.py" "$NAME:/root/install-rustfs.py"
docker exec -i "$NAME" bash -s <<'IN'
set -Eeuo pipefail
fail() { echo "FAIL $*"; exit 1; }
S=/root/install-control.sh
sed '/^main "\$@"/d' "$S" >/root/install-control-lib.sh
# 真实端口预检（control_preflight_ports + preflight_check_ports），只看“端口占用”一项。
ports_ok() { bash -c '. /root/install-control-lib.sh; INSTALL_ENV=plain MASTER_PORT=443 GATEWAY_ENROLLMENT_PORT=20001 GATEWAY_AGENT_PORT=20002
  SKIP_DEPENDENCIES=false INSTALL_MODE=all; mapfile -t p < <(control_preflight_ports); preflight_check_ports "${p[@]}"
  printf "%s %s\n" "${PREFLIGHT_STATUS[0]}" "${PREFLIGHT_DETAIL[0]}"; [ "${PREFLIGHT_STATUS[0]}" = pass ]'; }
half_install_db() {
  runuser -u postgres -- psql -qX -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE ROLE cdnca LOGIN PASSWORD 'redacted-test-only';
CREATE ROLE cdnca_control_app NOLOGIN; CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN;
CREATE ROLE cdnca_control_runtime NOLOGIN; CREATE ROLE cdnca_retention_cleanup NOLOGIN;
GRANT cdnca_retention_cleanup TO cdnca;
CREATE DATABASE cdnca OWNER cdnca;
SQL
}
# ===== 阶段一：PostgreSQL、Redis 由本次安装装上并启动 =====
bash -c '. /root/install-control-lib.sh
  PG_PORT=5432; assert_fresh_installation; control_install_state_begin
  control_install_state_add step=dependencies_ready; control_install_state_add "created=postgresql:${PG_PORT}"'
grep -qx 'service-absent=postgresql.service' /var/lib/cdnca-control-install/state || fail 'pg absent not recorded'
grep -qx 'service-absent=redis-server.service' /var/lib/cdnca-control-install/state || fail 'redis absent not recorded'
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends --no-download postgresql redis-server >/dev/null 2>&1 ||
  fail 'offline dependency install'
systemctl enable --now postgresql redis-server >/dev/null 2>&1
for _ in $(seq 1 30); do pg_isready -q && break; sleep 1; done
half_install_db
for _ in $(seq 1 30); do redis-cli ping 2>/dev/null | grep -q PONG && break; sleep 1; done
out=$(ports_ok || true); grep -q '^fail .*5432（PostgreSQL）.*6379（Redis）' <<<"$out" || fail "ports before cleanup: $out"
out=$(bash "$S" --cleanup-failed </dev/null 2>&1 || true)
grep -q '依赖服务（本次安装装上并启动；停止并停用以释放端口，软件包与数据目录保留）：postgresql.service' <<<"$out" || fail "plan pg service: $out"
grep -q '依赖服务（本次安装装上并启动；停止并停用以释放端口，软件包与数据目录保留）：redis-server.service' <<<"$out" || fail 'plan redis service'
grep -q '依赖服务（[^）]*）：redis.service' <<<"$out" && fail 'alias listed'
grep -q '人工处理' <<<"$out" && fail "nothing should be undeterminable: $out"
systemctl is-active --quiet postgresql@16-main && systemctl is-active --quiet redis-server || fail 'stopped before confirmation'
bash "$S" --cleanup-failed --yes >/tmp/cleanup1.log 2>&1 || { cat /tmp/cleanup1.log; fail 'cleanup 1 failed'; }
for u in postgresql postgresql@16-main redis-server; do systemctl is-active --quiet "$u" && fail "$u still running"; done
for u in postgresql redis-server; do [ "$(systemctl is-enabled "$u" 2>/dev/null)" = disabled ] || fail "$u still enabled"; done
[ -f /var/lib/postgresql/16/main/PG_VERSION ] && [ -f /etc/redis/redis.conf ] || fail 'data or config removed'
dpkg -s postgresql redis-server >/dev/null 2>&1 || fail 'packages removed'
out=$(ports_ok) || fail "preflight ports after cleanup: $out"
grep -q '^pass 所需端口均空闲' <<<"$out" || fail "preflight detail: $out"
bash -c '. /root/install-control-lib.sh; assert_fresh_installation' || fail 'fresh gate after cleanup 1'
echo 'PASS 阶段一：本次安装启动的 PostgreSQL/Redis 已停止停用，端口预检通过'
# ===== 阶段一b：原命令重装第二轮，再失败再清理 =====
# 记录：已装但停用的依赖记 service-inactive=（不是 preexisting），第二轮失败时清理仍会停它们。
bash -c '. /root/install-control-lib.sh
  PG_PORT=5432; assert_fresh_installation; control_install_state_begin
  control_install_state_add step=dependencies_ready; control_install_state_add "created=postgresql:${PG_PORT}"'
for u in postgresql.service redis-server.service; do
  grep -qx "service-inactive=$u" /var/lib/cdnca-control-install/state || fail "$u not recorded inactive: $(cat /var/lib/cdnca-control-install/state)"
done
grep -qx 'preexisting=service:postgresql.service' /var/lib/cdnca-control-install/state && fail 'stopped pg recorded preexisting'
# 依赖 helper 已装分支（真 systemctl）：重新启用并启动；包档案/回环/ClamAV/就绪检查是固定版本 PGDG 17/ClickHouse 专用，
# 本镜像为发行版 PG16、无 ClickHouse，打桩；单元名换成本镜像的。
cp /root/install-ubuntu-dependencies.sh /root/deps.sh
bash -c 'set -Eeuo pipefail; source /root/deps.sh
  DEPS_PG_UNITS=(postgresql.service postgresql@16-main.service)
  native_dependencies_packages() { printf installed; }; native_dependencies_loopback() { :; }
  native_dependencies_clamav_config() { DEPS_CLAM_CHANGED=false; }; native_dependencies_check() { :; }
  eval "$(declare -f native_dependencies_install | sed "s/redis-server.service clickhouse-server.service/redis-server.service/")"
  systemctl() { [ "$1" != is-enabled ] || [ "$*" != "is-enabled --quiet clamav-freshclam.service" ] || return 0; command systemctl "$@"; }
  native_dependencies_install' || fail 'helper installed branch'
for u in postgresql@16-main redis-server; do systemctl is-active --quiet "$u" || fail "$u not restarted by helper"; done
for u in postgresql redis-server; do [ "$(systemctl is-enabled "$u")" = enabled ] || fail "$u not re-enabled"; done
for _ in $(seq 1 30); do pg_isready -q && break; sleep 1; done
for _ in $(seq 1 30); do redis-cli ping 2>/dev/null | grep -q PONG && break; sleep 1; done
# 空库：上一轮清理删了 cdnca 库与角色，安装器的“库/角色不存在”门禁通过后再建。
[ "$(runuser -u postgres -- psql -XAtc "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'cdnca%'")" = 0 ] || fail 'roles left from round 1'
half_install_db
out=$(ports_ok || true); grep -q '^fail .*5432（PostgreSQL）.*6379（Redis）' <<<"$out" || fail "ports before cleanup 1b: $out"
bash "$S" --cleanup-failed --yes >/tmp/cleanup1b.log 2>&1 || { cat /tmp/cleanup1b.log; fail 'cleanup 1b failed'; }
grep -qF '依赖服务（本次安装装上并启动；停止并停用以释放端口，软件包与数据目录保留）：postgresql.service' /tmp/cleanup1b.log || fail "1b plan pg: $(cat /tmp/cleanup1b.log)"
for u in postgresql postgresql@16-main redis-server; do systemctl is-active --quiet "$u" && fail "$u still running after 1b"; done
out=$(ports_ok) || fail "preflight ports after cleanup 1b: $out"
bash -c '. /root/install-control-lib.sh; assert_fresh_installation' || fail 'fresh gate after cleanup 1b'
echo 'PASS 阶段一b：清理后重装第二轮 helper 重新启用依赖，再失败再清理后端口预检仍通过'
# ===== 阶段二：PostgreSQL、Redis 安装前已在运行，一律不动 =====
systemctl enable --now postgresql redis-server >/dev/null 2>&1
for _ in $(seq 1 30); do pg_isready -q && break; sleep 1; done
# 安装前已有的东西：用户自己的库、安装前已存在的 /usr/local/libexec/cdnca。
runuser -u postgres -- psql -qX -c 'CREATE DATABASE customer_data' >/dev/null
install -d /usr/local/libexec/cdnca && echo keep >/usr/local/libexec/cdnca/operator-tool
# 1. 真实门禁 + 记录，然后按安装器的 SQL 建库（与 prepare_database 相同的对象）。
bash -c '. /root/install-control-lib.sh
  PG_PORT=5432; assert_fresh_installation; control_install_state_begin
  control_install_state_add step=dependencies_ready; control_install_state_add "created=postgresql:${PG_PORT}"'
grep -qx 'preexisting=service:postgresql.service' /var/lib/cdnca-control-install/state || fail 'pg preexisting not recorded'
half_install_db
runuser -u postgres -- psql -qX -d cdnca -c 'CREATE TABLE t(x int); INSERT INTO t VALUES (1)' >/dev/null
install -d -m 0700 /etc/cdnca-control /var/lib/cdnca-control /data/cdnca-native-root/cdnca/current/bin
echo 'SECRET=redacted' >/etc/cdnca-control/control.env
printf '[Unit]\nDescription=t\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n' >/etc/systemd/system/cdnca-control-nats.service
systemctl daemon-reload && systemctl enable --now cdnca-control-nats.service >/dev/null 2>&1
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin cdnca-objectstore
install -d /etc/redis/cdnca-gateway && echo 'tls-port 6380' >/etc/redis/cdnca-gateway/redis-gateway.conf
printf '\ninclude /etc/redis/cdnca-gateway/redis-gateway.conf\n' >>/etc/redis/redis.conf
nft add table inet cdnca_gateway_access
# 2. 原命令重跑：被拒并提示。
out=$(bash "$S" --master-host 203.0.113.9 2>&1 || true)
grep -q 'run install-control.sh --cleanup-failed first' <<<"$out" || fail "rerun hint: $out"
# 3. 无终端、无 --yes：列清单后拒绝，不改任何东西。
out=$(bash "$S" --cleanup-failed </dev/null 2>&1 || true)
grep -q 'cleanup needs confirmation' <<<"$out" || fail "confirm: $out"
grep -q 'PostgreSQL（端口 5432）' <<<"$out" || fail 'plan pg'
grep -q 'libexec/cdnca$' <<<"$out" && fail 'preexisting path listed'
grep -q '依赖服务（' <<<"$out" && fail "preexisting service listed: $out"
[ -f /etc/cdnca-control/control.env ] && systemctl is-active --quiet cdnca-control-nats.service || fail 'changed before confirmation'
# 4. --yes：只清本次安装创建的。
bash "$S" --cleanup-failed --yes >/tmp/cleanup.log 2>&1 || { cat /tmp/cleanup.log; fail 'cleanup 2 failed'; }
for p in /etc/cdnca-control /var/lib/cdnca-control /data/cdnca-native-root/cdnca /etc/redis/cdnca-gateway \
  /etc/systemd/system/cdnca-control-nats.service /var/lib/cdnca-control-install; do [ ! -e "$p" ] || fail "kept $p"; done
systemctl is-active --quiet cdnca-control-nats.service && fail 'unit still running'
getent passwd cdnca-objectstore >/dev/null && fail 'account kept'
nft list table inet cdnca_gateway_access >/dev/null 2>&1 && fail 'nft table kept'
grep -q cdnca-gateway /etc/redis/redis.conf && fail 'redis include kept'
[ "$(runuser -u postgres -- psql -XAtc "SELECT count(*) FROM pg_database WHERE datname='cdnca'")" = 0 ] || fail 'db kept'
[ "$(runuser -u postgres -- psql -XAtc "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'cdnca%'")" = 0 ] || fail 'roles kept'
[ "$(runuser -u postgres -- psql -XAtc "SELECT count(*) FROM pg_database WHERE datname='customer_data'")" = 1 ] || fail 'user db removed'
[ "$(cat /usr/local/libexec/cdnca/operator-tool)" = keep ] || fail 'preexisting dir removed'
systemctl is-active --quiet postgresql && systemctl is-active --quiet redis-server || fail 'dependency service stopped'
# 5. 清理后空机门禁通过；再次 --cleanup-failed 因无记录拒绝。
bash -c '. /root/install-control-lib.sh; assert_fresh_installation' || fail 'fresh gate after cleanup'
out=$(bash "$S" --cleanup-failed --yes 2>&1 || true)
grep -q 'no install record' <<<"$out" || fail "second cleanup: $out"
echo 'PASS 阶段二：安装前已有的依赖服务与数据保留'
# ===== 阶段三：依赖装完、RustFS 与 ClamAV 配置写完后失败 =====
# 真实 RustFS 全新安装门禁（install-rustfs.py reject_existing_state：路径 + 账户）与空机门禁在清理后都要通过；
# 依赖 helper 写的 ClamAV socket drop-in 保留（包已装时 helper 已装分支要求它原样存在）。
rustfs_gate() { python3 -I -B -c 'import importlib.util as u; s=u.spec_from_file_location("r","/root/install-rustfs.py"); m=u.module_from_spec(s); s.loader.exec_module(m); m.reject_existing_state()'; }
rustfs_gate || fail 'rustfs gate before stage 3'
bash -c '. /root/install-control-lib.sh; assert_fresh_installation; control_install_state_begin'
install -d -m 0700 /etc/systemd/system/clamav-daemon.socket.d
printf '[Socket]\nSocketMode=0660\nSocketUser=clamav\nSocketGroup=clamav\n' >/etc/systemd/system/clamav-daemon.socket.d/zz-cdnca-mode.conf
useradd --system --user-group --no-create-home --home-dir /var/lib/cdnca-objectstore --shell /usr/sbin/nologin cdnca-objectstore
install -d -m 0700 /etc/cdnca-objectstore /var/lib/cdnca-objectstore /var/lib/cdnca-objectstore-logs /var/lib/cdnca-objectstore-credentials
echo redacted >/etc/cdnca-objectstore/root-secret-key
install -d -m 0755 /usr/local/lib/cdnca-runtime && install -m 0755 /bin/sleep /usr/local/lib/cdnca-runtime/rustfs
echo cert >/usr/local/share/ca-certificates/cdnca-objectstore.crt && ln -sf /usr/local/share/ca-certificates/cdnca-objectstore.crt /etc/ssl/certs/cdnca-objectstore.pem
printf '[Service]\nUser=cdnca-objectstore\nExecStart=/usr/local/lib/cdnca-runtime/rustfs infinity\n[Install]\nWantedBy=multi-user.target\n' >/etc/systemd/system/cdnca-objectstore.service
install -d /etc/systemd/system/cdnca-objectstore.service.d && printf '[Service]\n' >/etc/systemd/system/cdnca-objectstore.service.d/zz-cdnca-systemd-compat.conf
systemctl daemon-reload && systemctl enable --now cdnca-objectstore.service >/dev/null 2>&1
systemctl is-active --quiet cdnca-objectstore.service || fail 'objectstore stub not running'
install -d -m 0755 /usr/local/cdnca-control/support && echo x >/usr/local/cdnca-control/support/install-ubuntu-dependencies.sh
rustfs_gate 2>/dev/null && fail 'rustfs gate should refuse residue'
bash -c '. /root/install-control-lib.sh; assert_fresh_installation' >/dev/null 2>&1 && fail 'fresh gate should refuse'
bash "$S" --cleanup-failed --yes >/tmp/cleanup3.log 2>&1 || { cat /tmp/cleanup3.log; fail 'cleanup 3 failed'; }
systemctl is-active --quiet cdnca-objectstore.service && fail 'objectstore still running'
rustfs_gate || fail "rustfs gate after cleanup: $(cat /tmp/cleanup3.log)"
bash -c '. /root/install-control-lib.sh; assert_fresh_installation' || fail 'fresh gate after cleanup 3'
[ ! -e /usr/local/cdnca-control ] || fail 'install root kept'
# 本镜像未装 clickhouse-server（依赖包未装上）：drop-in 及其目录要删掉，否则 helper 全新分支 existing_state_requires_review。
# 包已装上时保留的分支由单测覆盖。
[ ! -e /etc/systemd/system/clamav-daemon.socket.d ] || fail 'clamav drop-in kept while dependency packages are absent'
grep -qF '依赖安装写下的文件（依赖包未装上，重装时会被拒）：/etc/systemd/system/clamav-daemon.socket.d/zz-cdnca-mode.conf' /tmp/cleanup3.log || fail "plan drop-in: $(cat /tmp/cleanup3.log)"
echo 'PASS 阶段三：RustFS 状态/账户/证书/单元、/usr/local/cdnca-control 与依赖包未装上时的 ClamAV drop-in 已清，RustFS 与空机门禁通过'
echo PASS
IN
