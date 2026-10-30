#!/usr/bin/env bash
# Fixed fresh-host dependency profile. No application databases, users or flags.
# Official repositories: postgresql.org/download/linux/ubuntu/ (and /debian/) and
# clickhouse.com/docs/get-started/setup/self-managed/debian-ubuntu.
# Supported hosts (docs/install/os-support-matrix.md): apt on Ubuntu 24.04 noble,
# Ubuntu 22.04 jammy, Debian 12 bookworm and Debian 13 trixie (PGDG), Ubuntu
# 20.04 and Debian 10/11 (portable PostgreSQL and ClamAV); dnf on Rocky,
# AlmaLinux and RHEL 8/9/10 (PGDG yum, ClickHouse rpm, ClamAV from EPEL, Redis
# from AppStream on EL8/EL9 and Valkey on EL10; EL8 selects the nginx:1.24 and
# redis:6 module streams). The same PostgreSQL 17.11 build is
# pinned per PGDG suite/EL major; ClickHouse uses one distribution-neutral
# repository; RustFS is the static musl build. Cloud-image bootstrap
# prerequisites: python3, flock and ss. A minimal image lacking these is
# rejected before mutation; not an upgrade tool. The file keeps its historical
# name because the signed package inventory names it.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

DEPS_PG_VERSION=''
DEPS_PG_SUITE=''
DEPS_OS_LABEL=''
DEPS_FAMILY=debian
DEPS_EL_MAJOR=''
DEPS_PG_PSQL=/usr/lib/postgresql/17/bin/psql
DEPS_PG_SOCKET_DIR=/var/run/postgresql
DEPS_PG_DATA=/var/lib/postgresql/17/main
DEPS_REDIS_UNIT=redis-server.service
DEPS_CLAM_USER=clamav
DEPS_CLAM_GROUP=clamav
DEPS_CLAM_UNITS=(clamav-daemon.service clamav-daemon.socket clamav-freshclam.service)
DEPS_CH_VERSION=25.3.6.56
DEPS_ROOT_UID=0
DEPS_PATH_BOUNDARY=/
DEPS_OS_RELEASE=/etc/os-release
DEPS_LOOPBACK=/etc/clickhouse-server/config.d/cdnca-loopback.xml
DEPS_ADMIN_CONFIG=/etc/cdnca-analytics/admin.xml
DEPS_CLAM_CONFIG=/etc/clamav/clamd.conf
DEPS_CLAM_DROPIN=/etc/systemd/system/clamav-daemon.socket.d/zz-cdnca-mode.conf
DEPS_CLAM_SOCKET=/var/run/clamav/clamd.ctl
DEPS_CLAM_DATABASE=/var/lib/clamav
DEPS_LOCK=/run/cdnca-native-dependencies/install.lock
DEPS_PG_KEY=/usr/share/keyrings/cdnca-pgdg.asc
DEPS_PG_SOURCE=/etc/apt/sources.list.d/cdnca-pgdg.sources
DEPS_CH_KEY=/usr/share/keyrings/cdnca-clickhouse.asc
DEPS_CH_SOURCE=/etc/apt/sources.list.d/cdnca-clickhouse.list
DEPS_EPEL_KEY=''
DEPS_EPEL_SOURCE=''
# Hosts without a PGDG 17.11 package use the reproducible portable build
# (build-portable-postgresql.sh); its archive is pinned here.
DEPS_PG_MODE=package
DEPS_PG_UNITS=(postgresql.service postgresql@17-main.service)
DEPS_PG_PORTABLE_ARCHIVE=postgresql-17.11-portable-linux-amd64.tar.gz
DEPS_PG_PORTABLE_SHA256=e58f34528c56ff3557ecaa6164ab45ebc7dcce26f23cf92d596183cd8b816cb0
DEPS_PG_PORTABLE_PREFIX=/opt/cdnca-postgresql-17
DEPS_PG_PORTABLE_RECEIPT=/var/lib/cdnca-postgresql/receipt
DEPS_PG_PORTABLE_UNIT=/etc/systemd/system/postgresql-17.service
DEPS_PG_PORTABLE_TOOLS=(psql pg_dump pg_restore pg_dumpall pg_isready)
DEPS_PG_PORTABLE_INPUT=''
# The same hosts get ClamAV 1.4 LTS repacked from the upstream build
# (build-portable-clamav.sh): the signature CDN refuses their ClamAV 0.103.
DEPS_CLAM_MODE=package
DEPS_CLAM_PORTABLE_ARCHIVE=clamav-1.4.6-portable-linux-amd64.tar.gz
DEPS_CLAM_PORTABLE_SHA256=a1cecce72db46a424393046ee351f2d23bc7e249a810fbdbe7e246c9752e35e8
DEPS_CLAM_PORTABLE_PREFIX=/opt/cdnca-clamav-1.4
DEPS_CLAM_PORTABLE_RECEIPT=/var/lib/cdnca-clamav/receipt
DEPS_CLAM_PORTABLE_TOOLS=(sbin/clamd bin/freshclam bin/clamdscan bin/clamscan)
DEPS_CLAM_PORTABLE_INPUT=''
DEPS_FRESHCLAM_CONFIG=/etc/clamav/freshclam.conf
DEPS_CLAMD_ARGS=()
# The upstream build's libcurl looks for the EL bundle; Debian keeps it here.
DEPS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
DEPS_CLAM_ENABLE=(clamav-daemon.socket clamav-daemon.service clamav-freshclam.service)
DEPS_LOOPBACK_CONTENT=$'<clickhouse>\n    <listen_host replace="replace">127.0.0.1</listen_host>\n    <interserver_listen_host replace="replace">127.0.0.1</interserver_listen_host>\n</clickhouse>\n'
DEPS_CLAM_DROPIN_CONTENT=$'[Socket]\nSocketMode=0660\nSocketUser=clamav\nSocketGroup=clamav\n'
DEPS_PROTECTED_PATHS=(/var/lib/postgresql /etc/postgresql /var/lib/clickhouse /etc/clickhouse-server /etc/clamav /etc/redis/redis.conf /var/lib/redis /etc/cdnca-control/control.env /var/lib/cdnca-control /var/lib/cdnca-edge /var/lib/site-runtime)
DEPS_NGINX_GUARDS=(/etc/nginx /usr/sbin/nginx /lib/systemd/system/nginx.service /etc/systemd/system/nginx.service /etc/systemd/system/nginx.service.d /run/systemd/system/nginx.service /run/systemd/system/nginx.service.d)
DEPS_CLAM_UNOWNED_OVERRIDES=(/etc/systemd/system/clamav-daemon.socket /run/systemd/system/clamav-daemon.socket /run/systemd/system/clamav-daemon.socket.d)
# Host port profile (fix-btenv). install-control.sh writes it on a BaoTa host
# whose PostgreSQL/Redis/ClickHouse default ports are taken; absent = defaults.
# Parsed strictly (never sourced); the same file drives a later migration.
DEPS_RUNTIME_ENV=/etc/cdnca-native-dependencies/runtime.env
DEPS_ENV=plain
DEPS_PG_PORT=5432
DEPS_REDIS_PORT=6379
DEPS_CH_HTTP_PORT=8123
DEPS_CH_TCP_PORT=9000
DEPS_CH_MYSQL_PORT=9004
DEPS_CH_POSTGRESQL_PORT=9005
DEPS_CH_INTERSERVER_PORT=9009
# BaoTa ships its own nginx; the control web runs a separate instance of it.
DEPS_BT_NGINX=/www/server/nginx/sbin/nginx
# Debian starts packaged services on install; a BaoTa host may already run a
# same-named service on the default port, so starts are held until configured.
DEPS_POLICY_RC=/usr/sbin/policy-rc.d
DEPS_REDIS_CONFIGS=(/etc/redis/redis.conf /etc/redis.conf /etc/valkey/valkey.conf)

native_dependencies_ports() {
  local path=$DEPS_RUNTIME_ENV line key value seen=' ' ports=' '
  [[ -e "$path" || -L "$path" ]] || return 0
  native_dependencies_path "$path" file 644
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^([A-Z_]+)=([a-z0-9]+)$ ]] || native_dependencies_fail invalid_runtime_env
    key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
    [[ "$seen" != *" $key "* ]] || native_dependencies_fail invalid_runtime_env
    seen="$seen$key "
    case "$key" in
      ENV) [[ "$value" == bt || "$value" == plain ]] || native_dependencies_fail invalid_runtime_env; DEPS_ENV=$value; continue ;;
      WEB_PORT|NODE_DOWNLOAD_PORT|PG_PORT|REDIS_PORT|CH_HTTP_PORT|CH_TCP_PORT|CH_MYSQL_PORT|CH_POSTGRESQL_PORT|CH_INTERSERVER_PORT) ;;
      *) native_dependencies_fail invalid_runtime_env ;;
    esac
    [[ "$value" =~ ^[1-9][0-9]{3,4}$ ]] && (( value <= 65535 )) || native_dependencies_fail invalid_runtime_env
    [[ "$ports" != *" $value "* ]] || native_dependencies_fail invalid_runtime_env
    ports="$ports$value "
    [[ "$key" == WEB_PORT || "$key" == NODE_DOWNLOAD_PORT ]] || printf -v "DEPS_$key" '%s' "$value"
  done < "$path"
  # Only non-default ports are written, so a default profile keeps its bytes.
  local extra=''
  [[ "$DEPS_CH_HTTP_PORT" == 8123 ]] || extra+="    <http_port>$DEPS_CH_HTTP_PORT</http_port>"$'\n'
  [[ "$DEPS_CH_TCP_PORT" == 9000 ]] || extra+="    <tcp_port>$DEPS_CH_TCP_PORT</tcp_port>"$'\n'
  [[ "$DEPS_CH_MYSQL_PORT" == 9004 ]] || extra+="    <mysql_port>$DEPS_CH_MYSQL_PORT</mysql_port>"$'\n'
  [[ "$DEPS_CH_POSTGRESQL_PORT" == 9005 ]] || extra+="    <postgresql_port>$DEPS_CH_POSTGRESQL_PORT</postgresql_port>"$'\n'
  [[ "$DEPS_CH_INTERSERVER_PORT" == 9009 ]] || extra+="    <interserver_http_port>$DEPS_CH_INTERSERVER_PORT</interserver_http_port>"$'\n'
  DEPS_LOOPBACK_CONTENT=${DEPS_LOOPBACK_CONTENT%'</clickhouse>'$'\n'}$extra'</clickhouse>'$'\n'
}

# PostgreSQL and Redis on the profile port (no-op on the default profile).
native_dependencies_set_ports() {
  local config content
  if [[ "$DEPS_PG_PORT" != 5432 ]]; then
    if [[ "$DEPS_FAMILY" == rhel || "$DEPS_PG_MODE" == portable ]]; then
      printf '\n# cdnca host port profile\nport = %s\n' "$DEPS_PG_PORT" >> "$DEPS_PG_DATA/postgresql.conf"
    else
      pg_conftool 17 main set port "$DEPS_PG_PORT"
    fi
  fi
  [[ "$DEPS_REDIS_PORT" != 6379 ]] || return 0
  for config in "${DEPS_REDIS_CONFIGS[@]}"; do
    [[ -f "$config" && ! -L "$config" ]] || continue
    grep -qx 'port 6379' "$config" || native_dependencies_fail redis_configuration_mismatch
    # Rewrite in place (cat >) so the vendor owner and mode stay unchanged.
    content=$(awk -v port="$DEPS_REDIS_PORT" '$0 == "port 6379" { $0 = "port " port } { print }' "$config") &&
      printf '%s\n' "$content" > "$config" || native_dependencies_fail redis_configuration_mismatch
    return 0
  done
  native_dependencies_fail redis_configuration_mismatch
}

# The nginx that runs the control web: BaoTa's own build on a BaoTa host.
native_dependencies_nginx() {
  if [[ "$DEPS_ENV" == bt && -x "$DEPS_BT_NGINX" ]]; then "$DEPS_BT_NGINX" "$@"; else nginx "$@"; fi
}

native_dependencies_hold_starts() {
  [[ "$DEPS_ENV" == bt ]] || return 0
  native_dependencies_write_new "$DEPS_POLICY_RC" 755 $'#!/bin/sh\n# cdnca: hold package service starts until the port profile is applied\nexit 101\n'
}

native_dependencies_release_starts() {
  [[ "$DEPS_ENV" == bt ]] || return 0
  rm -f -- "$DEPS_POLICY_RC"
}

native_dependencies_fail() {
  printf 'native_dependencies: %s\n' "$1" >&2
  exit 1
}

native_dependencies_profile() {
  local facts major pattern
  [[ $(id -u) == 0 ]] || native_dependencies_fail root_required
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || native_dependencies_fail unsupported_architecture
  [[ -f "$DEPS_OS_RELEASE" ]] || native_dependencies_fail unsupported_os
  facts=$(awk -F= '/^(ID|VERSION_ID|VERSION_CODENAME)=/ { gsub(/"/, "", $2); print $1 "=" $2 }' "$DEPS_OS_RELEASE" | sort)
  # One PGDG build of PostgreSQL 17.11 per suite; server_version_num is the same.
  case "$facts" in
    $'ID=ubuntu\nVERSION_CODENAME=noble\nVERSION_ID=24.04') DEPS_PG_VERSION=17.11-1.pgdg24.04+2 DEPS_PG_SUITE=noble-pgdg DEPS_OS_LABEL=ubuntu=24.04 ;;
    $'ID=ubuntu\nVERSION_CODENAME=jammy\nVERSION_ID=22.04') DEPS_PG_VERSION=17.11-1.pgdg22.04+2 DEPS_PG_SUITE=jammy-pgdg DEPS_OS_LABEL=ubuntu=22.04 ;;
    $'ID=debian\nVERSION_CODENAME=bookworm\nVERSION_ID=12') DEPS_PG_VERSION=17.11-1.pgdg12+2 DEPS_PG_SUITE=bookworm-pgdg DEPS_OS_LABEL=debian=12 ;;
    $'ID=debian\nVERSION_CODENAME=trixie\nVERSION_ID=13') DEPS_PG_VERSION=17.11-1.pgdg13+2 DEPS_PG_SUITE=trixie-pgdg DEPS_OS_LABEL=debian=13 ;;
    # No PGDG 17.11 package and a ClamAV the signature CDN refuses (0.103):
    # the portable PostgreSQL and ClamAV builds instead. Upstream ClamAV 1.4
    # needs glibc 2.28: Ubuntu 18.04 (2.27) waits for the musl source build
    # (build-portable-clamav-musl.sh) to be built, pinned and published.
    $'ID=ubuntu\nVERSION_CODENAME=focal\nVERSION_ID=20.04') DEPS_OS_LABEL=ubuntu=20.04; native_dependencies_portable_pg_profile; native_dependencies_portable_clamav_profile ;;
    $'ID=debian\nVERSION_CODENAME=bullseye\nVERSION_ID=11') DEPS_OS_LABEL=debian=11; native_dependencies_portable_pg_profile; native_dependencies_portable_clamav_profile ;;
    $'ID=debian\nVERSION_CODENAME=buster\nVERSION_ID=10') DEPS_OS_LABEL=debian=10; native_dependencies_portable_pg_profile; native_dependencies_portable_clamav_profile ;;
    *)
      # RHEL family: exactly one ID and one VERSION_ID; only the major counts.
      pattern=$'^ID=(rocky|almalinux|rhel)\nVERSION_ID=(8|9|10)(\\.[0-9]+)?$'
      [[ "$facts" =~ $pattern ]] || native_dependencies_fail unsupported_os
      major=${BASH_REMATCH[2]}
      native_dependencies_rhel_profile "${BASH_REMATCH[1]}" "$major"
      return ;;
  esac
  [[ $(dpkg --print-architecture) == amd64 ]] || native_dependencies_fail unsupported_architecture
}

# Paths, units and accounts of the EL packages (verified on rockylinux:9 with
# systemd as PID 1: postgresql17-server, clickhouse-server rpm, EPEL clamd).
native_dependencies_rhel_profile() {
  [[ $(rpm --eval '%{_arch}') == x86_64 ]] || native_dependencies_fail unsupported_architecture
  DEPS_FAMILY=rhel DEPS_EL_MAJOR=$2 DEPS_OS_LABEL="$1=$2"
  DEPS_PG_VERSION=17.11 DEPS_PG_SUITE="rhel-$2-x86_64"
  DEPS_PG_PSQL=/usr/pgsql-17/bin/psql DEPS_PG_SOCKET_DIR=/run/postgresql DEPS_PG_DATA=/var/lib/pgsql/17/data
  DEPS_REDIS_UNIT=redis.service
  if [[ $2 == 10 ]]; then DEPS_REDIS_UNIT=valkey.service; fi
  DEPS_CLAM_CONFIG=/etc/clamd.d/scan.conf DEPS_CLAM_SOCKET=/run/clamd.scan/clamd.sock
  DEPS_CLAM_USER=clamscan DEPS_CLAM_GROUP=virusgroup
  DEPS_CLAM_UNITS=(clamd@scan.service clamav-freshclam.service)
  DEPS_CLAM_UNOWNED_OVERRIDES=(/etc/systemd/system/clamd@.service /etc/systemd/system/clamd@scan.service /etc/systemd/system/clamd@scan.service.d)
  DEPS_PG_KEY=/etc/pki/rpm-gpg/CDNCA-PGDG-RPM-GPG-KEY-RHEL
  DEPS_CH_KEY=/etc/pki/rpm-gpg/CDNCA-CLICKHOUSE-RPM-GPG-KEY
  DEPS_EPEL_KEY=/etc/pki/rpm-gpg/CDNCA-RPM-GPG-KEY-EPEL-$2
  DEPS_PG_SOURCE=/etc/yum.repos.d/cdnca-pgdg17.repo
  DEPS_CH_SOURCE=/etc/yum.repos.d/cdnca-clickhouse.repo
  DEPS_EPEL_SOURCE=/etc/yum.repos.d/cdnca-epel.repo
  DEPS_PROTECTED_PATHS=(/var/lib/pgsql /var/lib/clickhouse /etc/clickhouse-server /etc/clamd.d/scan.conf.rpmsave /var/lib/clamav /etc/redis /etc/valkey /var/lib/redis /var/lib/valkey /etc/cdnca-control/control.env /var/lib/cdnca-control /var/lib/cdnca-edge /var/lib/site-runtime)
  DEPS_NGINX_GUARDS=(/etc/nginx /usr/sbin/nginx /usr/lib/systemd/system/nginx.service /etc/systemd/system/nginx.service /etc/systemd/system/nginx.service.d /run/systemd/system/nginx.service /run/systemd/system/nginx.service.d)
}

# Portable PostgreSQL: binaries under DEPS_PG_PORTABLE_PREFIX, data in the
# PGDG RHEL layout, one systemd unit named like the PGDG RHEL unit, tool links
# in /usr/bin (where the upgrade runner and install-control look for them).
native_dependencies_portable_pg_profile() {
  DEPS_PG_MODE=portable DEPS_PG_VERSION=17.11 DEPS_PG_SUITE=portable
  DEPS_PG_PSQL=/usr/bin/psql DEPS_PG_SOCKET_DIR=/run/postgresql DEPS_PG_DATA=/var/lib/pgsql/17/data
  DEPS_PG_UNITS=(postgresql-17.service)
  DEPS_PG_UNIT_CONTENT="[Unit]
Description=PostgreSQL 17 (cdnca portable build)
After=network.target

[Service]
Type=simple
User=postgres
Group=postgres
RuntimeDirectory=postgresql
RuntimeDirectoryMode=2775
Environment=PGDATA=$DEPS_PG_DATA
ExecStart=$DEPS_PG_PORTABLE_PREFIX/bin/postgres -D $DEPS_PG_DATA
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
KillSignal=SIGINT
TimeoutSec=300
OOMScoreAdjust=-900

[Install]
WantedBy=multi-user.target
"
}

# Portable ClamAV keeps the Debian package layout (account, socket, units,
# /etc/clamav) so install-control and control-api need no host branch.
native_dependencies_portable_clamav_profile() {
  DEPS_CLAM_MODE=portable
  DEPS_CLAM_UNITS=(clamav-daemon.service clamav-freshclam.service)
  DEPS_CLAM_ENABLE=(clamav-daemon.service clamav-freshclam.service)
  DEPS_CLAMD_ARGS=("--config-file=$DEPS_CLAM_CONFIG")
  DEPS_CLAM_CONFIG_CONTENT="# cdnca portable ClamAV profile (Debian package layout)
LocalSocket $DEPS_CLAM_SOCKET
LocalSocketGroup clamav
LocalSocketMode 660
FixStaleSocket yes
User clamav
DatabaseDirectory $DEPS_CLAM_DATABASE
Foreground yes
LogSyslog yes
"
  DEPS_FRESHCLAM_CONFIG_CONTENT="# cdnca portable ClamAV profile
DatabaseOwner clamav
DatabaseDirectory $DEPS_CLAM_DATABASE
DatabaseMirror database.clamav.net
Checks 12
NotifyClamd $DEPS_CLAM_CONFIG
Foreground yes
LogSyslog yes
"
  DEPS_CLAMD_UNIT_CONTENT="[Unit]
Description=ClamAV daemon (cdnca portable build)
After=network.target

[Service]
Type=simple
User=clamav
Group=clamav
RuntimeDirectory=clamav
RuntimeDirectoryMode=0755
ExecStart=$DEPS_CLAM_PORTABLE_PREFIX/sbin/clamd --config-file=$DEPS_CLAM_CONFIG
ExecReload=/bin/kill -USR2 \$MAINPID
TimeoutStartSec=420
Restart=on-failure

[Install]
WantedBy=multi-user.target
"
  DEPS_FRESHCLAM_UNIT_CONTENT="[Unit]
Description=ClamAV signature updater (cdnca portable build)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=clamav
Group=clamav
Environment=CURL_CA_BUNDLE=$DEPS_CA_BUNDLE
ExecStart=$DEPS_CLAM_PORTABLE_PREFIX/bin/freshclam -d --foreground=true --config-file=$DEPS_FRESHCLAM_CONFIG
Restart=on-failure

[Install]
WantedBy=multi-user.target
"
}

native_dependencies_portable_clamav_install() {
  local archive=$1 stage path
  [[ -f "$archive" && ! -L "$archive" ]] || native_dependencies_fail portable_clamav_archive_missing
  [[ $(sha256sum "$archive" | awk '{ print $1 }') == "$DEPS_CLAM_PORTABLE_SHA256" ]] || native_dependencies_fail portable_clamav_archive_mismatch
  for path in "$DEPS_CLAM_PORTABLE_PREFIX" "$DEPS_CLAM_PORTABLE_RECEIPT" /etc/clamav "$DEPS_CLAM_DATABASE" \
      /etc/systemd/system/clamav-daemon.service /etc/systemd/system/clamav-freshclam.service \
      /usr/sbin/clamd /usr/bin/freshclam /usr/bin/clamdscan /usr/bin/clamscan; do
    [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail existing_state_requires_review
  done
  stage=$(mktemp -d "$(dirname "$DEPS_CLAM_PORTABLE_PREFIX")/.cdnca-clamav.XXXXXXXX")
  tar -xzf "$archive" -C "$stage" --no-same-owner
  [[ $(find "$stage" -mindepth 1 -maxdepth 1 -printf '%f\n') == "$(basename "$DEPS_CLAM_PORTABLE_PREFIX")" ]] || native_dependencies_fail portable_clamav_archive_mismatch
  chown -R 0:0 "$stage"
  chmod -R go-w "$stage"
  mv -T "$stage/$(basename "$DEPS_CLAM_PORTABLE_PREFIX")" "$DEPS_CLAM_PORTABLE_PREFIX"
  rmdir "$stage"
  if ! getent passwd clamav >/dev/null; then
    getent group clamav >/dev/null || groupadd --system clamav
    useradd --system --gid clamav --home-dir "$DEPS_CLAM_DATABASE" --shell /usr/sbin/nologin --comment 'ClamAV' clamav
  fi
  [[ $(id -u clamav) =~ ^[1-9][0-9]*$ ]] || native_dependencies_fail clamav_account_unsafe
  install -d -o clamav -g clamav -m 0755 "$DEPS_CLAM_DATABASE"
  native_dependencies_write_new "$DEPS_CLAM_CONFIG" 644 "$DEPS_CLAM_CONFIG_CONTENT"
  native_dependencies_write_new "$DEPS_FRESHCLAM_CONFIG" 644 "$DEPS_FRESHCLAM_CONFIG_CONTENT"
  native_dependencies_write_new /etc/systemd/system/clamav-daemon.service 644 "$DEPS_CLAMD_UNIT_CONTENT"
  native_dependencies_write_new /etc/systemd/system/clamav-freshclam.service 644 "$DEPS_FRESHCLAM_UNIT_CONTENT"
  for path in "${DEPS_CLAM_PORTABLE_TOOLS[@]}"; do ln -s "$DEPS_CLAM_PORTABLE_PREFIX/$path" "/usr/$path"; done
  native_dependencies_write_new "$DEPS_CLAM_PORTABLE_RECEIPT" 644 "$DEPS_CLAM_PORTABLE_SHA256  $DEPS_CLAM_PORTABLE_ARCHIVE"$'\n'
}

native_dependencies_portable_clamav_check() {
  local path
  native_dependencies_path "$DEPS_CLAM_PORTABLE_RECEIPT" file 644
  [[ $(< "$DEPS_CLAM_PORTABLE_RECEIPT") == "$DEPS_CLAM_PORTABLE_SHA256  $DEPS_CLAM_PORTABLE_ARCHIVE" ]] || native_dependencies_fail portable_clamav_mismatch
  for path in "$DEPS_CLAM_PORTABLE_PREFIX" "$DEPS_CLAM_PORTABLE_PREFIX/sbin" "$DEPS_CLAM_PORTABLE_PREFIX/bin" "$DEPS_CLAM_PORTABLE_PREFIX/lib64"; do
    native_dependencies_path "$path" directory 755
  done
  for path in "$DEPS_CLAM_CONFIG:$DEPS_CLAM_CONFIG_CONTENT" "$DEPS_FRESHCLAM_CONFIG:$DEPS_FRESHCLAM_CONFIG_CONTENT" \
      "/etc/systemd/system/clamav-daemon.service:$DEPS_CLAMD_UNIT_CONTENT" "/etc/systemd/system/clamav-freshclam.service:$DEPS_FRESHCLAM_UNIT_CONTENT"; do
    native_dependencies_path "${path%%:*}" file 644
    cmp -s "${path%%:*}" <(printf '%s' "${path#*:}") || native_dependencies_fail portable_clamav_mismatch
  done
  for path in "${DEPS_CLAM_PORTABLE_TOOLS[@]}"; do
    [[ -L "/usr/$path" && $(readlink "/usr/$path") == "$DEPS_CLAM_PORTABLE_PREFIX/$path" ]] || native_dependencies_fail portable_clamav_mismatch
  done
}

# Fresh: no PostgreSQL package, no portable state. Installed: the receipt plus
# exactly the three pinned ClickHouse packages.
native_dependencies_portable_packages() {
  local inventory count
  if [[ "$DEPS_FAMILY" == rhel ]]; then
    inventory=$(rpm -qa --qf '%{NAME}\t%{VERSION}\n') || native_dependencies_fail package_inventory_unavailable
    count=$(awk -F '\t' -v ch="$DEPS_CH_VERSION" '
      $1 ~ /^postgresql([0-9]+)?-server$/ { bad=1 }
      $1 ~ /^clickhouse-(server|client|common-static)$/ { if ($2 != ch) bad=1; seen[$1]++ }
      END { for (name in seen) { count++; if (seen[name] != 1) bad=1 } if (bad) exit 1; print count + 0 }
    ' <<< "$inventory") || native_dependencies_fail incompatible_package_profile
  else
    inventory=$(dpkg-query -W -f='${Package}\t${db:Status-Status}\t${Version}\n') || native_dependencies_fail package_inventory_unavailable
    count=$(awk -F '\t' -v ch="$DEPS_CH_VERSION" -v clam="$DEPS_CLAM_MODE" '
      $2 == "installed" && $1 ~ /^postgresql(-client)?-[0-9]+$/ { bad=1 }
      clam == "portable" && $2 == "installed" && $1 ~ /^(clamav|clamav-daemon|clamav-freshclam|clamdscan)$/ { bad=1 }
      $2 == "installed" && $1 ~ /^clickhouse-(server|client|common-static)$/ { if ($3 != ch) bad=1; seen[$1]++ }
      END { for (name in seen) { count++; if (seen[name] != 1) bad=1 } if (bad) exit 1; print count + 0 }
    ' <<< "$inventory") || native_dependencies_fail incompatible_package_profile
  fi
  local receipts=("$DEPS_PG_PORTABLE_RECEIPT") receipt present=0
  [[ "$DEPS_CLAM_MODE" != portable ]] || receipts+=("$DEPS_CLAM_PORTABLE_RECEIPT")
  for receipt in "${receipts[@]}"; do if [[ -e "$receipt" || -L "$receipt" ]]; then present=$((present + 1)); fi; done
  if [[ "$count" == 3 && "$present" == "${#receipts[@]}" ]]; then printf 'installed\n'
  elif [[ "$count" == 0 && "$present" == 0 ]]; then printf 'fresh\n'
  else native_dependencies_fail incompatible_package_profile
  fi
}

# The archive is verified against the pin before anything is unpacked; the
# tree is staged next to its final path and renamed into place.
native_dependencies_portable_pg_install() {
  local archive=$1 stage path
  [[ -f "$archive" && ! -L "$archive" ]] || native_dependencies_fail portable_postgresql_archive_missing
  [[ $(sha256sum "$archive" | awk '{ print $1 }') == "$DEPS_PG_PORTABLE_SHA256" ]] || native_dependencies_fail portable_postgresql_archive_mismatch
  for path in "$DEPS_PG_PORTABLE_PREFIX" "$DEPS_PG_PORTABLE_RECEIPT" "$DEPS_PG_PORTABLE_UNIT" "$DEPS_PG_DATA" "${DEPS_PG_PORTABLE_TOOLS[@]/#//usr/bin/}"; do
    [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail existing_state_requires_review
  done
  stage=$(mktemp -d "$(dirname "$DEPS_PG_PORTABLE_PREFIX")/.cdnca-postgresql.XXXXXXXX")
  tar -xzf "$archive" -C "$stage" --no-same-owner
  [[ $(find "$stage" -mindepth 1 -maxdepth 1 -printf '%f\n') == "$(basename "$DEPS_PG_PORTABLE_PREFIX")" ]] || native_dependencies_fail portable_postgresql_archive_mismatch
  chown -R 0:0 "$stage"
  chmod -R go-w "$stage"
  mv -T "$stage/$(basename "$DEPS_PG_PORTABLE_PREFIX")" "$DEPS_PG_PORTABLE_PREFIX"
  rmdir "$stage"
  [[ $("$DEPS_PG_PORTABLE_PREFIX/bin/postgres" --version) == 'postgres (PostgreSQL) 17.11' ]] || native_dependencies_fail portable_postgresql_unusable
  if ! getent passwd postgres >/dev/null; then
    getent group postgres >/dev/null || groupadd --system postgres
    useradd --system --gid postgres --home-dir /var/lib/pgsql --shell /bin/bash --comment 'PostgreSQL Server' postgres
  fi
  [[ $(id -u postgres) =~ ^[1-9][0-9]*$ ]] || native_dependencies_fail postgresql_account_unsafe
  install -d -o postgres -g postgres -m 0700 /var/lib/pgsql /var/lib/pgsql/17 "$DEPS_PG_DATA"
  runuser -u postgres -- "$DEPS_PG_PORTABLE_PREFIX/bin/initdb" -D "$DEPS_PG_DATA" -U postgres -E UTF8 --locale=C \
    --auth-local=peer --auth-host=scram-sha-256 >/dev/null
  printf '\n# cdnca portable profile: loopback only, same socket as the packages.\nlisten_addresses = '"'"'127.0.0.1'"'"'\n' >> "$DEPS_PG_DATA/postgresql.conf"
  native_dependencies_write_new "$DEPS_PG_PORTABLE_UNIT" 644 "$DEPS_PG_UNIT_CONTENT"
  for path in "${DEPS_PG_PORTABLE_TOOLS[@]}"; do ln -s "$DEPS_PG_PORTABLE_PREFIX/bin/$path" "/usr/bin/$path"; done
  native_dependencies_write_new "$DEPS_PG_PORTABLE_RECEIPT" 644 "$DEPS_PG_PORTABLE_SHA256  $DEPS_PG_PORTABLE_ARCHIVE"$'\n'
}

native_dependencies_portable_pg_check() {
  local path
  native_dependencies_path "$DEPS_PG_PORTABLE_RECEIPT" file 644
  [[ $(< "$DEPS_PG_PORTABLE_RECEIPT") == "$DEPS_PG_PORTABLE_SHA256  $DEPS_PG_PORTABLE_ARCHIVE" ]] || native_dependencies_fail portable_postgresql_mismatch
  for path in "$DEPS_PG_PORTABLE_PREFIX" "$DEPS_PG_PORTABLE_PREFIX/bin" "$DEPS_PG_PORTABLE_PREFIX/lib"; do native_dependencies_path "$path" directory 755; done
  native_dependencies_path "$DEPS_PG_PORTABLE_PREFIX/bin/postgres" file 755
  native_dependencies_path "$DEPS_PG_PORTABLE_UNIT" file 644
  cmp -s "$DEPS_PG_PORTABLE_UNIT" <(printf '%s' "$DEPS_PG_UNIT_CONTENT") || native_dependencies_fail portable_postgresql_mismatch
  for path in "${DEPS_PG_PORTABLE_TOOLS[@]}"; do
    [[ -L "/usr/bin/$path" && $(readlink "/usr/bin/$path") == "$DEPS_PG_PORTABLE_PREFIX/bin/$path" ]] || native_dependencies_fail portable_postgresql_mismatch
  done
}

native_dependencies_packages() {
  local inventory result
  if [[ "$DEPS_PG_MODE" == portable ]]; then native_dependencies_portable_packages; return; fi
  if [[ "$DEPS_FAMILY" == rhel ]]; then native_dependencies_rhel_packages; return; fi
  inventory=$(dpkg-query -W -f='${Package}\t${db:Status-Status}\t${Version}\n') || native_dependencies_fail package_inventory_unavailable
  result=$(awk -F '\t' -v pg="$DEPS_PG_VERSION" -v ch="$DEPS_CH_VERSION" '
    $2 == "installed" && $1 ~ /^postgresql(-client)?-[0-9]+$/ {
      if (($1 != "postgresql-17" && $1 != "postgresql-client-17") || $3 != pg) bad=1; seen[$1]++
    }
    $2 == "installed" && $1 ~ /^clickhouse-(server|client|common-static)$/ { if ($3 != ch) bad=1; seen[$1]++ }
    END { for (name in seen) { count++; if (seen[name] != 1) bad=1 }
      if (bad || (count != 0 && count != 5)) exit 1; print (count == 5 ? "installed" : "fresh") }
  ' <<< "$inventory") || native_dependencies_fail incompatible_package_profile
  printf '%s\n' "$result"
}

# Same contract as the dpkg profile: either none or exactly the five pinned
# PostgreSQL 17.11 / ClickHouse packages, and no other PostgreSQL major.
native_dependencies_rhel_packages() {
  local inventory result
  inventory=$(rpm -qa --qf '%{NAME}\t%{VERSION}\n') || native_dependencies_fail package_inventory_unavailable
  result=$(awk -F '\t' -v pg="$DEPS_PG_VERSION" -v ch="$DEPS_CH_VERSION" '
    $1 ~ /^postgresql([0-9]+)?(-server)?$/ {
      if (($1 != "postgresql17-server" && $1 != "postgresql17") || $2 != pg) bad=1; seen[$1]++
    }
    $1 ~ /^clickhouse-(server|client|common-static)$/ { if ($2 != ch) bad=1; seen[$1]++ }
    END { for (name in seen) { count++; if (seen[name] != 1) bad=1 }
      if (bad || (count != 0 && count != 5)) exit 1; print (count == 5 ? "installed" : "fresh") }
  ' <<< "$inventory") || native_dependencies_fail incompatible_package_profile
  printf '%s\n' "$result"
}

# Inspect every parent without following links. All policy/configuration parents
# are root-owned and non-writable by services; only leaf ownership varies.
native_dependencies_path() {
  python3 -I -B - "$1" "$2" "$3" "${4:-$DEPS_ROOT_UID}" "${5:--}" "$DEPS_ROOT_UID" "$DEPS_PATH_BOUNDARY" <<'PY' || native_dependencies_fail unsafe_path
import os, stat, sys
path, kind, mode, uid, gid, root_uid, boundary = sys.argv[1:]
try:
    assert os.path.isabs(path) and os.path.normpath(path) == path
    assert os.path.commonpath([path, boundary]) == boundary
    parent = os.path.dirname(path)
    while True:
        info = os.lstat(parent)
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == int(root_uid) and info.st_mode & 0o022 == 0
        if parent == boundary: break
        assert parent != '/'
        parent = os.path.dirname(parent)
    info = os.lstat(path)
    assert (stat.S_ISREG(info.st_mode) and info.st_nlink == 1) if kind == 'file' else stat.S_ISDIR(info.st_mode)
    assert info.st_uid == int(uid) and (gid == '-' or info.st_gid == int(gid))
    assert stat.S_IMODE(info.st_mode) == int(mode, 8)
except (AssertionError, OSError, ValueError):
    sys.exit(1)
PY
}

# Contents are public repository/configuration data, never credentials.
native_dependencies_write_new() {
  python3 -I -B - "$1" "$2" "$3" "$DEPS_ROOT_UID" "$DEPS_PATH_BOUNDARY" <<'PY' || native_dependencies_fail unsafe_or_existing_path
import os, stat, sys
path, mode, content, root_uid, boundary = sys.argv[1:]
try:
    assert os.path.isabs(path) and os.path.normpath(path) == path
    assert os.path.commonpath([path, boundary]) == boundary
    parent = os.path.dirname(path)
    chain = []
    while parent != boundary:
        assert parent != '/'
        chain.append(parent)
        parent = os.path.dirname(parent)
    for parent in [boundary] + list(reversed(chain)):
        if not os.path.lexists(parent):
            os.mkdir(parent, 0o755)
            # chmod(follow_symlinks=False) is unavailable on Linux before
            # Python 3.10 / glibc 2.32; fchmod a no-follow directory handle.
            handle = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(handle, 0o755)
            finally:
                os.close(handle)
        info = os.lstat(parent)
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == int(root_uid) and info.st_mode & 0o022 == 0
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, int(mode, 8))
    with os.fdopen(fd, 'wb') as output:
        output.write(content.encode())
        output.flush()
        os.fchmod(output.fileno(), int(mode, 8))
        os.fsync(output.fileno())
except (AssertionError, OSError, ValueError):
    sys.exit(1)
PY
}

native_dependencies_verify_key() {
  local fingerprints listing home
  # --show-keys needs GnuPG 2.2.8+; older GnuPG (CentOS 7: 2.0) imports the
  # single downloaded key into a fresh private keyring and lists that instead.
  if ! listing=$(gpg --no-options --batch --homedir "$3" --with-colons --show-keys "$1" 2>/dev/null); then
    home=$(mktemp -d "$3/import.XXXXXXXX")
    gpg --no-options --batch --homedir "$home" --import "$1" >/dev/null 2>&1 || native_dependencies_fail repository_key_mismatch
    listing=$(gpg --no-options --batch --homedir "$home" --with-colons --fingerprint --list-keys 2>/dev/null) || native_dependencies_fail repository_key_mismatch
  fi
  fingerprints=$(awk -F: '$1 == "pub" { primary=1; next } primary && $1 == "fpr" { print $10; primary=0 }' <<< "$listing")
  [[ "$fingerprints" == "$2" ]] || native_dependencies_fail repository_key_mismatch
}

native_dependencies_repositories() (
  local key_dir path
  if [[ "$DEPS_FAMILY" == rhel ]]; then native_dependencies_rhel_repositories; exit; fi
  for path in "$DEPS_PG_KEY" "$DEPS_CH_KEY" "$DEPS_PG_SOURCE" "$DEPS_CH_SOURCE"; do
    [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail unsafe_or_existing_path
  done
  key_dir=$(mktemp -d /tmp/cdnca-native-dependencies.XXXXXXXX)
  trap '[[ "$key_dir" == /tmp/cdnca-native-dependencies.* ]] && rm -r -- "$key_dir"' EXIT
  mkdir -m 0700 "$key_dir/gpg"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key -o "$key_dir/ch.asc"
  native_dependencies_verify_key "$key_dir/ch.asc" 3A9EA1193A97B548BE1457D48919F6BD2B48D754 "$key_dir/gpg"
  native_dependencies_write_new "$DEPS_CH_KEY" 644 "$(< "$key_dir/ch.asc")"$'\n'
  native_dependencies_write_new "$DEPS_CH_SOURCE" 644 "deb [signed-by=$DEPS_CH_KEY arch=amd64] https://packages.clickhouse.com/deb stable main"$'\n'
  # The portable PostgreSQL build replaces the PGDG repository.
  [[ "$DEPS_PG_MODE" == package ]] || exit 0
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 https://www.postgresql.org/media/keys/ACCC4CF8.asc -o "$key_dir/pg.asc"
  native_dependencies_verify_key "$key_dir/pg.asc" B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8 "$key_dir/gpg"
  native_dependencies_write_new "$DEPS_PG_KEY" 644 "$(< "$key_dir/pg.asc")"$'\n'
  native_dependencies_write_new "$DEPS_PG_SOURCE" 644 "Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: $DEPS_PG_SUITE
Architectures: amd64
Components: main
Signed-By: $DEPS_PG_KEY
"
)

native_dependencies_loopback() {
  local group owner base path
  group=$(getent group clickhouse | cut -d: -f3)
  owner=$(getent passwd clickhouse | cut -d: -f3)
  [[ "$group" =~ ^[1-9][0-9]*$ && "$owner" =~ ^[1-9][0-9]*$ ]] || native_dependencies_fail clickhouse_account_missing
  [[ -f "$DEPS_LOOPBACK" && ! -L "$DEPS_LOOPBACK" ]] || native_dependencies_fail clickhouse_loopback_mismatch
  cmp -s "$DEPS_LOOPBACK" <(printf '%s' "$DEPS_LOOPBACK_CONTENT") || native_dependencies_fail clickhouse_loopback_mismatch
  base=$(dirname "$(dirname "$DEPS_LOOPBACK")")
  # The vendor package chowns its configuration to clickhouse. Freeze only this
  # explicitly enumerated configuration tree, using held no-follow descriptors.
  python3 -I -B - "$base" "$1" "$DEPS_ROOT_UID" "$owner" "$group" "$DEPS_PATH_BOUNDARY" <<'PY' || native_dependencies_fail unsafe_clickhouse_configuration
import os, stat, sys
base, operation, root_uid, service_uid, group, boundary = sys.argv[1:]
root_uid, service_uid, group = int(root_uid), int(service_uid), int(group)
fds = {}
try:
    assert os.path.isabs(base) and os.path.normpath(base) == base and os.path.commonpath([base, boundary]) == boundary
    parent = os.path.dirname(base)
    while True:
        info = os.lstat(parent)
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == root_uid and info.st_mode & 0o022 == 0
        if parent == boundary: break
        assert parent != '/'
        parent = os.path.dirname(parent)
    directories = ['', 'config.d', 'users.d']
    files = ['config.xml', 'users.xml', 'config.d/cdnca-loopback.xml']
    assert set(os.listdir(base)) == {'config.xml', 'users.xml', 'config.d', 'users.d'}
    assert set(os.listdir(os.path.join(base, 'config.d'))) == {'cdnca-loopback.xml'}
    user_files = set(os.listdir(os.path.join(base, 'users.d')))
    assert user_files <= {'cdnca-private-default.xml'}
    if user_files: files.append('users.d/cdnca-private-default.xml')
    for relative in directories + files:
        path = os.path.join(base, relative) if relative else base
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if relative in directories else 0))
        fds[relative] = fd
        info = os.fstat(fd)
        assert info.st_uid in (root_uid, service_uid) and info.st_gid in (0, group)
        if relative in directories:
            assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) in (0o500, 0o700, 0o750, 0o755)
        else:
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o400, 0o440, 0o640, 0o644)
    if operation == 'install':
        for relative in directories:
            info = os.fstat(fds[relative])
            if (info.st_uid, info.st_gid) != (root_uid, group): os.fchown(fds[relative], root_uid, group)
            if stat.S_IMODE(info.st_mode) != 0o750: os.fchmod(fds[relative], 0o750)
        assert set(os.listdir(base)) == {'config.xml', 'users.xml', 'config.d', 'users.d'}
        assert set(os.listdir(os.path.join(base, 'config.d'))) == {'cdnca-loopback.xml'}
        assert set(os.listdir(os.path.join(base, 'users.d'))) == user_files
        for relative, fd in fds.items():
            path = os.path.join(base, relative) if relative else base
            before, after = os.fstat(fd), os.lstat(path)
            assert before.st_dev == after.st_dev and before.st_ino == after.st_ino
            if relative in files:
                if (before.st_uid, before.st_gid) != (root_uid, group): os.fchown(fd, root_uid, group)
                mode = 0o644 if relative == 'config.d/cdnca-loopback.xml' else 0o640
                if stat.S_IMODE(before.st_mode) != mode: os.fchmod(fd, mode)
except (AssertionError, OSError, ValueError):
    sys.exit(1)
finally:
    for fd in fds.values(): os.close(fd)
PY
  for path in "$base" "$base/config.d" "$base/users.d"; do native_dependencies_path "$path" directory 750 "$DEPS_ROOT_UID" "$group"; done
  for path in "$base/config.xml" "$base/users.xml"; do native_dependencies_path "$path" file 640 "$DEPS_ROOT_UID" "$group"; done
  if [[ -e "$base/users.d/cdnca-private-default.xml" ]]; then native_dependencies_path "$base/users.d/cdnca-private-default.xml" file 640 "$DEPS_ROOT_UID" "$group"; fi
  native_dependencies_path "$DEPS_LOOPBACK" file 644 "$DEPS_ROOT_UID" "$group"
}

native_dependencies_clamav_config() {
  local path directory result
  DEPS_CLAM_CHANGED=false
  for path in "${DEPS_CLAM_UNOWNED_OVERRIDES[@]}"; do [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail clamav_configuration_mismatch; done
  directory=$(dirname "$DEPS_CLAM_DROPIN")
  if [[ -e "$directory" || -L "$directory" ]]; then
    native_dependencies_path "$directory" directory 755
    python3 -I -B -c 'import os, sys; sys.exit(set(os.listdir(sys.argv[1])) != {sys.argv[2]})' "$directory" "$(basename "$DEPS_CLAM_DROPIN")" || native_dependencies_fail clamav_configuration_mismatch
    native_dependencies_path "$DEPS_CLAM_DROPIN" file 644
    cmp -s "$DEPS_CLAM_DROPIN" <(printf '%s' "$DEPS_CLAM_DROPIN_CONTENT") || native_dependencies_fail clamav_configuration_mismatch
  fi
  native_dependencies_path "$DEPS_CLAM_CONFIG" file 644
  result=$(python3 -I -B - "$DEPS_CLAM_CONFIG" <<'PY'
import os, sys
path = sys.argv[1]
with open(path, encoding='utf8') as source: content = source.read()
lines = content.splitlines()
expected = {'LocalSocket': '/var/run/clamav/clamd.ctl', 'LocalSocketGroup': 'clamav', 'User': 'clamav', 'DatabaseDirectory': '/var/lib/clamav'}
for name, value in expected.items():
    if [line.split() for line in lines if line.split()[:1] == [name]] != [[name, value]]: sys.exit(1)
modes = [line for line in lines if line.split()[:1] == ['LocalSocketMode']]
if modes not in [['LocalSocketMode 666'], ['LocalSocketMode 660']]: sys.exit(1)
if modes == ['LocalSocketMode 666']:
    content = ''.join(line.replace('666', '660', 1) if line.rstrip('\r\n') == 'LocalSocketMode 666' else line for line in content.splitlines(keepends=True))
    with open(path, 'r+', encoding='utf8') as output:
        output.write(content)
        output.truncate()
        output.flush()
        os.fsync(output.fileno())
    print('changed')
PY
  ) || native_dependencies_fail clamav_configuration_mismatch
  if [[ "$result" == changed ]]; then DEPS_CLAM_CHANGED=true; fi
  if [[ ! -e "$DEPS_CLAM_DROPIN" ]]; then
    native_dependencies_write_new "$DEPS_CLAM_DROPIN" 644 "$DEPS_CLAM_DROPIN_CONTENT"
    DEPS_CLAM_CHANGED=true
  fi
}

# EL repositories: PGDG 17 for this EL major (repo metadata and packages
# signed), ClickHouse rpm (signed metadata, same key as the deb repository) and
# EPEL for ClamAV/certbot. Every key is pinned by primary fingerprint.
native_dependencies_rhel_repositories() (
  local key_dir path
  for path in "$DEPS_PG_KEY" "$DEPS_CH_KEY" "$DEPS_EPEL_KEY" "$DEPS_PG_SOURCE" "$DEPS_CH_SOURCE" "$DEPS_EPEL_SOURCE"; do
    [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail unsafe_or_existing_path
  done
  key_dir=$(mktemp -d /tmp/cdnca-native-dependencies.XXXXXXXX)
  trap '[[ "$key_dir" == /tmp/cdnca-native-dependencies.* ]] && rm -r -- "$key_dir"' EXIT
  mkdir -m 0700 "$key_dir/gpg"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL -o "$key_dir/pg.asc"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key -o "$key_dir/ch.asc"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 --max-filesize 1048576 "https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-$DEPS_EL_MAJOR" -o "$key_dir/epel.asc"
  native_dependencies_verify_key "$key_dir/pg.asc" D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20 "$key_dir/gpg"
  native_dependencies_verify_key "$key_dir/ch.asc" 3A9EA1193A97B548BE1457D48919F6BD2B48D754 "$key_dir/gpg"
  case "$DEPS_EL_MAJOR" in
    8) native_dependencies_verify_key "$key_dir/epel.asc" 94E279EB8D8F25B21810ADF121EA45AB2F86D6A1 "$key_dir/gpg" ;;
    9) native_dependencies_verify_key "$key_dir/epel.asc" FF8AD1344597106ECE813B918A3872BF3228467C "$key_dir/gpg" ;;
    10) native_dependencies_verify_key "$key_dir/epel.asc" 7D8D15CBFC4E62688591FB2633D98517E37ED158 "$key_dir/gpg" ;;
    *) native_dependencies_fail unsupported_os ;;
  esac
  native_dependencies_write_new "$DEPS_PG_KEY" 644 "$(< "$key_dir/pg.asc")"$'\n'
  native_dependencies_write_new "$DEPS_CH_KEY" 644 "$(< "$key_dir/ch.asc")"$'\n'
  native_dependencies_write_new "$DEPS_EPEL_KEY" 644 "$(< "$key_dir/epel.asc")"$'\n'
  native_dependencies_write_new "$DEPS_PG_SOURCE" 644 "[cdnca-pgdg17]
name=PostgreSQL 17 (PGDG) for EL $DEPS_EL_MAJOR
baseurl=https://download.postgresql.org/pub/repos/yum/17/redhat/$DEPS_PG_SUITE
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file://$DEPS_PG_KEY
"
  native_dependencies_write_new "$DEPS_CH_SOURCE" 644 "[cdnca-clickhouse]
name=ClickHouse stable
baseurl=https://packages.clickhouse.com/rpm/stable/
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=file://$DEPS_CH_KEY
"
  native_dependencies_write_new "$DEPS_EPEL_SOURCE" 644 "[cdnca-epel]
name=Extra Packages for Enterprise Linux $DEPS_EL_MAJOR
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-$DEPS_EL_MAJOR&arch=x86_64
enabled=1
gpgcheck=1
gpgkey=file://$DEPS_EPEL_KEY
"
)

# EPEL ships clamd@scan with every socket directive commented out. Keep the
# vendor file and its comments; set exactly one value per directive at the end.
native_dependencies_rhel_clamav_config() {
  DEPS_CLAM_CHANGED=false
  local path result
  for path in "${DEPS_CLAM_UNOWNED_OVERRIDES[@]}"; do [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail clamav_configuration_mismatch; done
  native_dependencies_path "$DEPS_CLAM_CONFIG" file 644
  result=$(python3 -I -B - "$DEPS_CLAM_CONFIG" "$DEPS_CLAM_SOCKET" "$DEPS_CLAM_GROUP" "$DEPS_CLAM_USER" "$DEPS_CLAM_DATABASE" <<'PY'
import os, sys
path, socket_path, group, user, database = sys.argv[1:]
expected = [('LocalSocket', socket_path), ('LocalSocketGroup', group), ('LocalSocketMode', '660'),
            ('User', user), ('DatabaseDirectory', database)]
names = {name for name, _ in expected} | {'Example', 'TCPSocket', 'TCPAddr'}
with open(path, encoding='utf8') as source: lines = source.read().splitlines()
active = [line.split() for line in lines if line.strip() and not line.lstrip().startswith('#')]
current = [words for words in active if words[0] in names]
if current == [[name, value] for name, value in expected]: sys.exit(0)
# Only the vendor default (User clamscan alone) may be rewritten.
if current not in ([], [['User', user]]): sys.exit(1)
kept = [line for line in lines if line.split()[:1] != ['User']]
content = '\n'.join(kept + ['', '# cdnca native profile'] + [name + ' ' + value for name, value in expected]) + '\n'
with open(path, 'r+', encoding='utf8') as output:
    output.write(content)
    output.truncate()
    output.flush()
    os.fsync(output.fileno())
print('changed')
PY
  ) || native_dependencies_fail clamav_configuration_mismatch
  if [[ "$result" == changed ]]; then DEPS_CLAM_CHANGED=true; fi
}

native_dependencies_rhel_install() {
  local state nginx_fresh=false path redis_package=redis
  local base=(jq openssl ca-certificates vim-common util-linux file tar unzip python3 gnupg2 iproute procps-ng policycoreutils-python-utils)
  [[ "$DEPS_EL_MAJOR" != 10 ]] || redis_package=valkey
  base+=("$redis_package")
  state=$(native_dependencies_packages)
  if [[ "$state" == installed ]]; then
    native_dependencies_loopback install
    native_dependencies_rhel_clamav_config
    if [[ "$DEPS_CLAM_CHANGED" == true ]]; then systemctl restart clamd@scan.service; fi
    if ! systemctl is-enabled --quiet clamav-freshclam.service; then systemctl enable clamav-freshclam.service; fi
    # install-control.sh --cleanup-failed stops and disables the services a failed install started (packages kept).
    systemctl enable --now postgresql-17.service "$DEPS_REDIS_UNIT" clickhouse-server.service
    native_dependencies_check
    return
  fi
  native_dependencies_fresh
  if [[ "$DEPS_ENV" == bt && -x "$DEPS_BT_NGINX" ]]; then
    :
  elif ! rpm -q --quiet nginx; then
    for path in "${DEPS_NGINX_GUARDS[@]}"; do
      [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail existing_nginx_requires_review
    done
    # EL packages never start on install, so a BaoTa-held 80 does not matter.
    [[ "$DEPS_ENV" == bt ]] || ss -H -ltn | awk '$4 ~ /:80$/ { exit 1 }' || native_dependencies_fail nginx_port_in_use
    nginx_fresh=true
    base+=(nginx)
  fi
  # EL8 AppStream defaults are nginx 1.14, redis 5 and a postgresql module that
  # masks the PGDG packages; select the streams the profile is tested with.
  if [[ "$DEPS_EL_MAJOR" == 8 ]]; then
    dnf -y module disable postgresql
    dnf -y module enable nginx:1.24 redis:6
  fi
  dnf -y install "${base[@]}"
  if [[ "$nginx_fresh" == true ]]; then systemctl disable --now nginx.service; fi
  native_dependencies_repositories
  native_dependencies_write_new "$DEPS_LOOPBACK" 644 "$DEPS_LOOPBACK_CONTENT"
  dnf -y install "postgresql17-server-$DEPS_PG_VERSION" "postgresql17-$DEPS_PG_VERSION" "clickhouse-server-$DEPS_CH_VERSION" \
    "clickhouse-client-$DEPS_CH_VERSION" "clickhouse-common-static-$DEPS_CH_VERSION" clamav clamd clamav-freshclam
  native_dependencies_loopback install
  native_dependencies_rhel_clamav_config
  # PGDG initdb: local peer, loopback scram-sha-256 (control-api uses TCP).
  PGSETUP_INITDB_OPTIONS='--auth-local=peer --auth-host=scram-sha-256' /usr/pgsql-17/bin/postgresql-17-setup initdb
  systemctl stop clamav-freshclam.service
  # EL: freshclam writes as clamupdate, clamd@scan reads as clamscan; the
  # installer's umask 077 would leave the databases 0600 and clamd unable to load them.
  (umask 022; timeout 900 freshclam --foreground --stdout) || native_dependencies_fail clamav_database_update_failed
  native_dependencies_set_ports
  systemctl daemon-reload
  systemctl enable --now postgresql-17.service "$DEPS_REDIS_UNIT" clickhouse-server.service clamd@scan.service clamav-freshclam.service
  native_dependencies_check
}

native_dependencies_rhel_check() {
  local command version
  [[ $(native_dependencies_packages) == installed ]] || native_dependencies_fail incomplete_package_profile
  # PGDG registers psql but not pg_isready as an alternative; use its fixed path.
  for command in curl jq openssl python3 gpg sha256sum xxd uuidgen file tar unzip psql ss semanage restorecon /usr/pgsql-17/bin/pg_isready; do
    command -v "$command" >/dev/null || native_dependencies_fail missing_dependency_tool
  done
  command -v redis-cli >/dev/null || command -v valkey-cli >/dev/null || native_dependencies_fail missing_dependency_tool
  native_dependencies_nginx -v >/dev/null 2>&1 || native_dependencies_fail nginx_binary_unavailable
  native_dependencies_loopback check
  native_dependencies_service postgresql-17.service
  [[ $(cat "$DEPS_PG_DATA/PG_VERSION" 2>/dev/null) == 17 ]] || native_dependencies_fail incompatible_postgresql_cluster
  /usr/pgsql-17/bin/pg_isready -h 127.0.0.1 -p "$DEPS_PG_PORT" -q || native_dependencies_fail postgresql_not_ready
  version=$(runuser -u postgres -- "$DEPS_PG_PSQL" -X -h "$DEPS_PG_SOCKET_DIR" -p "$DEPS_PG_PORT" -U postgres -d postgres -Atqc 'SHOW server_version_num') || native_dependencies_fail postgresql_not_ready
  [[ "$version" == 170011 ]] || native_dependencies_fail postgresql_version_mismatch
  native_dependencies_service "$DEPS_REDIS_UNIT"
  local cli=redis-cli
  command -v redis-cli >/dev/null || cli=valkey-cli
  [[ $("$cli" -h 127.0.0.1 -p "$DEPS_REDIS_PORT" --raw PING) == PONG ]] || native_dependencies_fail redis_not_ready
  native_dependencies_clickhouse
  native_dependencies_clamav
  printf 'native_dependencies: ready %s arch=amd64 postgresql=%s clickhouse=%s\n' "$DEPS_OS_LABEL" "$DEPS_PG_VERSION" "$DEPS_CH_VERSION"
}

native_dependencies_service() {
  local attempt
  systemctl is-enabled --quiet "${2:-$1}" || native_dependencies_fail service_not_ready
  for ((attempt=0; attempt<30; attempt++)); do
    if systemctl is-active --quiet "$1"; then return; fi
    sleep 1
  done
  native_dependencies_fail service_not_ready
}

native_dependencies_clickhouse() {
  local version='' attempt pid listeners
  local client=(clickhouse-client --host 127.0.0.1 --port "$DEPS_CH_TCP_PORT" --connect_timeout 3 --receive_timeout 5)
  native_dependencies_service clickhouse-server.service
  if [[ -e "$DEPS_ADMIN_CONFIG" || -L "$DEPS_ADMIN_CONFIG" ]]; then
    native_dependencies_path "$(dirname "$DEPS_ADMIN_CONFIG")" directory 700
    native_dependencies_path "$DEPS_ADMIN_CONFIG" file 600
    client+=(--config-file "$DEPS_ADMIN_CONFIG")
  else
    client+=(--user default)
  fi
  for ((attempt=0; attempt<30; attempt++)); do
    if version=$("${client[@]}" --query 'SELECT version()' 2>/dev/null); then break; fi
    sleep 1
  done
  [[ "$version" == "$DEPS_CH_VERSION" ]] || native_dependencies_fail clickhouse_not_ready
  pid=$(systemctl show --property MainPID --value clickhouse-server.service)
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || native_dependencies_fail clickhouse_not_ready
  listeners=$(ss -H -ltnp) || native_dependencies_fail clickhouse_listener_not_loopback
  awk -v pid="$pid" -v http_addr="127.0.0.1:$DEPS_CH_HTTP_PORT" -v native_addr="127.0.0.1:$DEPS_CH_TCP_PORT" '
    $0 ~ ("pid=" pid "[,)]") { count++; if ($4 !~ /^127[.]0[.]0[.]1:[0-9]+$/) bad=1; if ($4 == http_addr) http=1; if ($4 == native_addr) native=1 }
    END { if (!count || bad || !http || !native) exit 1 }
  ' <<< "$listeners" || native_dependencies_fail clickhouse_listener_not_loopback
}

native_dependencies_clamav() {
  local uid gid name path found version
  for name in "${DEPS_CLAM_UNITS[@]}"; do native_dependencies_service "$name"; done
  uid=$(getent passwd "$DEPS_CLAM_USER" | cut -d: -f3)
  gid=$(getent group "$DEPS_CLAM_GROUP" | cut -d: -f3)
  [[ "$uid" =~ ^[1-9][0-9]*$ && "$gid" =~ ^[1-9][0-9]*$ ]] || native_dependencies_fail clamav_not_ready
  for name in main daily; do
    found=false
    for path in "$DEPS_CLAM_DATABASE/$name.cvd" "$DEPS_CLAM_DATABASE/$name.cld"; do
      if [[ -s "$path" && ! -L "$path" ]]; then found=true; fi
    done
    [[ "$found" == true ]] || native_dependencies_fail clamav_database_missing
  done
  # VERSION may deliberately be disabled. Inspect local metadata without
  # exposing it, then prove the daemon can accept clean content and reject EICAR.
  version=$(timeout 10 clamd ${DEPS_CLAMD_ARGS[@]+"${DEPS_CLAMD_ARGS[@]}"} --version 2>/dev/null) || native_dependencies_fail clamav_not_ready
  python3 -I -B - "$DEPS_CLAM_SOCKET" "$uid" "$gid" "$version" <<'PY' || native_dependencies_fail clamav_not_ready
import errno, os, re, socket, stat, struct, sys, time
path, uid, gid, version = sys.argv[1:]
try:
    assert re.fullmatch(r'ClamAV [0-9]+\.[0-9]+\.[0-9]+/[1-9][0-9]*/[^\r\n\x00]+', version)
    clean = b'cdnca-clamd-readiness-v1\n'
    eicar = br'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    probes = [(b'zPING\0', b'PONG\0')]
    for content, expected in [(clean, b'stream: OK\0'), (eicar, None)]:
        probes.append((b'zINSTREAM\0' + struct.pack('!I', len(content)) + content + struct.pack('!I', 0), expected))
    # systemd active can precede database loading. Retry only absent/unready
    # transport, never permissions, protocol errors or a failed scan verdict.
    deadline = time.monotonic() + 120
    while True:
        response = b''
        try:
            for request, expected in probes:
                response = b''
                info = os.lstat(path)
                assert stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o660
                assert info.st_uid == int(uid) and info.st_gid == int(gid)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: raise TimeoutError()
                    connection.settimeout(min(5, remaining))
                    connection.connect(path)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0: raise TimeoutError()
                    connection.settimeout(min(5, remaining))
                    connection.sendall(request)
                    while len(response) < 1024:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0: raise TimeoutError()
                        connection.settimeout(min(5, remaining))
                        chunk = connection.recv(1024 - len(response))
                        if not chunk: break
                        response += chunk
                        if expected is not None:
                            assert expected.startswith(response)
                        else:
                            assert b'stream: '.startswith(response) or response.startswith(b'stream: ')
                            if b'\0' in response:
                                assert re.fullmatch(rb'stream: [A-Za-z0-9_.-]+ FOUND\0', response) and b'eicar' in response.lower()
                if expected is None:
                    assert re.fullmatch(rb'stream: [A-Za-z0-9_.-]+ FOUND\0', response) and b'eicar' in response.lower()
                else:
                    assert response == expected
            break
        except OSError as error:
            if response or not (isinstance(error, (TimeoutError, socket.timeout)) or error.errno in (
                    errno.ENOENT, errno.ECONNREFUSED, errno.ECONNRESET, errno.EPIPE, errno.ETIMEDOUT)):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise
            time.sleep(min(1, remaining))
except (AssertionError, OSError):
    sys.exit(1)
PY
}

native_dependencies_check() {
  local command version
  if [[ "$DEPS_FAMILY" == rhel ]]; then native_dependencies_rhel_check; return; fi
  [[ $(native_dependencies_packages) == installed ]] || native_dependencies_fail incomplete_package_profile
  for command in curl jq openssl redis-cli python3 gpg sha256sum xxd uuidgen file tar unzip psql pg_isready ss; do
    command -v "$command" >/dev/null || native_dependencies_fail missing_dependency_tool
  done
  native_dependencies_nginx -v >/dev/null 2>&1 || native_dependencies_fail nginx_binary_unavailable
  native_dependencies_loopback check
  if [[ "$DEPS_PG_MODE" == portable ]]; then
    native_dependencies_portable_pg_check
    native_dependencies_service postgresql-17.service
    [[ $(cat "$DEPS_PG_DATA/PG_VERSION" 2>/dev/null) == 17 ]] || native_dependencies_fail incompatible_postgresql_cluster
  else
    command -v pg_lsclusters >/dev/null || native_dependencies_fail missing_dependency_tool
    native_dependencies_service postgresql@17-main.service postgresql.service
    [[ $(pg_lsclusters --no-header | awk '{ print $1 " " $2 " " $3 }') == "17 main $DEPS_PG_PORT" ]] || native_dependencies_fail incompatible_postgresql_cluster
  fi
  pg_isready -h 127.0.0.1 -p "$DEPS_PG_PORT" -q || native_dependencies_fail postgresql_not_ready
  version=$(runuser -u postgres -- "$DEPS_PG_PSQL" -X -h "$DEPS_PG_SOCKET_DIR" -p "$DEPS_PG_PORT" -U postgres -d postgres -Atqc 'SHOW server_version_num') || native_dependencies_fail postgresql_not_ready
  [[ "$version" == 170011 ]] || native_dependencies_fail postgresql_version_mismatch
  native_dependencies_service redis-server.service
  [[ $(redis-cli -h 127.0.0.1 -p "$DEPS_REDIS_PORT" --raw PING) == PONG ]] || native_dependencies_fail redis_not_ready
  native_dependencies_clickhouse
  if [[ "$DEPS_CLAM_MODE" == portable ]]; then native_dependencies_portable_clamav_check; fi
  native_dependencies_clamav
  printf 'native_dependencies: ready %s arch=amd64 postgresql=%s clickhouse=%s\n' "$DEPS_OS_LABEL" "$DEPS_PG_VERSION" "$DEPS_CH_VERSION"
}

native_dependencies_fresh() {
  local path listeners
  local -a extra=("$(dirname "$DEPS_CLAM_DROPIN")")
  [[ "$DEPS_FAMILY" != rhel ]] || extra=("$DEPS_EPEL_KEY" "$DEPS_EPEL_SOURCE")
  for path in "${DEPS_PROTECTED_PATHS[@]}" "${DEPS_CLAM_UNOWNED_OVERRIDES[@]}" "${extra[@]}" "$DEPS_PG_KEY" "$DEPS_CH_KEY" "$DEPS_PG_SOURCE" "$DEPS_CH_SOURCE"; do
    [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail existing_state_requires_review
  done
  listeners=$(ss -H -ltn) || native_dependencies_fail listener_inventory_unavailable
  awk -v ports="$DEPS_PG_PORT|$DEPS_CH_HTTP_PORT|$DEPS_CH_TCP_PORT|$DEPS_CH_MYSQL_PORT|$DEPS_CH_POSTGRESQL_PORT|$DEPS_CH_INTERSERVER_PORT$([[ "$DEPS_ENV" != bt ]] || printf '|%s' "$DEPS_REDIS_PORT")" \
    '$4 ~ ("^.*:(" ports ")$") { exit 1 }' <<< "$listeners" || native_dependencies_fail dependency_port_in_use
}

native_dependencies_install() {
  local state nginx_fresh=false path
  local base=(curl jq openssl ca-certificates coreutils xxd uuid-runtime file tar unzip redis-server python3 gnupg iproute2)
  local postgresql=("postgresql-17=$DEPS_PG_VERSION" "postgresql-client-17=$DEPS_PG_VERSION")
  local clamav=(clamav clamav-daemon clamav-freshclam)
  if [[ "$DEPS_FAMILY" == rhel ]]; then native_dependencies_rhel_install; return; fi
  if [[ "$DEPS_PG_MODE" == portable ]]; then postgresql=(); fi
  if [[ "$DEPS_CLAM_MODE" == portable ]]; then clamav=(); fi
  state=$(native_dependencies_packages)
  if [[ "$state" == installed ]]; then
    native_dependencies_loopback install
    if [[ "$DEPS_CLAM_MODE" == package ]]; then native_dependencies_clamav_config; else DEPS_CLAM_CHANGED=false; fi
    if [[ "$DEPS_CLAM_CHANGED" == true ]]; then
      systemctl daemon-reload
      systemctl restart clamav-daemon.socket clamav-daemon.service
    fi
    # Enable the already-running vendor updater without triggering a DB update.
    if ! systemctl is-enabled --quiet clamav-freshclam.service; then systemctl enable clamav-freshclam.service; fi
    # install-control.sh --cleanup-failed stops and disables the services a failed install started (packages kept).
    systemctl enable --now "${DEPS_PG_UNITS[@]}" redis-server.service clickhouse-server.service
    native_dependencies_check
    return
  fi
  native_dependencies_fresh
  # BaoTa: its nginx serves the control web too; the distribution package would
  # take over /etc/init.d/nginx (BaoTa's own service script).
  if [[ "$DEPS_ENV" == bt && -x "$DEPS_BT_NGINX" ]]; then
    :
  elif ! dpkg-query -W -f='${db:Status-Status}' nginx 2>/dev/null | grep -qx installed; then
    for path in "${DEPS_NGINX_GUARDS[@]}"; do
      [[ ! -e "$path" && ! -L "$path" ]] || native_dependencies_fail existing_nginx_requires_review
    done
    # Held starts (BaoTa) keep the package from binding 80 on install.
    [[ "$DEPS_ENV" == bt ]] || ss -H -ltn | awk '$4 ~ /:80$/ { exit 1 }' || native_dependencies_fail nginx_port_in_use
    nginx_fresh=true
    base+=(nginx)
  fi
  export DEBIAN_FRONTEND=noninteractive
  native_dependencies_hold_starts
  trap native_dependencies_release_starts EXIT
  apt-get update
  apt-get install -y --no-install-recommends "${base[@]}"
  if [[ "$nginx_fresh" == true ]]; then systemctl disable --now nginx.service; fi
  native_dependencies_repositories
  native_dependencies_write_new "$DEPS_LOOPBACK" 644 "$DEPS_LOOPBACK_CONTENT"
  if [[ "$DEPS_CLAM_MODE" == package ]]; then native_dependencies_write_new "$DEPS_CLAM_DROPIN" 644 "$DEPS_CLAM_DROPIN_CONTENT"; fi
  systemctl daemon-reload
  apt-get update
  apt-get install -y --no-install-recommends ${postgresql[@]+"${postgresql[@]}"} "clickhouse-server=$DEPS_CH_VERSION" "clickhouse-client=$DEPS_CH_VERSION" "clickhouse-common-static=$DEPS_CH_VERSION" ${clamav[@]+"${clamav[@]}"}
  if [[ "$DEPS_PG_MODE" == portable ]]; then native_dependencies_portable_pg_install "$DEPS_PG_PORTABLE_INPUT"; fi
  native_dependencies_loopback install
  if [[ "$DEPS_CLAM_MODE" == portable ]]; then
    native_dependencies_portable_clamav_install "$DEPS_CLAM_PORTABLE_INPUT"
    DEPS_CLAM_CHANGED=false
  else
    native_dependencies_clamav_config
    systemctl stop clamav-freshclam.service
  fi
  if [[ "$DEPS_CLAM_MODE" == portable ]]; then
    CURL_CA_BUNDLE=$DEPS_CA_BUNDLE timeout 900 freshclam --foreground --stdout "--config-file=$DEPS_FRESHCLAM_CONFIG" || native_dependencies_fail clamav_database_update_failed
  else
    timeout 900 freshclam --foreground --stdout || native_dependencies_fail clamav_database_update_failed
  fi
  native_dependencies_set_ports
  native_dependencies_release_starts
  systemctl daemon-reload
  systemctl enable --now "${DEPS_PG_UNITS[@]}" redis-server.service clickhouse-server.service "${DEPS_CLAM_ENABLE[@]}"
  if [[ "$DEPS_CLAM_CHANGED" == true ]]; then systemctl restart clamav-daemon.socket clamav-daemon.service; fi
  native_dependencies_check
}

# Inputs that are not repository packages: "postgresql ARCHIVE SHA256" when
# this host uses the portable build, nothing otherwise.
native_dependencies_requirements() {
  if [[ "$DEPS_PG_MODE" == portable ]]; then printf 'postgresql %s %s\n' "$DEPS_PG_PORTABLE_ARCHIVE" "$DEPS_PG_PORTABLE_SHA256"; fi
  if [[ "$DEPS_CLAM_MODE" == portable ]]; then printf 'clamav %s %s\n' "$DEPS_CLAM_PORTABLE_ARCHIVE" "$DEPS_CLAM_PORTABLE_SHA256"; fi
}

native_dependencies_main() {
  local usage='usage: install-ubuntu-dependencies.sh install|check|requirements (install takes --postgresql-archive/--clamav-archive FILE where requirements lists them)'
  local action=${1-}
  [[ "$action" == install || "$action" == check || "$action" == requirements ]] || native_dependencies_fail "$usage"
  shift
  while [[ $# -gt 0 && "$action" == install ]]; do
    case "${1-}:$#" in
      --postgresql-archive:[2-9]) [[ -z "$DEPS_PG_PORTABLE_INPUT" ]] || native_dependencies_fail "$usage"; DEPS_PG_PORTABLE_INPUT=$2 ;;
      --clamav-archive:[2-9]) [[ -z "$DEPS_CLAM_PORTABLE_INPUT" ]] || native_dependencies_fail "$usage"; DEPS_CLAM_PORTABLE_INPUT=$2 ;;
      *) native_dependencies_fail "$usage" ;;
    esac
    shift 2
  done
  [[ $# == 0 ]] || native_dependencies_fail "$usage"
  set -- "$action"
  native_dependencies_profile
  native_dependencies_ports
  if [[ "$1" == requirements ]]; then native_dependencies_requirements; return; fi
  # Each archive is required exactly when this host uses that portable build.
  if [[ "$1" == install ]]; then
    [[ ( "$DEPS_PG_MODE" == portable && -n "$DEPS_PG_PORTABLE_INPUT" ) || ( "$DEPS_PG_MODE" != portable && -z "$DEPS_PG_PORTABLE_INPUT" ) ]] || native_dependencies_fail "$usage"
    [[ ( "$DEPS_CLAM_MODE" == portable && -n "$DEPS_CLAM_PORTABLE_INPUT" ) || ( "$DEPS_CLAM_MODE" != portable && -z "$DEPS_CLAM_PORTABLE_INPUT" ) ]] || native_dependencies_fail "$usage"
  fi
  if [[ "$1" == check ]]; then native_dependencies_check; return; fi
  if ! command -v python3 >/dev/null || ! command -v flock >/dev/null || ! command -v ss >/dev/null; then native_dependencies_fail missing_base_tool; fi
  if [[ ! -e "$DEPS_LOCK" && ! -L "$DEPS_LOCK" ]]; then native_dependencies_write_new "$DEPS_LOCK" 600 ''; fi
  native_dependencies_path "$DEPS_LOCK" file 600
  exec 9<>"$DEPS_LOCK"
  flock -n 9 || native_dependencies_fail another_dependency_install_running
  native_dependencies_install
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then native_dependencies_main "$@"; fi
