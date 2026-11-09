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

# >>> BEGIN repo-keys (generated from scripts/lib/repo-keys.sh; do not edit here)
# shellcheck shell=bash
# 软件源签名公钥，随安装器内置，安装时不再在线下载。
#
# 唯一源文件：由 scripts/sync-install-preflight.mjs 逐字嵌入
# scripts/native-runtime/install-ubuntu-dependencies.sh 的 “BEGIN/END repo-keys” 标记之间，
# 修改后运行 node scripts/sync-install-preflight.mjs。
# 主钥指纹仍由调用方写死，写入系统前照旧核对；tests/install-repo-keys.test.mjs 核对
# 指纹、主钥与子钥都没有过期时间、内容与上游文件一致（SHA-256，末尾换行除外）。
# 更新办法：从下表上游 HTTPS 地址取新文件，与上游公布的指纹核对，替换对应块并更新测试里的 SHA-256。
# 取回日期 2026-11-09。
#   名称       上游地址                                                             主钥指纹
#   pgdg-apt   https://www.postgresql.org/media/keys/ACCC4CF8.asc                    B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
#   clickhouse https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key       3A9EA1193A97B548BE1457D48919F6BD2B48D754
#   pgdg-rhel  https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20
#   epel-8     https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-8              94E279EB8D8F25B21810ADF121EA45AB2F86D6A1
#   epel-9     https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-9              FF8AD1344597106ECE813B918A3872BF3228467C
#   epel-10    https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-10             7D8D15CBFC4E62688591FB2633D98517E37ED158

# repo_key_armor NAME：把内置公钥（ASCII armor）写到标准输出；未知名称返回 1。
repo_key_armor() {
  case "$1" in
    pgdg-apt) cat <<'CDNCA_REPO_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=DA1T
-----END PGP PUBLIC KEY BLOCK-----
CDNCA_REPO_KEY
      ;;
    clickhouse) cat <<'CDNCA_REPO_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
e/vtNUUUDp3i8qczTjuaVywRbE3+9xjjsSiI
=c48w
-----END PGP PUBLIC KEY BLOCK-----
CDNCA_REPO_KEY
      ;;
    pgdg-rhel) cat <<'CDNCA_REPO_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=Elfg
-----END PGP PUBLIC KEY BLOCK-----
CDNCA_REPO_KEY
      ;;
    epel-8) cat <<'CDNCA_REPO_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBFz3zvsBEADJOIIWllGudxnpvJnkxQz2CtoWI7godVnoclrdl83kVjqSQp+2
dgxuG5mUiADUfYHaRQzxKw8efuQnwxzU9kZ70ngCxtmbQWGmUmfSThiapOz00018
+eo5MFabd2vdiGo1y+51m2sRDpN8qdCaqXko65cyMuLXrojJHIuvRA/x7iqOrRfy
a8x3OxC4PEgl5pgDnP8pVK0lLYncDEQCN76D9ubhZQWhISF/zJI+e806V71hzfyL
/Mt3mQm/li+lRKU25Usk9dWaf4NH/wZHMIPAkVJ4uD4H/uS49wqWnyiTYGT7hUbi
ecF7crhLCmlRzvJR8mkRP6/4T/F3tNDPWZeDNEDVFUkTFHNU6/h2+O398MNY/fOh
yKaNK3nnE0g6QJ1dOH31lXHARlpFOtWt3VmZU0JnWLeYdvap4Eff9qTWZJhI7Cq0
Wm8DgLUpXgNlkmquvE7P2W5EAr2E5AqKQoDbfw/GiWdRvHWKeNGMRLnGI3QuoX3U
pAlXD7v13VdZxNydvpeypbf/AfRyrHRKhkUj3cU1pYkM3DNZE77C5JUe6/0nxbt4
ETUZBTgLgYJGP8c7PbkVnO6I/KgL1jw+7MW6Az8Ox+RXZLyGMVmbW/TMc8haJfKL
MoUo3TVk8nPiUhoOC0/kI7j9ilFrBxBU5dUtF4ITAWc8xnG6jJs/IsvRpQARAQAB
tChGZWRvcmEgRVBFTCAoOCkgPGVwZWxAZmVkb3JhcHJvamVjdC5vcmc+iQI4BBMB
AgAiBQJc9877AhsPBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRAh6kWrL4bW
oWagD/4xnLWws34GByVDQkjprk0fX7Iyhpm/U7BsIHKspHLL+Y46vAAGY/9vMvdE
0fcr9Ek2Zp7zE1RWmSCzzzUgTG6BFoTG1H4Fho/7Z8BXK/jybowXSZfqXnTOfhSF
alwDdwlSJvfYNV9MbyvbxN8qZRU1z7PEWZrIzFDDToFRk0R71zHpnPTNIJ5/YXTw
NqU9OxII8hMQj4ufF11040AJQZ7br3rzerlyBOB+Jd1zSPVrAPpeMyJppWFHSDAI
WK6x+am13VIInXtqB/Cz4GBHLFK5d2/IYspVw47Solj8jiFEtnAq6+1Aq5WH3iB4
bE2e6z00DSF93frwOyWN7WmPIoc2QsNRJhgfJC+isGQAwwq8xAbHEBeuyMG8GZjz
xohg0H4bOSEujVLTjH1xbAG4DnhWO/1VXLX+LXELycO8ZQTcjj/4AQKuo4wvMPrv
9A169oETG+VwQlNd74VBPGCvhnzwGXNbTK/KH1+WRH0YSb+41flB3NKhMSU6dGI0
SGtIxDSHhVVNmx2/6XiT9U/znrZsG5Kw8nIbbFz+9MGUUWgJMsd1Zl9R8gz7V9fp
n7L7y5LhJ8HOCMsY/Z7/7HUs+t/A1MI4g7Q5g5UuSZdgi0zxukiWuCkLeAiAP4y7
zKK4OjJ644NDcWCHa36znwVmkz3ixL8Q0auR15Oqq2BjR/fyog==
=84m8
-----END PGP PUBLIC KEY BLOCK-----
CDNCA_REPO_KEY
      ;;
    epel-9) cat <<'CDNCA_REPO_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGE3mOsBEACsU+XwJWDJVkItBaugXhXIIkb9oe+7aadELuVo0kBmc3HXt/Yp
CJW9hHEiGZ6z2jwgPqyJjZhCvcAWvgzKcvqE+9i0NItV1rzfxrBe2BtUtZmVcuE6
2b+SPfxQ2Hr8llaawRjt8BCFX/ZzM4/1Qk+EzlfTcEcpkMf6wdO7kD6ulBk/tbsW
DHX2lNcxszTf+XP9HXHWJlA2xBfP+Dk4gl4DnO2Y1xR0OSywE/QtvEbN5cY94ieu
n7CBy29AleMhmbnx9pw3NyxcFIAsEZHJoU4ZW9ulAJ/ogttSyAWeacW7eJGW31/Z
39cS+I4KXJgeGRI20RmpqfH0tuT+X5Da59YpjYxkbhSK3HYBVnNPhoJFUc2j5iKy
XLgkapu1xRnEJhw05kr4LCbud0NTvfecqSqa+59kuVc+zWmfTnGTYc0PXZ6Oa3rK
44UOmE6eAT5zd/ToleDO0VesN+EO7CXfRsm7HWGpABF5wNK3vIEF2uRr2VJMvgqS
9eNwhJyOzoca4xFSwCkc6dACGGkV+CqhufdFBhmcAsUotSxe3zmrBjqA0B/nxIvH
DVgOAMnVCe+Lmv8T0mFgqZSJdIUdKjnOLu/GRFhjDKIak4jeMBMTYpVnU+HhMHLq
uDiZkNEvEEGhBQmZuI8J55F/a6UURnxUwT3piyi3Pmr2IFD7ahBxPzOBCQARAQAB
tCdGZWRvcmEgKGVwZWw5KSA8ZXBlbEBmZWRvcmFwcm9qZWN0Lm9yZz6JAk4EEwEI
ADgWIQT/itE0RZcQbs6BO5GKOHK/MihGfAUCYTeY6wIbDwULCQgHAgYVCgkICwIE
FgIDAQIeAQIXgAAKCRCKOHK/MihGfFX/EACBPWv20+ttYu1A5WvtHJPzwbj0U4yF
3zTQpBglQ2UfkRpYdipTlT3Ih6j5h2VmgRPtINCc/ZE28adrWpBoeFIS2YAKOCLC
nZYtHl2nCoLq1U7FSttUGsZ/t8uGCBgnugTfnIYcmlP1jKKA6RJAclK89evDQX5n
R9ZD+Cq3CBMlttvSTCht0qQVlwycedH8iWyYgP/mF0W35BIn7NuuZwWhgR00n/VG
4nbKPOzTWbsP45awcmivdrS74P6mL84WfkghipdmcoyVb1B8ZP4Y/Ke0RXOnLhNe
CfrXXvuW+Pvg2RTfwRDtehGQPAgXbmLmz2ZkV69RGIr54HJv84NDbqZovRTMr7gL
9k3ciCzXCiYQgM8yAyGHV0KEhFSQ1HV7gMnt9UmxbxBE2pGU7vu3CwjYga5DpwU7
w5wu1TmM5KgZtZvuWOTDnqDLf0cKoIbW8FeeCOn24elcj32bnQDuF9DPey1mqcvT
/yEo/Ushyz6CVYxN8DGgcy2M9JOsnmjDx02h6qgWGWDuKgb9jZrvRedpAQCeemEd
fhEs6ihqVxRFl16HxC4EVijybhAL76SsM2nbtIqW1apBQJQpXWtQwwdvgTVpdEtE
r4ArVJYX5LrswnWEQMOelugUG6S3ZjMfcyOa/O0364iY73vyVgaYK+2XtT2usMux
VL469Kj5m13T6w==
=Mjs/
-----END PGP PUBLIC KEY BLOCK-----
CDNCA_REPO_KEY
      ;;
    epel-10) cat <<'CDNCA_REPO_KEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGV4X6kBEAC3eQxgiWuo08uc3mHo4ELux++uqTnYz/tJzEf9Ou3h36WnhumA
Nvs+Ts5h8PBx879Y9/aIX1Z20p1kf6tBCinZnEJu59n+TAAsph0+XQlV1l5YkleK
Z2ff/Fg65k8QcLXWaIGykA/FaKznRiSurGuD6tRGhJw7DawEwBJr8QZSkRUpnH1L
URW97Q/iKrRPiE5VEayE0y8eAL28jIIiFvR+4oJMzvCsRRB/2wYZ2MlJOW91hcYf
mbUoXKOBD5UzsJylu7kj25K/ge8rEJ7KicOOwcdYddxsU3DxGSSfwF8AMagENcm2
XROeXknjm84A8sNlUkFZBJwfuc7eRTiZGJrnQQVYLrkKj8Mxpq9Ts7hU51TqAWNI
uvGDlJdYNE3D2RMqjMEsZ8ej08Thrib6xslu4NzTBkt+6QNnXL4E3hEgYtoyio60
GswSz2ulogKg7X4JrNdJYE8/qNowyF3hoVgj5TG1/wQRq+5HlMMOLjgGu9wzLUix
fnVfEUnzaofbrUf4/GabCaeY8xRe4tFQrvzigQ4g+kgwKKnfAeqBmPov0yljkw9z
BYJWR5zvaw0ffg9Ing00KUSaXBXA5jSlgk1603Y+LefY1SlXsTyqohiRvGH6FI77
HNMo72DwoJfFcYjncZUzKgXWJECR4nhVsdj6pKoOjcQ4aSuyVxtsR86ASQARAQAB
tChGZWRvcmEgKGVwZWwxMCkgPGVwZWxAZmVkb3JhcHJvamVjdC5vcmc+iQJOBBMB
CAA4FiEEfY0Vy/xOYmiFkfsmM9mFF+N+0VgFAmV4X6kCGw8FCwkIBwIGFQoJCAsC
BBYCAwECHgECF4AACgkQM9mFF+N+0Vhv/A/+PlhPLSctGRCUEahE+cN4764Acc3p
l40ZYzXRhqR0/Tc1/cSDjlA3qVTc8SPohi5OJXwCyr9EiMqKoyoDN097euqbYpyp
yN/Pj0lBjsXwcpdDtZ21WGeQU0Khb04N68bMtJbDaxeBciTvDDQravZuPPh0m4Rg
Z6myEoa6Aa6EK0hI1Qwi1qIWeRiuEkVT671IaKVETBW5XiUpNBXDAB/L+6DzUF9u
scBzfsUDiPO6NrpYDtV3jwq22y6gWluIct/Ka8brwPbqK2sBfFzrHboRhfqlTGjs
7F9qUGwIQZn/A8iozXZYQ0+JG1bhQyvjA8eN1GOcRpT+O7H7JXN49o6IG2As4+iK
F04+qjqAu2sVfpD8mzM2VubFNllcKKiyCzRYHhSbObRCPzsudDL9GPiXeGGaCuWg
sDkiA1MESvf2tLETAGBs/TziO4GwmXUtlKbRiq1FYm90mVq9mBxPZ/Idn+yZusNB
0O5SXIbI8lYZw5n4XTK4b+byHRBYsOTHiTsGvjTF2Y7oSwW2CVUmL6RZ23mI4qoY
1p5kzRS+GjT1acnTei/FTsOlIKCsjfeHx7uxCkX6xpAD8P3UtLQqfsgH0CL4vSZt
TGO6L1InQlp4ZG3OYIomTKbD3/R0wod3U3dTqdulQMXL895u6OLTY3spY2m2MO2k
p9Dfd2pKuxK9Mys=
=mhQZ
-----END PGP PUBLIC KEY BLOCK-----
CDNCA_REPO_KEY
      ;;
    *) return 1 ;;
  esac
}
# <<< END repo-keys

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
  # Bundled keys (repo-keys block above): no download; the pinned primary fingerprints are still checked.
  repo_key_armor clickhouse >"$key_dir/ch.asc"
  native_dependencies_verify_key "$key_dir/ch.asc" 3A9EA1193A97B548BE1457D48919F6BD2B48D754 "$key_dir/gpg"
  native_dependencies_write_new "$DEPS_CH_KEY" 644 "$(< "$key_dir/ch.asc")"$'\n'
  native_dependencies_write_new "$DEPS_CH_SOURCE" 644 "deb [signed-by=$DEPS_CH_KEY arch=amd64] https://packages.clickhouse.com/deb stable main"$'\n'
  # The portable PostgreSQL build replaces the PGDG repository.
  [[ "$DEPS_PG_MODE" == package ]] || exit 0
  repo_key_armor pgdg-apt >"$key_dir/pg.asc"
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
  # Bundled keys (repo-keys block above): no download; the pinned primary fingerprints are still checked.
  repo_key_armor pgdg-rhel >"$key_dir/pg.asc"
  repo_key_armor clickhouse >"$key_dir/ch.asc"
  repo_key_armor "epel-$DEPS_EL_MAJOR" >"$key_dir/epel.asc" || native_dependencies_fail unsupported_os
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
