#!/usr/bin/env bash
# AUDIT-1029 ①-11 容器演练：Ubuntu 24.04 真 systemd（屏蔽 systemd-binfmt 等）里装 unattended-upgrades，
# 跑安装器内嵌的 quiesce_package_automation：默认停用三个单元、退出不恢复；
# --keep-unattended-upgrades 保留系统默认（退出后两个定时器恢复运行）。不联网安装 cdnca，只测这一段。
# 用法：bash tests/install-smoke/package-automation.sh
set -Eeuo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=cdnca-install-smoke-apt:$$
NAME=cdnca-apt-automation-$$
CTX=$(mktemp -d)
cleanup() { docker rm -f -v "$NAME" >/dev/null 2>&1 || true; docker rmi "$IMAGE" >/dev/null 2>&1 || true; rm -rf "$CTX"; }
trap cleanup EXIT
cat >"$CTX/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus unattended-upgrades procps >/dev/null && rm -rf /var/lib/apt/lists/*
RUN for u in systemd-binfmt.service proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount systemd-firstboot.service \
      systemd-udevd.service systemd-udev-trigger.service systemd-networkd-wait-online.service getty.target console-getty.service; do \
      ln -sf /dev/null /etc/systemd/system/$u; done
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKER
docker build -q -t "$IMAGE" "$CTX" >/dev/null
docker run -d --name "$NAME" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock --tmpfs /tmp:exec "$IMAGE" >/dev/null
for _ in $(seq 1 60); do docker exec "$NAME" systemctl is-system-running 2>/dev/null | grep -Eq 'running|degraded' && break; sleep 1; done
docker exec "$NAME" mkdir -p /work
for f in scripts/lib/install-progress.sh scripts/lib/package-automation.sh scripts/install-control.sh scripts/install-node.sh; do
  docker cp "$ROOT/$f" "$NAME:/work/$(basename "$f")"
done
docker exec -i "$NAME" bash -s <<'IN'
set -Eeuo pipefail
state() { for u in apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service; do
  printf '%s=%s/%s ' "$u" "$(systemctl is-enabled "$u" 2>/dev/null || true)" "$(systemctl is-active "$u" 2>/dev/null || true)"; done; echo; }
reset() { systemctl enable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service >/dev/null 2>&1; }
# 两个安装器内嵌的库必须与源文件逐字一致，演练用源文件。
for f in install-control.sh install-node.sh; do grep -Fq "$(head -3 /work/package-automation.sh)" "/work/$f"; done
drive() { # <参数...>：parse 出开关后运行 quiesce，退出时按 cleanup 规则恢复暂停的定时器
  bash -c 'set -Eeuo pipefail; . /work/install-progress.sh; . /work/package-automation.sh
    log() { echo "LOG $*"; }; fail() { echo "FAIL $*"; exit 1; }
    trap '"'"'[ "${#PAUSED_APT_TIMERS[@]}" -eq 0 ] || systemctl start "${PAUSED_APT_TIMERS[@]}"'"'"' EXIT
    [ "${1:-}" != --keep-unattended-upgrades ] || KEEP_UNATTENDED_UPGRADES=true
    quiesce_package_automation; echo "DURING $(systemctl is-active apt-daily.timer)"' drive "$@"
}
reset; echo "BEFORE $(state)"
drive 2>&1 | sed 's/^/  /'
echo "DEFAULT $(state)"
for u in apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service; do
  [ "$(systemctl is-enabled "$u")" = disabled ] && ! systemctl is-active --quiet "$u" || { echo "FAIL default left $u on"; exit 1; }
done
dpkg -s unattended-upgrades >/dev/null && command -v unattended-upgrade >/dev/null || { echo 'FAIL package removed'; exit 1; }
reset
drive --keep-unattended-upgrades 2>&1 | sed 's/^/  /'
echo "KEEP $(state)"
for u in apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service; do
  [ "$(systemctl is-enabled "$u")" = enabled ] && systemctl is-active --quiet "$u" || { echo "FAIL keep changed $u"; exit 1; }
done
echo PASS
IN
