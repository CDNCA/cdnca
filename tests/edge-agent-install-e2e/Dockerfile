ARG DISTRO_IMAGE
FROM ${DISTRO_IMAGE}

ARG DISTRO_IMAGE
ARG APT_PACKAGES="ca-certificates curl jq passwd procps systemd systemd-sysv util-linux"
ARG APT_PACKAGES_SHA256=sha256:c282a8ce39dbefb7457c3566354ab31df204a037b6577582f6283792fc491419
ARG APT_SNAPSHOT=20260801T000000Z
ARG EXPECTED_SYSTEMD

ENV container=docker

RUN set -eu; \
    test "sha256:$(printf '%s' "${APT_PACKAGES}" | sha256sum | awk '{print $1}')" = "${APT_PACKAGES_SHA256}"; \
    . /etc/os-release; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    case "${ID}:${VERSION_ID}" in \
      debian:12) \
        printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" >/etc/apt/sources.list \
        ;; \
      ubuntu:24.04) \
        printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble main universe\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble-updates main universe\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble-security main universe\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" >/etc/apt/sources.list \
        ;; \
      *) printf 'unsupported base distribution: %s:%s\n' "${ID}" "${VERSION_ID}" >&2; exit 1 ;; \
    esac; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 -o Acquire::https::Timeout=20 update -qq; \
    apt-get -o Acquire::ForceIPv4=true -o Acquire::Retries=5 -o Acquire::https::Timeout=20 \
      install -y --no-install-recommends ${APT_PACKAGES}; \
    actual_systemd="$(systemd --version | awk 'NR == 1 {print $2}')"; \
    test "${actual_systemd}" = "${EXPECTED_SYSTEMD}"; \
    systemctl mask console-getty.service getty@.service systemd-logind.service >/dev/null 2>&1 || true; \
    rm -rf /var/lib/apt/lists/*; \
    rm -f /etc/machine-id; touch /etc/machine-id; \
    install -d -m 0755 /usr/share/cdnca-ops11; \
    printf 'schema=cdnca.edge.ops11-systemd-image/v1\nbase=%s\ndistro=%s\nversion=%s\napt_snapshot=%s\napt_packages_sha256=%s\n' \
      "${DISTRO_IMAGE}" "${ID}" "${VERSION_ID}" "${APT_SNAPSHOT}" "${APT_PACKAGES_SHA256#sha256:}" \
      >/usr/share/cdnca-ops11/image-contract

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
