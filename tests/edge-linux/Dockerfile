# The Dockerfile frontend is the builtin parser in the digest-pinned BuildKit image.

ARG OPENRESTY_IMAGE
ARG DISTRO_IMAGE
FROM ${OPENRESTY_IMAGE} AS openresty

FROM ${DISTRO_IMAGE} AS toolchain

ARG APT_PACKAGES="ca-certificates curl jq passwd procps systemd systemd-sysv util-linux"
ARG APT_PACKAGES_SHA256=sha256:c282a8ce39dbefb7457c3566354ab31df204a037b6577582f6283792fc491419
ARG APT_SNAPSHOT=20260801T000000Z
ARG OPENRESTY_VERSION
ARG OPENRESTY_SOURCE_DIGEST
ARG TOOLCHAIN_PACKAGES=patchelf
ARG TOOLCHAIN_PACKAGES_SHA256=sha256:c01828471a3298e527af608c61f77d878db5441214c7cbc984bd95c1b7433ea3

RUN set -eu; \
    test "sha256:$(printf '%s' "${APT_PACKAGES}" | sha256sum | awk '{print $1}')" = "${APT_PACKAGES_SHA256}"; \
    test "sha256:$(printf '%s' "${TOOLCHAIN_PACKAGES}" | sha256sum | awk '{print $1}')" = "${TOOLCHAIN_PACKAGES_SHA256}"; \
    . /etc/os-release; \
    rm -f /etc/apt/sources.list.d/*; \
    case "${ID}:${VERSION_ID}" in \
      debian:12) \
        printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" >/etc/apt/sources.list \
        ;; \
      ubuntu:24.04) \
        printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble main universe\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble-updates main universe\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble-security main universe\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" >/etc/apt/sources.list \
        ;; \
      *) printf 'unsupported distro: %s:%s\n' "${ID}" "${VERSION_ID}" >&2; exit 1 ;; \
    esac; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends ${APT_PACKAGES} ${TOOLCHAIN_PACKAGES}; \
    rm -rf /var/lib/apt/lists/*

COPY --from=openresty /usr/local/openresty /usr/local/openresty
COPY --from=openresty /lib /opt/cdnca-musl/lib
COPY --from=openresty /usr/lib /opt/cdnca-musl/usr/lib

RUN set -eu; \
    loader="$(find /opt/cdnca-musl/lib -maxdepth 1 -type f -name 'ld-musl-*.so.1' -print -quit)"; \
    test -n "${loader}"; \
    patchelf \
        --set-interpreter "${loader}" \
        --set-rpath '/usr/local/openresty/luajit/lib:/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib:/opt/cdnca-musl/usr/lib:/opt/cdnca-musl/lib' \
        /usr/local/openresty/nginx/sbin/nginx; \
    actual_version="$(/usr/local/openresty/bin/openresty -V 2>&1 | sed -n 's/^nginx version: openresty\///p')"; \
    test "${actual_version}" = "${OPENRESTY_VERSION}"

FROM ${DISTRO_IMAGE} AS runtime

ARG APT_PACKAGES="ca-certificates curl jq passwd procps systemd systemd-sysv util-linux"
ARG APT_PACKAGES_SHA256=sha256:c282a8ce39dbefb7457c3566354ab31df204a037b6577582f6283792fc491419
ARG APT_SNAPSHOT=20260801T000000Z
ARG BUILDKIT_IMAGE
ARG EXPECTED_BUILDER_ID
ARG EXPECTED_RUNTIME_INVENTORY_SHA256_AMD64=UNBOUND
ARG EXPECTED_RUNTIME_INVENTORY_SHA256_ARM64=UNBOUND
ARG OPENRESTY_SOURCE_DIGEST
ARG OPENRESTY_VERSION
ARG REQUIRED_RUNTIME_PACKAGES="ca-certificates curl jq passwd procps systemd systemd-sysv util-linux"
ARG REQUIRED_RUNTIME_PACKAGES_SHA256=sha256:c282a8ce39dbefb7457c3566354ab31df204a037b6577582f6283792fc491419
ARG SOURCE_DATE_EPOCH
ARG SOURCE_REVISION
ARG TARGETARCH

ENV container=docker

RUN set -eu; \
    test "sha256:$(printf '%s' "${APT_PACKAGES}" | sha256sum | awk '{print $1}')" = "${APT_PACKAGES_SHA256}"; \
    test "sha256:$(printf '%s' "${REQUIRED_RUNTIME_PACKAGES}" | sha256sum | awk '{print $1}')" = "${REQUIRED_RUNTIME_PACKAGES_SHA256}"; \
    . /etc/os-release; \
    rm -f /etc/apt/sources.list.d/*; \
    case "${ID}:${VERSION_ID}" in \
      debian:12) \
        printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian/%s bookworm main\ndeb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian-security/%s bookworm-security main\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" >/etc/apt/sources.list \
        ;; \
      ubuntu:24.04) \
        printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble main universe\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble-updates main universe\ndeb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/%s noble-security main universe\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" >/etc/apt/sources.list \
        ;; \
      *) printf 'unsupported distro: %s:%s\n' "${ID}" "${VERSION_ID}" >&2; exit 1 ;; \
    esac; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update; \
    apt-get install -y --no-install-recommends ${APT_PACKAGES}; \
    rm -rf /var/lib/apt/lists/*; \
    for package in ${REQUIRED_RUNTIME_PACKAGES}; do dpkg-query -W -f='${db:Status-Abbrev}' "${package}" | grep -qx 'ii '; done; \
    systemctl mask console-getty.service getty@.service systemd-logind.service; \
    rm -f /etc/machine-id; \
    touch /etc/machine-id

COPY --from=toolchain /usr/local/openresty /usr/local/openresty
COPY --from=toolchain /opt/cdnca-musl /opt/cdnca-musl
COPY agents/edge-agent/packaging /opt/cdnca-upgrade-e2e/packaging

RUN set -eu; \
    test -x /opt/cdnca-upgrade-e2e/packaging/scripts/install.sh; \
    bash -n /opt/cdnca-upgrade-e2e/packaging/scripts/install.sh; \
    install -m 0644 /opt/cdnca-upgrade-e2e/packaging/systemd/cdnca-edge-agent-helper.service /usr/lib/systemd/system/cdnca-edge-agent-helper.service; \
    install -m 0644 /opt/cdnca-upgrade-e2e/packaging/systemd/cdnca-edge-agent-helper.socket /usr/lib/systemd/system/cdnca-edge-agent-helper.socket; \
    systemctl enable cdnca-edge-agent-helper.socket; \
    jq --version >/dev/null; \
    ! command -v patchelf >/dev/null 2>&1; \
    actual_version="$(/usr/local/openresty/bin/openresty -V 2>&1 | sed -n 's/^nginx version: openresty\///p')"; \
    test "${actual_version}" = "${OPENRESTY_VERSION}"; \
    mkdir -p /usr/share/cdnca; \
    dpkg-query -W -f='${Package}\t${Version}\n' | LC_ALL=C sort -u >/usr/share/cdnca/runtime-packages.tsv; \
    find / -xdev \( -type f -o -type l \) \
      ! -path '/usr/share/cdnca/runtime-packages.tsv' \
      ! -path '/usr/share/cdnca/runtime-files.tsv' \
      ! -path '/usr/share/cdnca/runtime-inventory.sha256' \
      ! -path '/tmp/*' -print | LC_ALL=C sort | \
      while IFS= read -r path; do \
        if test -L "${path}"; then \
          target="$(readlink "${path}")"; \
          digest="$(printf '%s' "${target}" | sha256sum | awk '{print $1}')"; \
          printf 'L\t%s\t%s\t%s\n' "${digest}" "${path}" "${target}"; \
        else \
          digest="$(sha256sum "${path}" | awk '{print $1}')"; \
          printf 'F\t%s\t%s\t-\n' "${digest}" "${path}"; \
        fi; \
      done >/usr/share/cdnca/runtime-files.tsv; \
    { printf 'cdnca.runtime-inventory/v1\n'; cat /usr/share/cdnca/runtime-packages.tsv /usr/share/cdnca/runtime-files.tsv; } | \
      sha256sum | awk '{print "sha256:" $1}' >/usr/share/cdnca/runtime-inventory.sha256; \
    actual_inventory="$(cat /usr/share/cdnca/runtime-inventory.sha256)"; \
    case "${TARGETARCH}" in \
      amd64) expected_inventory="${EXPECTED_RUNTIME_INVENTORY_SHA256_AMD64}" ;; \
      arm64) expected_inventory="${EXPECTED_RUNTIME_INVENTORY_SHA256_ARM64}" ;; \
      *) printf 'unsupported TARGETARCH: %s\n' "${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    test "${expected_inventory}" = UNBOUND || test "${actual_inventory}" = "${expected_inventory}"

LABEL org.opencontainers.image.title="CDNCA edge Linux systemd smoke" \
      org.opencontainers.image.version="${OPENRESTY_VERSION}" \
      org.opencontainers.image.base.digest="${OPENRESTY_SOURCE_DIGEST}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created.epoch="${SOURCE_DATE_EPOCH}" \
      io.cdnca.build.builder.id="${EXPECTED_BUILDER_ID}" \
      io.cdnca.build.buildkit.digest="${BUILDKIT_IMAGE}" \
      io.cdnca.runtime.inventory.digest.amd64="${EXPECTED_RUNTIME_INVENTORY_SHA256_AMD64}" \
      io.cdnca.runtime.inventory.digest.arm64="${EXPECTED_RUNTIME_INVENTORY_SHA256_ARM64}"

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]

FROM scratch AS inventory-export
COPY --from=runtime /usr/share/cdnca/runtime-packages.tsv /runtime-packages.tsv
COPY --from=runtime /usr/share/cdnca/runtime-files.tsv /runtime-files.tsv
COPY --from=runtime /usr/share/cdnca/runtime-inventory.sha256 /runtime-inventory.sha256

FROM runtime AS final
