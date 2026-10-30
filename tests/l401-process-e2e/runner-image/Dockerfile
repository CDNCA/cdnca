# syntax=docker/dockerfile:1.7
ARG GO_IMAGE=docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5
ARG OPENRESTY_IMAGE

FROM ${OPENRESTY_IMAGE} AS openresty
FROM ${GO_IMAGE} AS runtime

ARG DEBIAN_SNAPSHOT=20260201T000000Z
ARG SOURCE_DATE_EPOCH=1769904000
ARG APT_PACKAGES="ca-certificates curl findutils jq openssl patchelf postgresql-client procps"
ARG OPENRESTY_VERSION
ARG BUILDX_BUILDER=
ARG BUILDX_BUILDER_PLATFORMS=
ARG PROVENANCE_INPUT_SHA256

RUN test -r /usr/share/keyrings/debian-archive-keyring.gpg && \
    test -r /etc/ssl/certs/ca-certificates.crt && \
    printf '%s\n' \
      "deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
      > /etc/apt/sources.list && \
    rm -f /etc/apt/sources.list.d/* && \
    apt-get -o Acquire::Retries=3 -o Acquire::https::Timeout=30 update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${APT_PACKAGES} && \
    rm -rf /var/lib/apt/lists/*

COPY --from=openresty /usr/local/openresty /usr/local/openresty
COPY --from=openresty /lib /opt/cdnca-musl/lib
COPY --from=openresty /usr/lib /opt/cdnca-musl/usr/lib

RUN set -eu; \
    loader="$(find /opt/cdnca-musl/lib -maxdepth 1 -type f -name 'ld-musl-*.so.1' -print -quit)"; \
    test -n "${loader}"; \
    patchelf --set-interpreter "${loader}" \
      --set-rpath '/usr/local/openresty/luajit/lib:/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib:/opt/cdnca-musl/usr/lib:/opt/cdnca-musl/lib' \
      /usr/local/openresty/nginx/sbin/nginx; \
    actual="$(/usr/local/openresty/bin/openresty -V 2>&1 | sed -n 's/^nginx version: openresty\///p')"; \
    test "${actual}" = "${OPENRESTY_VERSION}"; \
    test "$(go env GOVERSION)" = 'go1.27.3'; \
    useradd --create-home --uid 10001 l401

LABEL io.cdnca.l401.runner.contract="v1" \
      io.cdnca.l401.runner.go-image="${GO_IMAGE}" \
      io.cdnca.l401.runner.openresty-image="${OPENRESTY_IMAGE}" \
      io.cdnca.l401.runner.openresty-version="${OPENRESTY_VERSION}" \
      io.cdnca.l401.runner.debian-snapshot="${DEBIAN_SNAPSHOT}" \
      io.cdnca.l401.runner.buildx-builder="${BUILDX_BUILDER}" \
      io.cdnca.l401.runner.buildx-builder-platforms="${BUILDX_BUILDER_PLATFORMS}" \
      io.cdnca.l401.runner.provenance-input-sha256="${PROVENANCE_INPUT_SHA256}" \
      org.opencontainers.image.created="2026-02-01T00:00:00Z" \
      org.opencontainers.image.title="CDNCA L4-01 process E2E runner"

USER 10001:10001
WORKDIR /repo
ENTRYPOINT ["/bin/bash"]
