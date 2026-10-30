# syntax=docker/dockerfile:1.7

FROM docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS edge-agent-build

ARG TARGETARCH
ARG EDGE_AGENT_VERSION=1.0.0
WORKDIR /src/agents/edge-agent

COPY agents/edge-agent/go.mod agents/edge-agent/go.sum ./
COPY libs/edgeconfig /src/libs/edgeconfig
COPY proto/gen/go /src/proto/gen/go
RUN --mount=type=cache,target=/go/pkg/mod GOTOOLCHAIN=local go mod download

COPY agents/edge-agent .
COPY apps/web/edge-agent-artifacts.json /src/apps/web/edge-agent-artifacts.json
RUN set -eu; \
    GOARCH="${TARGETARCH:-amd64}" CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local go build \
      -buildvcs=false -trimpath -ldflags="-s -w -X main.agentVersion=${EDGE_AGENT_VERSION}" \
      -o /tmp/edge-agent ./cmd/edge-agent; \
    mkdir -p /out/edge-agent; \
    install -m 0755 /tmp/edge-agent /out/edge-agent/edge-agent; \
    install -m 0444 /src/apps/web/edge-agent-artifacts.json /out/edge-agent/artifacts.json; \
    tar -czf /out/cdnca-edge-agent.tar.gz -C /out/edge-agent edge-agent artifacts.json; \
    sha256sum /out/cdnca-edge-agent.tar.gz | sed 's# /out/##' > /out/SHA256SUMS

FROM public.ecr.aws/docker/library/node:22.19.0-alpine3.22@sha256:d2166de198f26e17e5a442f537754dd616ab069c47cc57b889310a717e0abbf9 AS build

WORKDIR /src

RUN corepack enable && corepack prepare pnpm@10.15.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/package.json
COPY packages/cdnca-ui/package.json packages/cdnca-ui/package.json

RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --filter @cdnca/web...

COPY apps/web ./apps/web
COPY packages/cdnca-ui ./packages/cdnca-ui
COPY libs/marketproto/pluginkind/kinds.json ./libs/marketproto/pluginkind/kinds.json

ARG VITE_TURNSTILE_SITE_KEY
ARG VITE_PACKAGE_COMMERCE_ENABLED=true
ENV VITE_PACKAGE_COMMERCE_ENABLED=$VITE_PACKAGE_COMMERCE_ENABLED
RUN test -n "$VITE_TURNSTILE_SITE_KEY" \
    && test "$VITE_PACKAGE_COMMERCE_ENABLED" = true \
    && pnpm --filter @cdnca/web build

FROM public.ecr.aws/docker/library/nginx:1.29.1-alpine3.22@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8 AS runtime

COPY apps/web/nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=65532:65532 /src/apps/web/dist /usr/share/nginx/html
COPY --chown=65532:65532 scripts/install-node.sh /usr/share/cdnca/downloads/install-node.sh
COPY --from=edge-agent-build --chown=65532:65532 /out/cdnca-edge-agent.tar.gz /usr/share/cdnca/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz
COPY --from=edge-agent-build --chown=65532:65532 /out/SHA256SUMS /usr/share/cdnca/downloads/edge-agent/latest/SHA256SUMS
COPY --chown=65532:65532 apps/web/edge-agent-artifacts.json /usr/share/cdnca/downloads/edge-agent/artifacts.json

RUN set -eu; \
    test -x /usr/share/cdnca/downloads/install-node.sh; \
    test -s /usr/share/cdnca/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz; \
    test -s /usr/share/cdnca/downloads/edge-agent/latest/SHA256SUMS; \
    test -s /usr/share/cdnca/downloads/edge-agent/artifacts.json; \
    tar -tzf /usr/share/cdnca/downloads/edge-agent/latest/cdnca-edge-agent.tar.gz >/dev/null

USER 65532:65532
EXPOSE 8080

ENTRYPOINT ["nginx", "-g", "daemon off;"]
