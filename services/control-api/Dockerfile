FROM docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build

WORKDIR /src/services/control-api

ARG CONTROL_VERSION

COPY services/control-api/go.mod services/control-api/go.sum ./
COPY libs/edgeconfig /src/libs/edgeconfig
COPY libs/entitlement /src/libs/entitlement
COPY libs/rulepack /src/libs/rulepack
COPY libs/themepack /src/libs/themepack
COPY libs/sitetheme /src/libs/sitetheme
COPY libs/marketproto /src/libs/marketproto
COPY libs/mtlstunnel /src/libs/mtlstunnel
COPY libs/mail /src/libs/mail
COPY libs/passwordpolicy /src/libs/passwordpolicy
COPY proto/gen/go /src/proto/gen/go
RUN --mount=type=cache,target=/go/pkg/mod GOTOOLCHAIN=local go mod download

COPY services/control-api/cmd ./cmd
COPY services/control-api/internal ./internal
COPY services/control-api/migrations ./migrations
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -n "$CONTROL_VERSION" && \
    CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local go build \
    -buildvcs=false -trimpath -ldflags="-s -w -X main.controlVersion=$CONTROL_VERSION" \
    -o /out/control-api ./cmd/control-api && \
    CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local go build \
    -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/analytics-history-bootstrap ./cmd/analytics-history-bootstrap && \
    CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local go build \
    -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/control-upgrade-runner ./cmd/control-upgrade-runner

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

COPY --from=build --chown=65532:65532 /out/control-api /control-api
COPY --from=build --chown=65532:65532 /out/analytics-history-bootstrap /analytics-history-bootstrap
COPY --from=build --chown=65532:65532 /out/control-upgrade-runner /control-upgrade-runner

USER 65532:65532
WORKDIR /
ENTRYPOINT ["/control-api"]
