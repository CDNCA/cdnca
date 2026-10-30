FROM docker.io/library/golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build

WORKDIR /src/services/agent-gateway

COPY services/agent-gateway/go.mod services/agent-gateway/go.sum ./
COPY proto/gen/go /src/proto/gen/go
COPY libs/edgeconfig /src/libs/edgeconfig
RUN --mount=type=cache,target=/go/pkg/mod GOTOOLCHAIN=local go mod download

COPY services/agent-gateway .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local go build \
    -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/agent-gateway ./cmd/agent-gateway

# Keep the runtime image distroless while retaining a real Compose healthcheck.
RUN cat <<'EOF' >/tmp/healthcheck.go
package main

import (
	"net/http"
	"os"
	"time"
)

func main() {
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://127.0.0.1:8082/health/ready")
	if err != nil {
		os.Exit(1)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		os.Exit(1)
	}
}
EOF
RUN CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local go build \
    -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/healthcheck /tmp/healthcheck.go

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

COPY --from=build --chown=65532:65532 /out/agent-gateway /agent-gateway
COPY --from=build --chown=65532:65532 /out/healthcheck /healthcheck

USER 65532:65532
WORKDIR /
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=30 CMD ["/healthcheck"]
ENTRYPOINT ["/agent-gateway"]
