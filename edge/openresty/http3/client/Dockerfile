FROM golang@sha256:895e5feab11a4b3774d24ee3c9579028456b82ad37f42a9eb6f82adaf776a201 AS build

ARG GOPROXY=https://goproxy.cn,direct
ENV CGO_ENABLED=0 GOPROXY=${GOPROXY}
WORKDIR /src
COPY client.mod ./go.mod
COPY client.sum ./go.sum
RUN go mod download
COPY main.go ./
RUN go test ./... && go vet ./...
RUN go build -trimpath -ldflags '-s -w -buildid=' -o /out/h3probe .

FROM scratch
LABEL org.opencontainers.image.title="CDNCA HTTP/3 protocol probe" \
      org.opencontainers.image.version="quic-go-v0.54.0" \
      org.opencontainers.image.base.digest="sha256:895e5feab11a4b3774d24ee3c9579028456b82ad37f42a9eb6f82adaf776a201"
USER 65532:65532
COPY --from=build /out/h3probe /h3probe
ENTRYPOINT ["/h3probe"]
