module github.com/cdnca/cdnca/services/agent-gateway

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/libs/edgeconfig v0.0.0
	github.com/cdnca/cdnca/proto/gen/go v0.0.0
	github.com/google/uuid v1.6.0
	github.com/nats-io/nats.go v1.47.0
	github.com/redis/go-redis/v9 v9.12.1
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.10
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/nats-io/nkeys v0.4.11 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.39.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)

replace github.com/cdnca/cdnca/proto/gen/go => ../../proto/gen/go

replace github.com/cdnca/cdnca/libs/edgeconfig => ../../libs/edgeconfig
