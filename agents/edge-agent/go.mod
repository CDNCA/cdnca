module github.com/cdnca/cdnca/agents/edge-agent

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/libs/edgeconfig v0.0.0
	github.com/cdnca/cdnca/libs/entitlement v0.0.0
	github.com/cdnca/cdnca/libs/rulepack v0.0.0
	github.com/cdnca/cdnca/proto/gen/go v0.0.0
	github.com/cilium/ebpf v0.19.0
	github.com/cloudflare/circl v1.6.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/klauspost/compress v1.18.0
	golang.org/x/crypto v0.39.0
	golang.org/x/sys v0.33.0
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.10
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)

replace github.com/cdnca/cdnca/proto/gen/go => ../../proto/gen/go

replace github.com/cdnca/cdnca/libs/edgeconfig => ../../libs/edgeconfig

replace github.com/cdnca/cdnca/libs/entitlement => ../../libs/entitlement

replace github.com/cdnca/cdnca/libs/rulepack => ../../libs/rulepack



