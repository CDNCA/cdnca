module github.com/cdnca/cdnca/tests/gateway-cdn-poc

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/proto/gen/go v0.0.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.10
)

require (
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)

replace github.com/cdnca/cdnca/proto/gen/go => ../../proto/gen/go
