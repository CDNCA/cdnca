package gateway

import (
	"context"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// HeartbeatSink is the Gateway's durable heartbeat boundary. A nil sink keeps
// the standalone protocol mode, whose acknowledgements are not production
// evidence of node liveness.
type HeartbeatSink interface {
	PersistHeartbeat(context.Context, string, *agentv1.Heartbeat) error
}
