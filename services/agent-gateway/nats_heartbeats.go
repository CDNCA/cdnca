package gateway

import (
	"context"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func (b *NATSCommandBus) PersistHeartbeat(ctx context.Context, nodeID string, heartbeat *agentv1.Heartbeat) error {
	if ctx == nil {
		return fmt.Errorf("heartbeat publication context is required")
	}
	parsedNodeID, err := uuid.Parse(nodeID)
	if err != nil || parsedNodeID.String() != nodeID {
		return fmt.Errorf("node ID must be a canonical UUID")
	}
	if heartbeat == nil || heartbeat.Event == nil {
		return fmt.Errorf("heartbeat event is required")
	}
	parsedEventID, err := uuid.Parse(heartbeat.Event.EventId)
	if err != nil || parsedEventID.String() != heartbeat.Event.EventId {
		return fmt.Errorf("heartbeat event ID must be a canonical UUID")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		return fmt.Errorf("marshal heartbeat: %w", err)
	}
	if len(payload) == 0 || len(payload) > b.config.MaxHeartbeatBytes {
		return fmt.Errorf("heartbeat exceeds its size limit")
	}
	message := nats.NewMsg(b.config.HeartbeatSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, heartbeat.Event.EventId)
	operationCtx, cancel := context.WithTimeout(ctx, b.config.OperationTimeout)
	defer cancel()
	if _, err := b.js.PublishMsg(message, nats.Context(operationCtx), nats.ExpectStream(b.config.HeartbeatStream)); err != nil {
		return fmt.Errorf("publish heartbeat: %w", err)
	}
	return nil
}
