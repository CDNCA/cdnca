package gatewayclient

import (
	"context"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// L4LiveExecutor runs L4LiveConnectionsCommand (internal/l4live.Executor).
type L4LiveExecutor interface {
	Validate(*agentv1.L4LiveConnectionsCommand) error
	Execute(context.Context, *agentv1.L4LiveConnectionsCommand) *agentv1.L4LiveConnectionsResult
	// APIVersion: 1 lists, 2 also closes.
	APIVersion() uint32
}

// WithL4LiveExecutor advertises CAPABILITY_NAME_L4_LIVE_CONNECTIONS (once a
// Gateway lists it in known_capabilities) and runs its commands.
func WithL4LiveExecutor(executor L4LiveExecutor) ClientOption {
	return func(client *Client) error {
		if executor == nil || client == nil || executor.APIVersion() < 1 || executor.APIVersion() > 2 {
			return ErrInvalidConfiguration
		}
		client.l4Live = executor
		return nil
	}
}

// negotiateL4LiveConnections: the Gateway may leave it off, but must not
// enable it for an Agent that did not advertise it, or another version.
func negotiateL4LiveConnections(gatewayHello *agentv1.GatewayHello, executor L4LiveExecutor, advertised bool) (bool, error) {
	enabled := false
	for _, capability := range gatewayHello.GetEnabledCapabilities() {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS {
			continue
		}
		if enabled || executor == nil || !advertised || capability.ApiVersion != executor.APIVersion() {
			return false, fmt.Errorf("%w: L4 live connections capability is duplicated or was not advertised", ErrInvalidMessage)
		}
		enabled = true
	}
	return enabled, nil
}

// startL4Live runs command in the background (one at a time); a command
// arriving meanwhile is answered busy. An invalid command is dropped.
func (client *Client) startL4Live(ctx context.Context, command *agentv1.L4LiveConnectionsCommand, busy bool,
	done chan<- *agentv1.L4LiveConnectionsResult,
) (started bool, immediate *agentv1.L4LiveConnectionsResult) {
	if command.GetNodeId() != client.config.NodeID || client.l4Live.Validate(command) != nil {
		return false, nil
	}
	if busy {
		return false, client.l4LiveResult(command, &agentv1.L4LiveConnectionsResult{ErrorCode: "busy"}, client.now())
	}
	go func() {
		executeCtx, cancel := context.WithDeadline(ctx, command.ExpireTime.AsTime())
		defer cancel()
		result := client.l4Live.Execute(executeCtx, command)
		select {
		case done <- client.l4LiveResult(command, result, client.now()):
		case <-ctx.Done():
		}
	}()
	return true, nil
}

func (client *Client) l4LiveResult(command *agentv1.L4LiveConnectionsCommand, result *agentv1.L4LiveConnectionsResult,
	now time.Time,
) *agentv1.L4LiveConnectionsResult {
	namespace := uuid.MustParse(client.config.NodeID)
	result.Event = &commonv1.EventMetadata{
		EventId:      uuid.NewSHA1(namespace, []byte("l4-live-result/"+command.Event.EventId)).String(),
		RequestId:    uuid.NewSHA1(namespace, []byte("l4-live-result-request/"+command.Event.EventId)).String(),
		OccurredTime: timestamppb.New(now.UTC()),
	}
	result.NodeId, result.CommandEventId = client.config.NodeID, command.Event.EventId
	return result
}

func sendL4LiveResult(stream interface {
	Send(*agentv1.ConnectRequest) error
}, sequence uint64, result *agentv1.L4LiveConnectionsResult, now time.Time) error {
	return stream.Send(&agentv1.ConnectRequest{Stream: streamMetadata(sequence, now),
		Payload: &agentv1.ConnectRequest_L4LiveConnectionsResult{L4LiveConnectionsResult: result}})
}
