package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/l4live"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// L4 live connection requests are ephemeral request/reply exchanges relayed
// to the node's live session like market probes (libs/edgeconfig/l4live).

const maxPendingL4Live = 2

type L4LiveRequest interface {
	Command() *agentv1.L4LiveConnectionsCommand
	// Reply answers the request; nil means refused or not executed.
	Reply(*agentv1.L4LiveConnectionsResult) error
}

type L4LiveSubscription interface {
	Requests() <-chan L4LiveRequest
	Close() error
}

type L4LiveBus interface {
	SubscribeL4Live(ctx context.Context, nodeID string) (L4LiveSubscription, error)
}

func (g *Gateway) ConfigureL4Live(bus L4LiveBus) error {
	if g == nil || bus == nil || g.l4Live != nil {
		return fmt.Errorf("L4 live bus is invalid or already configured")
	}
	g.l4Live = bus
	return nil
}

// l4LiveCapabilityFromFeatures returns the advertised version (1 lists, 2
// also closes), 0 when absent.
func l4LiveCapabilityFromFeatures(features []*agentv1.Capability) (uint32, error) {
	version := uint32(0)
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS {
			continue
		}
		if version != 0 || capability.ApiVersion < 1 || capability.ApiVersion > 2 {
			return 0, fmt.Errorf("L4 live connections capability is duplicated or unsupported")
		}
		version = capability.ApiVersion
	}
	return version, nil
}

type sessionL4Live struct {
	subscription L4LiveSubscription
	pending      map[string]pendingL4Live
}

type pendingL4Live struct {
	request L4LiveRequest
	command *agentv1.L4LiveConnectionsCommand
}

func (g *Gateway) startSessionL4Live(ctx context.Context, nodeID string) (*sessionL4Live, error) {
	subscription, err := g.l4Live.SubscribeL4Live(ctx, nodeID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "could not subscribe to L4 live connection commands")
	}
	return &sessionL4Live{subscription: subscription, pending: map[string]pendingL4Live{}}, nil
}

func (session *sessionL4Live) requests() <-chan L4LiveRequest {
	if session == nil {
		return nil
	}
	return session.subscription.Requests()
}

func (session *sessionL4Live) stop() {
	if session != nil {
		_ = session.subscription.Close()
	}
}

func (g *Gateway) applyL4LiveAuthorization(ctx context.Context, nodeID string, session *sessionL4Live, isAllowed bool) (*sessionL4Live, error) {
	if g.l4Live == nil || (session != nil) == isAllowed {
		return session, nil
	}
	if !isAllowed {
		session.stop()
		return nil, nil
	}
	return g.startSessionL4Live(ctx, nodeID)
}

func validateL4LiveCommand(command *agentv1.L4LiveConnectionsCommand, nodeID string, version uint32, now time.Time) error {
	if command == nil || proto.Size(command) > l4live.MaxCarrierBytes || cacheControlMessageHasUnknown(command.ProtoReflect()) ||
		command.NodeId != nodeID || command.Event == nil || !canonicalUUID(command.Event.EventId) || !canonicalUUID(command.StreamId) ||
		command.Limit < 1 || command.Limit > l4live.MaxConnections || len(command.CloseSessionKeys) > l4live.MaxCloseKeys ||
		(len(command.CloseSessionKeys) != 0 && version < 2) ||
		command.ExpireTime == nil || command.ExpireTime.CheckValid() != nil || !now.Before(command.ExpireTime.AsTime()) ||
		command.ExpireTime.AsTime().Sub(now) > l4live.MaxTTLMillis*time.Millisecond {
		return fmt.Errorf("L4 live connections command is invalid")
	}
	return nil
}

func validateL4LiveResult(result *agentv1.L4LiveConnectionsResult, command *agentv1.L4LiveConnectionsCommand, nodeID string) error {
	if result == nil || command == nil || proto.Size(result) > l4live.MaxCarrierBytes ||
		cacheControlMessageHasUnknown(result.ProtoReflect()) || result.NodeId != nodeID ||
		result.CommandEventId != command.Event.GetEventId() || result.Event == nil || !canonicalUUID(result.Event.EventId) ||
		len(result.Connections) > int(command.Limit) || len(result.Closed) > len(command.CloseSessionKeys) || len(result.ErrorCode) > 64 {
		return fmt.Errorf("L4 live connections result is invalid")
	}
	return nil
}

func (session *sessionL4Live) admit(request L4LiveRequest, nodeID string, version uint32, now time.Time) (*agentv1.L4LiveConnectionsCommand, bool) {
	command := request.Command()
	if validateL4LiveCommand(command, nodeID, version, now) != nil || len(session.pending) >= maxPendingL4Live {
		_ = request.Reply(nil)
		return nil, false
	}
	if _, exists := session.pending[command.Event.EventId]; exists {
		_ = request.Reply(nil)
		return nil, false
	}
	command = proto.Clone(command).(*agentv1.L4LiveConnectionsCommand)
	session.pending[command.Event.EventId] = pendingL4Live{request: request, command: command}
	return command, true
}

func (session *sessionL4Live) settle(result *agentv1.L4LiveConnectionsResult, nodeID string) error {
	pending, exists := session.pending[result.GetCommandEventId()]
	if !exists {
		return nil
	}
	if err := validateL4LiveResult(result, pending.command, nodeID); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	delete(session.pending, result.CommandEventId)
	_ = pending.request.Reply(proto.Clone(result).(*agentv1.L4LiveConnectionsResult))
	return nil
}

func (session *sessionL4Live) expire(now time.Time) {
	if session == nil {
		return
	}
	for id, pending := range session.pending {
		if !now.Before(pending.command.ExpireTime.AsTime()) {
			delete(session.pending, id)
		}
	}
}

// NATSL4LiveBus relays requests with core NATS: one queue subscription per
// live session on the node's request subject.
type NATSL4LiveBus struct{ connection *nats.Conn }

func NewNATSL4LiveBus(connection *nats.Conn) (*NATSL4LiveBus, error) {
	if connection == nil || connection.IsClosed() {
		return nil, errors.New("L4 live bus requires an active NATS connection")
	}
	return &NATSL4LiveBus{connection: connection}, nil
}

func (bus *NATSL4LiveBus) SubscribeL4Live(ctx context.Context, nodeID string) (L4LiveSubscription, error) {
	if _, err := uuid.Parse(nodeID); err != nil || ctx.Err() != nil {
		return nil, errors.New("L4 live subscription is invalid")
	}
	subscription := &natsL4LiveSubscription{requests: make(chan L4LiveRequest, maxPendingL4Live), done: make(chan struct{})}
	raw, err := bus.connection.QueueSubscribe(l4live.Subject(nodeID), l4live.QueueGroup, func(message *nats.Msg) {
		request := &natsL4LiveRequest{message: message}
		if message.Reply == "" || len(message.Data) > l4live.MaxCarrierBytes || proto.Unmarshal(message.Data, &request.command) != nil {
			_ = request.Reply(nil)
			return
		}
		select {
		case subscription.requests <- request:
		case <-subscription.done:
		default:
			_ = request.Reply(nil)
		}
	})
	if err != nil {
		return nil, err
	}
	subscription.raw = raw
	return subscription, nil
}

type natsL4LiveSubscription struct {
	raw      *nats.Subscription
	requests chan L4LiveRequest
	done     chan struct{}
	once     sync.Once
}

func (subscription *natsL4LiveSubscription) Requests() <-chan L4LiveRequest {
	return subscription.requests
}

func (subscription *natsL4LiveSubscription) Close() error {
	var err error
	subscription.once.Do(func() {
		close(subscription.done)
		err = subscription.raw.Unsubscribe()
	})
	return err
}

type natsL4LiveRequest struct {
	message *nats.Msg
	command agentv1.L4LiveConnectionsCommand
}

func (request *natsL4LiveRequest) Command() *agentv1.L4LiveConnectionsCommand {
	return &request.command
}

func (request *natsL4LiveRequest) Reply(result *agentv1.L4LiveConnectionsResult) error {
	if result == nil {
		return request.message.Respond(nil)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil || len(payload) > l4live.MaxCarrierBytes {
		return request.message.Respond(nil)
	}
	return request.message.Respond(payload)
}
