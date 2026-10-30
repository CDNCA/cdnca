package gateway

import (
	"context"
	"errors"
	"sync"

	"github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// NATSMarketProbeBus relays market probe requests with core NATS (no stream):
// one queue subscription per live session on the node's request subject.
type NATSMarketProbeBus struct {
	connection *nats.Conn
}

func NewNATSMarketProbeBus(connection *nats.Conn) (*NATSMarketProbeBus, error) {
	if connection == nil || connection.IsClosed() {
		return nil, errors.New("market probe bus requires an active NATS connection")
	}
	return &NATSMarketProbeBus{connection: connection}, nil
}

func (bus *NATSMarketProbeBus) SubscribeMarketProbes(ctx context.Context, nodeID string) (MarketProbeSubscription, error) {
	if _, err := uuid.Parse(nodeID); err != nil || ctx.Err() != nil {
		return nil, errors.New("market probe subscription is invalid")
	}
	subscription := &natsMarketProbeSubscription{requests: make(chan MarketProbeRequest, maxPendingMarketProbes),
		done: make(chan struct{})}
	raw, err := bus.connection.QueueSubscribe(marketprobe.Subject(nodeID), marketprobe.QueueGroup, func(message *nats.Msg) {
		request := &natsMarketProbeRequest{message: message}
		if message.Reply == "" || len(message.Data) > marketprobe.MaxCarrierBytes ||
			proto.Unmarshal(message.Data, &request.command) != nil {
			_ = request.Reply(nil)
			return
		}
		select {
		case subscription.requests <- request:
		case <-subscription.done:
		default:
			// The session is not keeping up: refuse instead of queueing.
			_ = request.Reply(nil)
		}
	})
	if err != nil {
		return nil, err
	}
	subscription.raw = raw
	return subscription, nil
}

type natsMarketProbeSubscription struct {
	raw      *nats.Subscription
	requests chan MarketProbeRequest
	done     chan struct{}
	once     sync.Once
}

func (subscription *natsMarketProbeSubscription) Requests() <-chan MarketProbeRequest {
	return subscription.requests
}

func (subscription *natsMarketProbeSubscription) Close() error {
	var err error
	subscription.once.Do(func() {
		close(subscription.done)
		err = subscription.raw.Unsubscribe()
	})
	return err
}

type natsMarketProbeRequest struct {
	message *nats.Msg
	command agentv1.MarketProbeCommand
}

func (request *natsMarketProbeRequest) Command() *agentv1.MarketProbeCommand { return &request.command }

func (request *natsMarketProbeRequest) Reply(result *agentv1.MarketProbeResult) error {
	if result == nil {
		return request.message.Respond(nil)
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil || len(payload) > marketprobe.MaxCarrierBytes {
		return request.message.Respond(nil)
	}
	return request.message.Respond(payload)
}
