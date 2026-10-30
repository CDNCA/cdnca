package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSGatewayAddressBusConfig struct {
	CommandStream        string
	ReceiptStream        string
	CommandSubjectPrefix string
	ReceiptSubjectPrefix string
	OperationTimeout     time.Duration
}

func DefaultNATSGatewayAddressBusConfig() NATSGatewayAddressBusConfig {
	return NATSGatewayAddressBusConfig{
		CommandStream: contract.CommandStream, ReceiptStream: contract.ReceiptStream,
		CommandSubjectPrefix: contract.CommandSubjectPrefix, ReceiptSubjectPrefix: contract.ReceiptSubjectPrefix,
		OperationTimeout: 5 * time.Second,
	}
}

func (config NATSGatewayAddressBusConfig) validate() error {
	if !validNATSName(config.CommandStream) || !validNATSName(config.ReceiptStream) || config.CommandStream == config.ReceiptStream ||
		!validSubjectPrefix(config.CommandSubjectPrefix) || !validSubjectPrefix(config.ReceiptSubjectPrefix) ||
		config.CommandSubjectPrefix == config.ReceiptSubjectPrefix || config.OperationTimeout <= 0 {
		return fmt.Errorf("invalid gateway address change NATS configuration")
	}
	return nil
}

// StreamConfigs are the JetStream streams the gateway owns. Commands are not
// consumed: the stream keeps each node's newest document and every session
// reads it again (a switched node gets it on the new address and answers
// switched there). A document never outlives MaxLifetime, nor does its message.
func (config NATSGatewayAddressBusConfig) StreamConfigs() []*nats.StreamConfig {
	return []*nats.StreamConfig{
		{Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"}, Retention: nats.LimitsPolicy,
			MaxMsgsPerSubject: 1, Discard: nats.DiscardOld, MaxAge: contract.MaxLifetime,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
		{Name: config.ReceiptStream, Subjects: []string{config.ReceiptSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			Discard: nats.DiscardNew, MaxMsgs: 1_000_000, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
	}
}

type NATSGatewayAddressBus struct {
	js     nats.JetStreamContext
	config NATSGatewayAddressBusConfig
}

// NewNATSGatewayAddressBus creates (or verifies) the address change streams and returns the bus.
func NewNATSGatewayAddressBus(ctx context.Context, connection *nats.Conn, config NATSGatewayAddressBusConfig) (*NATSGatewayAddressBus, error) {
	if ctx == nil || connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("an active NATS connection is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, err
	}
	for _, expected := range config.StreamConfigs() {
		op, cancel := context.WithTimeout(ctx, config.OperationTimeout)
		info, err := js.StreamInfo(expected.Name, nats.Context(op))
		if errors.Is(err, nats.ErrStreamNotFound) {
			info, err = js.AddStream(expected, nats.Context(op))
		}
		cancel()
		if err != nil {
			return nil, fmt.Errorf("ensure gateway address change stream %s: %w", expected.Name, err)
		}
		if len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != expected.Subjects[0] ||
			info.Config.Retention != expected.Retention || max(info.Config.MaxMsgsPerSubject, 0) != expected.MaxMsgsPerSubject {
			return nil, fmt.Errorf("gateway address change stream %s configuration does not match", expected.Name)
		}
	}
	return &NATSGatewayAddressBus{js: js, config: config}, nil
}

// SubscribeGatewayAddressChanges opens a per-session ephemeral consumer
// starting at the node's newest document; nothing is acknowledged.
func (bus *NATSGatewayAddressBus) SubscribeGatewayAddressChanges(ctx context.Context, nodeID string) (GatewayAddressSubscription, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid gateway address change subscription")
	}
	subject := bus.config.CommandSubjectPrefix + "." + nodeID
	subscription, err := bus.js.PullSubscribe(subject, "", nats.BindStream(bus.config.CommandStream),
		nats.DeliverLastPerSubject(), nats.AckNone(), nats.InactiveThreshold(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("subscribe to gateway address changes: %w", err)
	}
	return &natsGatewayAddressSubscription{subscription: subscription, config: bus.config}, nil
}

func (bus *NATSGatewayAddressBus) PublishGatewayAddressReceipt(ctx context.Context, nodeID string, receipt *agentv1.GatewayAddressChangeReceipt) (GatewayAddressPublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || receipt == nil ||
		receipt.NodeId != nodeID || receipt.Event == nil {
		return GatewayAddressPublication{}, fmt.Errorf("invalid gateway address change receipt publication")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return GatewayAddressPublication{}, fmt.Errorf("encode gateway address change receipt")
	}
	message := nats.NewMsg(bus.config.ReceiptSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, receipt.Event.EventId)
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	ack, err := bus.js.PublishMsg(message, nats.Context(op), nats.ExpectStream(bus.config.ReceiptStream))
	cancel()
	if err != nil || ack == nil || ack.Stream != bus.config.ReceiptStream || ack.Sequence == 0 {
		return GatewayAddressPublication{}, fmt.Errorf("publish gateway address change receipt: %w", err)
	}
	return GatewayAddressPublication{Stream: ack.Stream, Sequence: ack.Sequence, Replayed: ack.Duplicate}, nil
}

type natsGatewayAddressSubscription struct {
	subscription *nats.Subscription
	config       NATSGatewayAddressBusConfig
}

func (subscription *natsGatewayAddressSubscription) Next(ctx context.Context) (*agentv1.GatewayAddressChangeCommand, error) {
	if subscription == nil || subscription.subscription == nil || ctx == nil {
		return nil, fmt.Errorf("invalid gateway address change subscription")
	}
	for {
		fetchContext, cancel := context.WithTimeout(ctx, subscription.config.OperationTimeout)
		messages, err := subscription.subscription.Fetch(1, nats.Context(fetchContext))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
				continue
			}
			return nil, err
		}
		if len(messages) != 1 {
			return nil, fmt.Errorf("gateway address change delivery returned %d messages", len(messages))
		}
		command := &agentv1.GatewayAddressChangeCommand{}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > contract.MaxCarrierBytes ||
			(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command) != nil ||
			cacheControlMessageHasUnknown(command.ProtoReflect()) {
			continue // a malformed publication can never become valid; wait for the next one
		}
		return command, nil
	}
}

func (subscription *natsGatewayAddressSubscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}
