package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSSecurityBanBusConfig struct {
	CommandStream        string
	StatusStream         string
	CommandSubjectPrefix string
	StatusSubjectPrefix  string
	ConsumerPrefix       string
	AckWait              time.Duration
	OperationTimeout     time.Duration
}

func DefaultNATSSecurityBanBusConfig() NATSSecurityBanBusConfig {
	return NATSSecurityBanBusConfig{
		CommandStream: contract.CommandStream, StatusStream: contract.StatusStream,
		CommandSubjectPrefix: contract.CommandSubjectPrefix, StatusSubjectPrefix: contract.StatusSubjectPrefix,
		ConsumerPrefix: contract.GatewayConsumerPrefix, AckWait: 2 * time.Minute, OperationTimeout: 5 * time.Second,
	}
}

func (config NATSSecurityBanBusConfig) validate() error {
	if !validNATSName(config.CommandStream) || !validNATSName(config.StatusStream) || config.CommandStream == config.StatusStream ||
		!validNATSName(config.ConsumerPrefix) || !validSubjectPrefix(config.CommandSubjectPrefix) ||
		!validSubjectPrefix(config.StatusSubjectPrefix) || config.CommandSubjectPrefix == config.StatusSubjectPrefix ||
		config.AckWait <= 0 || config.OperationTimeout <= 0 {
		return fmt.Errorf("invalid security ban NATS configuration")
	}
	return nil
}

// StreamConfigs are the JetStream streams the gateway owns. Commands keep only the newest snapshot per node (each
// carries the whole list); a snapshot for a node that never connects ages out after a week and control-api
// republishes until the node reports it enforces the latest revision.
func (config NATSSecurityBanBusConfig) StreamConfigs() []*nats.StreamConfig {
	return []*nats.StreamConfig{
		{Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			MaxMsgsPerSubject: 1, Discard: nats.DiscardOld, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
		{Name: config.StatusStream, Subjects: []string{config.StatusSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			Discard: nats.DiscardNew, MaxMsgs: 1_000_000, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
	}
}

type NATSSecurityBanBus struct {
	js     nats.JetStreamContext
	config NATSSecurityBanBusConfig
}

// NewNATSSecurityBanBus creates (or verifies) the security ban streams and returns the bus.
func NewNATSSecurityBanBus(ctx context.Context, connection *nats.Conn, config NATSSecurityBanBusConfig) (*NATSSecurityBanBus, error) {
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
			return nil, fmt.Errorf("ensure security ban stream %s: %w", expected.Name, err)
		}
		if len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != expected.Subjects[0] ||
			info.Config.Retention != expected.Retention || max(info.Config.MaxMsgsPerSubject, 0) != expected.MaxMsgsPerSubject {
			return nil, fmt.Errorf("security ban stream %s configuration does not match", expected.Name)
		}
	}
	return &NATSSecurityBanBus{js: js, config: config}, nil
}

func (bus *NATSSecurityBanBus) SubscribeSecurityBans(ctx context.Context, nodeID string) (SecurityBanSubscription, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid security ban subscription")
	}
	subject := bus.config.CommandSubjectPrefix + "." + nodeID
	durable := bus.config.ConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{Durable: durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: bus.config.AckWait, MaxDeliver: -1,
		FilterSubject: subject, ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: 1, MaxWaiting: 1, MaxRequestBatch: 1, MaxRequestExpires: bus.config.OperationTimeout}
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	_, err := bus.js.AddConsumer(bus.config.CommandStream, consumer, nats.Context(op))
	cancel()
	if err != nil {
		op, cancel = context.WithTimeout(ctx, bus.config.OperationTimeout)
		info, infoErr := bus.js.ConsumerInfo(bus.config.CommandStream, durable, nats.Context(op))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable security ban consumer: %w", err)
		}
	}
	subscription, err := bus.js.PullSubscribe(subject, durable, nats.Bind(bus.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable security ban lists: %w", err)
	}
	return &natsSecurityBanSubscription{subscription: subscription, config: bus.config}, nil
}

func (bus *NATSSecurityBanBus) PublishSecurityBanStatus(ctx context.Context, nodeID string, report *agentv1.SecurityBanStatus) (SecurityBanPublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || report == nil ||
		report.NodeId != nodeID || report.Event == nil {
		return SecurityBanPublication{}, fmt.Errorf("invalid security ban status publication")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return SecurityBanPublication{}, fmt.Errorf("encode security ban status")
	}
	message := nats.NewMsg(bus.config.StatusSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, report.Event.EventId)
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	ack, err := bus.js.PublishMsg(message, nats.Context(op), nats.ExpectStream(bus.config.StatusStream))
	cancel()
	if err != nil || ack == nil || ack.Stream != bus.config.StatusStream || ack.Sequence == 0 {
		return SecurityBanPublication{}, fmt.Errorf("publish security ban status: %w", err)
	}
	return SecurityBanPublication{Stream: ack.Stream, Sequence: ack.Sequence, Replayed: ack.Duplicate}, nil
}

type natsSecurityBanSubscription struct {
	subscription *nats.Subscription
	config       NATSSecurityBanBusConfig
}

func (subscription *natsSecurityBanSubscription) Next(ctx context.Context) (SecurityBanDelivery, error) {
	if subscription == nil || subscription.subscription == nil || ctx == nil {
		return nil, fmt.Errorf("invalid security ban subscription")
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
			return nil, fmt.Errorf("security ban list delivery returned %d messages", len(messages))
		}
		command := &agentv1.SecurityBanCommand{}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > contract.MaxCarrierBytes ||
			(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command) != nil ||
			cacheControlMessageHasUnknown(command.ProtoReflect()) {
			// A malformed publication can never become valid; drop it instead of redelivering forever.
			_ = messages[0].Term()
			continue
		}
		return &natsSecurityBanDelivery{message: messages[0], command: command}, nil
	}
}

func (subscription *natsSecurityBanSubscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}

type natsSecurityBanDelivery struct {
	message *nats.Msg
	command *agentv1.SecurityBanCommand
}

func (delivery *natsSecurityBanDelivery) Command() *agentv1.SecurityBanCommand {
	return proto.Clone(delivery.command).(*agentv1.SecurityBanCommand)
}

func (delivery *natsSecurityBanDelivery) Ack(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("security ban delivery context is invalid")
	}
	return delivery.message.AckSync(nats.Context(ctx))
}

func (delivery *natsSecurityBanDelivery) Nak(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("security ban delivery context is invalid")
	}
	return delivery.message.Nak()
}

// Term drops a delivery that failed gateway validation; it can never become valid.
func (delivery *natsSecurityBanDelivery) Term() error { return delivery.message.Term() }
