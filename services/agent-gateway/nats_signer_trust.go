package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/signertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSSignerTrustBusConfig struct {
	CommandStream        string
	StatusStream         string
	CommandSubjectPrefix string
	StatusSubjectPrefix  string
	ConsumerPrefix       string
	AckWait              time.Duration
	OperationTimeout     time.Duration
}

func DefaultNATSSignerTrustBusConfig() NATSSignerTrustBusConfig {
	return NATSSignerTrustBusConfig{
		CommandStream: contract.CommandStream, StatusStream: contract.StatusStream,
		CommandSubjectPrefix: contract.CommandSubjectPrefix, StatusSubjectPrefix: contract.StatusSubjectPrefix,
		ConsumerPrefix: contract.GatewayConsumerPrefix, AckWait: 2 * time.Minute, OperationTimeout: 5 * time.Second,
	}
}

func (config NATSSignerTrustBusConfig) validate() error {
	if !validNATSName(config.CommandStream) || !validNATSName(config.StatusStream) || config.CommandStream == config.StatusStream ||
		!validNATSName(config.ConsumerPrefix) || !validSubjectPrefix(config.CommandSubjectPrefix) ||
		!validSubjectPrefix(config.StatusSubjectPrefix) || config.CommandSubjectPrefix == config.StatusSubjectPrefix ||
		config.AckWait <= 0 || config.OperationTimeout <= 0 {
		return fmt.Errorf("invalid edge signer trust NATS configuration")
	}
	return nil
}

// StreamConfigs are the JetStream streams the gateway owns. Commands keep only the newest bundle per node (each
// carries the whole document); a bundle for a node that never connects ages out after a week and control-api
// republishes until the node reports it enforces the latest revision.
func (config NATSSignerTrustBusConfig) StreamConfigs() []*nats.StreamConfig {
	return []*nats.StreamConfig{
		{Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			MaxMsgsPerSubject: 1, Discard: nats.DiscardOld, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
		{Name: config.StatusStream, Subjects: []string{config.StatusSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			Discard: nats.DiscardNew, MaxMsgs: 1_000_000, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
	}
}

type NATSSignerTrustBus struct {
	js     nats.JetStreamContext
	config NATSSignerTrustBusConfig
}

// NewNATSSignerTrustBus creates (or verifies) the edge signer trust streams and returns the bus.
func NewNATSSignerTrustBus(ctx context.Context, connection *nats.Conn, config NATSSignerTrustBusConfig) (*NATSSignerTrustBus, error) {
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
			return nil, fmt.Errorf("ensure edge signer trust stream %s: %w", expected.Name, err)
		}
		if len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != expected.Subjects[0] ||
			info.Config.Retention != expected.Retention || max(info.Config.MaxMsgsPerSubject, 0) != expected.MaxMsgsPerSubject {
			return nil, fmt.Errorf("edge signer trust stream %s configuration does not match", expected.Name)
		}
	}
	return &NATSSignerTrustBus{js: js, config: config}, nil
}

func (bus *NATSSignerTrustBus) SubscribeSignerTrust(ctx context.Context, nodeID string) (SignerTrustSubscription, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid edge signer trust subscription")
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
			return nil, fmt.Errorf("bind durable edge signer trust consumer: %w", err)
		}
	}
	subscription, err := bus.js.PullSubscribe(subject, durable, nats.Bind(bus.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable edge signer trust bundles: %w", err)
	}
	return &natsSignerTrustSubscription{subscription: subscription, config: bus.config}, nil
}

func (bus *NATSSignerTrustBus) PublishSignerTrustReceipt(ctx context.Context, nodeID string, receipt *agentv1.EdgeSignerTrustReceipt) (SignerTrustPublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || receipt == nil ||
		receipt.NodeId != nodeID || receipt.Event == nil {
		return SignerTrustPublication{}, fmt.Errorf("invalid edge signer trust receipt publication")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return SignerTrustPublication{}, fmt.Errorf("encode edge signer trust receipt")
	}
	message := nats.NewMsg(bus.config.StatusSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, receipt.Event.EventId)
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	ack, err := bus.js.PublishMsg(message, nats.Context(op), nats.ExpectStream(bus.config.StatusStream))
	cancel()
	if err != nil || ack == nil || ack.Stream != bus.config.StatusStream || ack.Sequence == 0 {
		return SignerTrustPublication{}, fmt.Errorf("publish edge signer trust receipt: %w", err)
	}
	return SignerTrustPublication{Stream: ack.Stream, Sequence: ack.Sequence, Replayed: ack.Duplicate}, nil
}

type natsSignerTrustSubscription struct {
	subscription *nats.Subscription
	config       NATSSignerTrustBusConfig
}

func (subscription *natsSignerTrustSubscription) Next(ctx context.Context) (SignerTrustDelivery, error) {
	if subscription == nil || subscription.subscription == nil || ctx == nil {
		return nil, fmt.Errorf("invalid edge signer trust subscription")
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
			return nil, fmt.Errorf("edge signer trust bundle delivery returned %d messages", len(messages))
		}
		bundle := &agentv1.EdgeSignerTrustBundle{}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > contract.MaxCarrierBytes ||
			(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, bundle) != nil ||
			cacheControlMessageHasUnknown(bundle.ProtoReflect()) {
			// A malformed publication can never become valid; drop it instead of redelivering forever.
			_ = messages[0].Term()
			continue
		}
		return &natsSignerTrustDelivery{message: messages[0], bundle: bundle}, nil
	}
}

func (subscription *natsSignerTrustSubscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}

type natsSignerTrustDelivery struct {
	message *nats.Msg
	bundle  *agentv1.EdgeSignerTrustBundle
}

func (delivery *natsSignerTrustDelivery) Bundle() *agentv1.EdgeSignerTrustBundle {
	return proto.Clone(delivery.bundle).(*agentv1.EdgeSignerTrustBundle)
}

func (delivery *natsSignerTrustDelivery) Ack(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("edge signer trust delivery context is invalid")
	}
	return delivery.message.AckSync(nats.Context(ctx))
}

func (delivery *natsSignerTrustDelivery) Nak(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("edge signer trust delivery context is invalid")
	}
	return delivery.message.Nak()
}

// Term drops a delivery that failed gateway validation; it can never become valid.
func (delivery *natsSignerTrustDelivery) Term() error { return delivery.message.Term() }
