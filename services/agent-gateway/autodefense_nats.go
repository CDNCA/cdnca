package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSAutoDefenseBusConfig struct {
	CommandStream        string
	ReceiptStream        string
	ReportStream         string
	CommandSubjectPrefix string
	ReceiptSubjectPrefix string
	ReportSubjectPrefix  string
	ConsumerPrefix       string
	AckWait              time.Duration
	OperationTimeout     time.Duration
}

func DefaultNATSAutoDefenseBusConfig() NATSAutoDefenseBusConfig {
	return NATSAutoDefenseBusConfig{
		CommandStream: contract.CommandStream, ReceiptStream: contract.ReceiptStream, ReportStream: contract.ReportStream,
		CommandSubjectPrefix: contract.CommandSubjectPrefix, ReceiptSubjectPrefix: contract.ReceiptSubjectPrefix,
		ReportSubjectPrefix: contract.ReportSubjectPrefix, ConsumerPrefix: contract.GatewayConsumerPrefix,
		AckWait: 2 * time.Minute, OperationTimeout: 5 * time.Second,
	}
}

func (config NATSAutoDefenseBusConfig) validate() error {
	streams := []string{config.CommandStream, config.ReceiptStream, config.ReportStream}
	prefixes := []string{config.CommandSubjectPrefix, config.ReceiptSubjectPrefix, config.ReportSubjectPrefix}
	for index := range streams {
		if !validNATSName(streams[index]) || !validSubjectPrefix(prefixes[index]) {
			return fmt.Errorf("invalid auto defense NATS configuration")
		}
		for other := index + 1; other < len(streams); other++ {
			if streams[index] == streams[other] || prefixes[index] == prefixes[other] {
				return fmt.Errorf("invalid auto defense NATS configuration")
			}
		}
	}
	if !validNATSName(config.ConsumerPrefix) || config.AckWait <= 0 || config.OperationTimeout <= 0 {
		return fmt.Errorf("invalid auto defense NATS configuration")
	}
	return nil
}

// StreamConfigs are the JetStream streams the gateway owns.
//
// Commands: work queue, one durable consumer per node; a revision has up to MaxParts parts, so the newest
// 2 x MaxParts messages per node are kept (a superseded revision is refused by the node as stale_revision and
// acknowledged like any other part). A node that never connects ages out after a week; control-api republishes
// until the node reports the latest revision.
// Receipts: consumed by control-api (control_api_autodefense_receipts).
// Reports: display only, limits retention for a day, bounded per node; the 10 minute duplicate window makes
// node/scope/seq publication idempotent across Agent retries and gateway reconnects.
func (config NATSAutoDefenseBusConfig) StreamConfigs() []*nats.StreamConfig {
	return []*nats.StreamConfig{
		{Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			MaxMsgsPerSubject: 2 * contract.MaxParts, Discard: nats.DiscardOld, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
		{Name: config.ReceiptStream, Subjects: []string{config.ReceiptSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			Discard: nats.DiscardNew, MaxMsgs: 1_000_000, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: maxAutoDefenseReceiptBytes, Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
		{Name: config.ReportStream, Subjects: []string{config.ReportSubjectPrefix + ".*"}, Retention: nats.LimitsPolicy,
			Discard: nats.DiscardOld, MaxMsgsPerSubject: 100_000, MaxBytes: 8 << 30, MaxAge: 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxReportBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute},
	}
}

type NATSAutoDefenseBus struct {
	js     nats.JetStreamContext
	config NATSAutoDefenseBusConfig
}

// NewNATSAutoDefenseBus creates (or verifies) the automatic defense streams and returns the bus.
func NewNATSAutoDefenseBus(ctx context.Context, connection *nats.Conn, config NATSAutoDefenseBusConfig) (*NATSAutoDefenseBus, error) {
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
			return nil, fmt.Errorf("ensure auto defense stream %s: %w", expected.Name, err)
		}
		if len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != expected.Subjects[0] ||
			info.Config.Retention != expected.Retention || max(info.Config.MaxMsgsPerSubject, 0) != expected.MaxMsgsPerSubject ||
			info.Config.Duplicates < expected.Duplicates {
			return nil, fmt.Errorf("auto defense stream %s configuration does not match", expected.Name)
		}
	}
	return &NATSAutoDefenseBus{js: js, config: config}, nil
}

func (bus *NATSAutoDefenseBus) SubscribeAutoDefense(ctx context.Context, nodeID string) (AutoDefenseSubscription, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid auto defense subscription")
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
			return nil, fmt.Errorf("bind durable auto defense consumer: %w", err)
		}
	}
	subscription, err := bus.js.PullSubscribe(subject, durable, nats.Bind(bus.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable auto defense snapshots: %w", err)
	}
	return &natsAutoDefenseSubscription{subscription: subscription, config: bus.config}, nil
}

func (bus *NATSAutoDefenseBus) PublishAutoDefenseReceipt(ctx context.Context, nodeID string, receipt *agentv1.AutoDefenseReceipt) (AutoDefensePublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || receipt == nil ||
		receipt.NodeId != nodeID || receipt.Event == nil {
		return AutoDefensePublication{}, fmt.Errorf("invalid auto defense receipt publication")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil || len(payload) > maxAutoDefenseReceiptBytes {
		return AutoDefensePublication{}, fmt.Errorf("encode auto defense receipt")
	}
	message := nats.NewMsg(bus.config.ReceiptSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, receipt.Event.EventId)
	return bus.publish(ctx, message, bus.config.ReceiptStream)
}

func (bus *NATSAutoDefenseBus) PublishAutoDefenseReport(ctx context.Context, nodeID, msgID string, report []byte) (AutoDefensePublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || msgID == "" ||
		len(report) == 0 || len(report) > contract.MaxReportBytes {
		return AutoDefensePublication{}, fmt.Errorf("invalid auto defense report publication")
	}
	message := nats.NewMsg(bus.config.ReportSubjectPrefix + "." + nodeID)
	message.Data = append([]byte(nil), report...)
	message.Header.Set(nats.MsgIdHdr, msgID)
	return bus.publish(ctx, message, bus.config.ReportStream)
}

func (bus *NATSAutoDefenseBus) publish(ctx context.Context, message *nats.Msg, stream string) (AutoDefensePublication, error) {
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	ack, err := bus.js.PublishMsg(message, nats.Context(op), nats.ExpectStream(stream))
	cancel()
	if err != nil || ack == nil || ack.Stream != stream || ack.Sequence == 0 {
		return AutoDefensePublication{}, fmt.Errorf("publish auto defense message: %w", err)
	}
	return AutoDefensePublication{Stream: ack.Stream, Sequence: ack.Sequence, Replayed: ack.Duplicate}, nil
}

type natsAutoDefenseSubscription struct {
	subscription *nats.Subscription
	config       NATSAutoDefenseBusConfig
}

func (subscription *natsAutoDefenseSubscription) Next(ctx context.Context) (AutoDefenseDelivery, error) {
	if subscription == nil || subscription.subscription == nil || ctx == nil {
		return nil, fmt.Errorf("invalid auto defense subscription")
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
			return nil, fmt.Errorf("auto defense delivery returned %d messages", len(messages))
		}
		command := &agentv1.AutoDefenseCommand{}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > contract.MaxCarrierBytes ||
			(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command) != nil ||
			cacheControlMessageHasUnknown(command.ProtoReflect()) {
			// A malformed publication can never become valid; drop it instead of redelivering forever.
			_ = messages[0].Term()
			continue
		}
		return &natsAutoDefenseDelivery{message: messages[0], command: command}, nil
	}
}

func (subscription *natsAutoDefenseSubscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}

type natsAutoDefenseDelivery struct {
	message *nats.Msg
	command *agentv1.AutoDefenseCommand
}

func (delivery *natsAutoDefenseDelivery) Command() *agentv1.AutoDefenseCommand {
	return proto.Clone(delivery.command).(*agentv1.AutoDefenseCommand)
}

func (delivery *natsAutoDefenseDelivery) Ack(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("auto defense delivery context is invalid")
	}
	return delivery.message.AckSync(nats.Context(ctx))
}

func (delivery *natsAutoDefenseDelivery) Nak(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return fmt.Errorf("auto defense delivery context is invalid")
	}
	return delivery.message.Nak()
}

// Term drops a delivery that failed gateway validation; it can never become valid.
func (delivery *natsAutoDefenseDelivery) Term() error { return delivery.message.Term() }
