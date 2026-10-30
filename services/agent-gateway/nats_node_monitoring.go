package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSNodeMonitoringBusConfig struct {
	CommandStream        string
	StatusStream         string
	CommandSubjectPrefix string
	StatusSubjectPrefix  string
	ConsumerPrefix       string
	MaxMessageBytes      int
	MaxAckPending        int
	AckWait              time.Duration
	OperationTimeout     time.Duration
}

func DefaultNATSNodeMonitoringBusConfig() NATSNodeMonitoringBusConfig {
	return NATSNodeMonitoringBusConfig{
		CommandStream: NodeMonitoringCommandStream, StatusStream: NodeMonitoringStatusStream,
		CommandSubjectPrefix: "cdnca.agent.node-monitoring.commands",
		StatusSubjectPrefix:  "cdnca.agent.node-monitoring.status", ConsumerPrefix: "node_monitoring",
		MaxMessageBytes: maxNodeMonitoringBytes, MaxAckPending: 64,
		AckWait: 2 * time.Minute, OperationTimeout: 5 * time.Second,
	}
}

func (config NATSNodeMonitoringBusConfig) validate() error {
	if !validNATSName(config.CommandStream) || !validNATSName(config.StatusStream) ||
		!validNATSName(config.ConsumerPrefix) || !validSubjectPrefix(config.CommandSubjectPrefix) ||
		!validSubjectPrefix(config.StatusSubjectPrefix) || config.CommandSubjectPrefix == config.StatusSubjectPrefix ||
		config.MaxMessageBytes <= 0 || config.MaxAckPending <= 0 || config.AckWait <= 0 || config.OperationTimeout <= 0 {
		return fmt.Errorf("invalid node monitoring NATS configuration")
	}
	return nil
}

type NATSNodeMonitoringBus struct {
	js     nats.JetStreamContext
	config NATSNodeMonitoringBusConfig
}

func NewNATSNodeMonitoringBus(connection *nats.Conn, config NATSNodeMonitoringBusConfig) (*NATSNodeMonitoringBus, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("an active NATS connection is required")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, err
	}
	return &NATSNodeMonitoringBus{js: js, config: config}, nil
}

func nodeMonitoringCommandSubject(config NATSNodeMonitoringBusConfig, nodeID string) string {
	return config.CommandSubjectPrefix + "." + nodeID
}

func nodeMonitoringStatusSubject(config NATSNodeMonitoringBusConfig, nodeID string) string {
	return config.StatusSubjectPrefix + "." + nodeID
}

func (bus *NATSNodeMonitoringBus) SubscribeNodeMonitoring(ctx context.Context, nodeID string) (NodeMonitoringSubscription, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid node monitoring subscription")
	}
	subject := nodeMonitoringCommandSubject(bus.config, nodeID)
	durable := bus.config.ConsumerPrefix + "_" + strings.ReplaceAll(nodeID, "-", "_")
	consumer := &nats.ConsumerConfig{Durable: durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: bus.config.AckWait, MaxDeliver: -1,
		FilterSubject: subject, ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: bus.config.MaxAckPending, MaxWaiting: 1, MaxRequestBatch: 1,
		MaxRequestExpires: bus.config.OperationTimeout}
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	_, err := bus.js.AddConsumer(bus.config.CommandStream, consumer, nats.Context(op))
	cancel()
	if err != nil {
		op, cancel = context.WithTimeout(ctx, bus.config.OperationTimeout)
		info, infoErr := bus.js.ConsumerInfo(bus.config.CommandStream, durable, nats.Context(op))
		cancel()
		if infoErr != nil || !sameConsumerConfig(info, consumer) {
			return nil, fmt.Errorf("bind durable node monitoring consumer: %w", err)
		}
	}
	subscription, err := bus.js.PullSubscribe(subject, durable, nats.Bind(bus.config.CommandStream, durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable node monitoring artifacts: %w", err)
	}
	return &natsNodeMonitoringSubscription{subscription: subscription, config: bus.config}, nil
}

func (bus *NATSNodeMonitoringBus) PublishNodeMonitoring(ctx context.Context, nodeID string, report *agentv1.NodeMonitoringReport) (NodeMonitoringPublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || report == nil || report.NodeId != nodeID {
		return NodeMonitoringPublication{}, fmt.Errorf("invalid node monitoring publication")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil || len(payload) > bus.config.MaxMessageBytes {
		return NodeMonitoringPublication{}, fmt.Errorf("encode node monitoring publication")
	}
	message := nats.NewMsg(nodeMonitoringStatusSubject(bus.config, nodeID))
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, report.Event.EventId)
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	ack, err := bus.js.PublishMsg(message, nats.Context(op), nats.ExpectStream(bus.config.StatusStream))
	cancel()
	if err != nil || ack == nil || ack.Stream != bus.config.StatusStream || ack.Sequence == 0 {
		return NodeMonitoringPublication{}, fmt.Errorf("publish node monitoring status: %w", err)
	}
	return NodeMonitoringPublication{Stream: ack.Stream, Sequence: ack.Sequence, Replayed: ack.Duplicate}, nil
}

type natsNodeMonitoringSubscription struct {
	subscription *nats.Subscription
	config       NATSNodeMonitoringBusConfig
}

const nodeMonitoringPendingPullBackoff = 50 * time.Millisecond

func nodeMonitoringPullStillPending(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "exceeded maxwaiting")
}

func (subscription *natsNodeMonitoringSubscription) Next(ctx context.Context) (NodeMonitoringDelivery, error) {
	if subscription == nil || subscription.subscription == nil || ctx == nil {
		return nil, fmt.Errorf("invalid node monitoring subscription")
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
			// The consumer allows a single waiting pull (MaxWaiting: 1). After a
			// client-side fetch timeout the server may still hold the expiring pull
			// for a moment, so an immediate re-pull is answered with 409 "Exceeded
			// MaxWaiting". That is transient; returning it would make the gateway
			// end the whole node session as "monitoring delivery failed".
			if nodeMonitoringPullStillPending(err) {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(nodeMonitoringPendingPullBackoff):
				}
				continue
			}
			return nil, err
		}
		if len(messages) != 1 {
			return nil, fmt.Errorf("node monitoring artifact delivery returned %d messages", len(messages))
		}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > subscription.config.MaxMessageBytes {
			_ = messages[0].Nak()
			return nil, fmt.Errorf("node monitoring artifact exceeds limit")
		}
		artifact := &agentv1.NodeMonitoringArtifact{}
		if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, artifact); err != nil ||
			cacheControlMessageHasUnknown(artifact.ProtoReflect()) {
			_ = messages[0].Nak()
			return nil, fmt.Errorf("decode node monitoring artifact")
		}
		return &natsNodeMonitoringDelivery{message: messages[0], artifact: artifact}, nil
	}
}

func (subscription *natsNodeMonitoringSubscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}

type natsNodeMonitoringDelivery struct {
	message  *nats.Msg
	artifact *agentv1.NodeMonitoringArtifact
}

func (delivery *natsNodeMonitoringDelivery) Artifact() *agentv1.NodeMonitoringArtifact {
	if delivery == nil || delivery.artifact == nil {
		return nil
	}
	return proto.Clone(delivery.artifact).(*agentv1.NodeMonitoringArtifact)
}

func (delivery *natsNodeMonitoringDelivery) Ack(ctx context.Context) error {
	if delivery == nil || delivery.message == nil || ctx == nil {
		return fmt.Errorf("node monitoring delivery is missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return delivery.message.AckSync(nats.Context(ctx))
}

func (delivery *natsNodeMonitoringDelivery) Nak(ctx context.Context) error {
	if delivery == nil || delivery.message == nil {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("node monitoring delivery context is missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return delivery.message.Nak()
}

func (delivery *natsNodeMonitoringDelivery) NakWithDelay(ctx context.Context, delay time.Duration) error {
	if delivery == nil || delivery.message == nil || ctx == nil || delay <= 0 {
		return fmt.Errorf("node monitoring delivery is missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return delivery.message.NakWithDelay(delay)
}
