package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSSiteDropBusConfig struct {
	CommandStream        string
	ReceiptStream        string
	CommandSubjectPrefix string
	ReceiptSubjectPrefix string
	OperationTimeout     time.Duration
}

func DefaultNATSSiteDropBusConfig() NATSSiteDropBusConfig {
	return NATSSiteDropBusConfig{
		CommandStream: contract.CommandStream, ReceiptStream: contract.ReceiptStream,
		CommandSubjectPrefix: contract.CommandSubjectPrefix, ReceiptSubjectPrefix: contract.ReceiptSubjectPrefix,
		OperationTimeout: 5 * time.Second,
	}
}

func (config NATSSiteDropBusConfig) validate() error {
	if !validNATSName(config.CommandStream) || !validNATSName(config.ReceiptStream) || config.CommandStream == config.ReceiptStream ||
		!validSubjectPrefix(config.CommandSubjectPrefix) || !validSubjectPrefix(config.ReceiptSubjectPrefix) ||
		config.CommandSubjectPrefix == config.ReceiptSubjectPrefix || config.OperationTimeout <= 0 {
		return fmt.Errorf("invalid site drop NATS configuration")
	}
	return nil
}

// StreamConfigs are the JetStream streams the gateway owns. Unlike the ban
// list work queue, commands are not consumed: the stream keeps each node's
// newest full snapshot and every session reads it again (gateway restart and
// node reconnect resend the current list). A list never outlives 7 days
// (until ≤ issued_at + 7 days), nor does its message.
func (config NATSSiteDropBusConfig) StreamConfigs() []*nats.StreamConfig {
	return []*nats.StreamConfig{
		{Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"}, Retention: nats.LimitsPolicy,
			MaxMsgsPerSubject: 1, Discard: nats.DiscardOld, MaxAge: contract.MaxDuration,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
		{Name: config.ReceiptStream, Subjects: []string{config.ReceiptSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			Discard: nats.DiscardNew, MaxMsgs: 1_000_000, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
	}
}

type NATSSiteDropBus struct {
	js     nats.JetStreamContext
	config NATSSiteDropBusConfig
}

// NewNATSSiteDropBus creates (or verifies) the site drop streams and returns the bus.
func NewNATSSiteDropBus(ctx context.Context, connection *nats.Conn, config NATSSiteDropBusConfig) (*NATSSiteDropBus, error) {
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
			return nil, fmt.Errorf("ensure site drop stream %s: %w", expected.Name, err)
		}
		if len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != expected.Subjects[0] ||
			info.Config.Retention != expected.Retention || max(info.Config.MaxMsgsPerSubject, 0) != expected.MaxMsgsPerSubject {
			return nil, fmt.Errorf("site drop stream %s configuration does not match", expected.Name)
		}
	}
	return &NATSSiteDropBus{js: js, config: config}, nil
}

// SubscribeSiteDrops opens a per-session ephemeral consumer starting at the
// node's newest snapshot; nothing is acknowledged.
func (bus *NATSSiteDropBus) SubscribeSiteDrops(ctx context.Context, nodeID string) (SiteDropSubscription, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid site drop subscription")
	}
	subject := bus.config.CommandSubjectPrefix + "." + nodeID
	subscription, err := bus.js.PullSubscribe(subject, "", nats.BindStream(bus.config.CommandStream),
		nats.DeliverLastPerSubject(), nats.AckNone(), nats.InactiveThreshold(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("subscribe to site drop lists: %w", err)
	}
	return &natsSiteDropSubscription{subscription: subscription, config: bus.config}, nil
}

func (bus *NATSSiteDropBus) PublishSiteDropReceipt(ctx context.Context, nodeID string, receipt *agentv1.SiteDropReceipt) (SiteDropPublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || receipt == nil ||
		receipt.NodeId != nodeID || receipt.Event == nil {
		return SiteDropPublication{}, fmt.Errorf("invalid site drop receipt publication")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return SiteDropPublication{}, fmt.Errorf("encode site drop receipt")
	}
	message := nats.NewMsg(bus.config.ReceiptSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, receipt.Event.EventId)
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	ack, err := bus.js.PublishMsg(message, nats.Context(op), nats.ExpectStream(bus.config.ReceiptStream))
	cancel()
	if err != nil || ack == nil || ack.Stream != bus.config.ReceiptStream || ack.Sequence == 0 {
		return SiteDropPublication{}, fmt.Errorf("publish site drop receipt: %w", err)
	}
	return SiteDropPublication{Stream: ack.Stream, Sequence: ack.Sequence, Replayed: ack.Duplicate}, nil
}

type natsSiteDropSubscription struct {
	subscription *nats.Subscription
	config       NATSSiteDropBusConfig
}

func (subscription *natsSiteDropSubscription) Next(ctx context.Context) (*agentv1.SiteDropCommand, error) {
	if subscription == nil || subscription.subscription == nil || ctx == nil {
		return nil, fmt.Errorf("invalid site drop subscription")
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
			return nil, fmt.Errorf("site drop list delivery returned %d messages", len(messages))
		}
		command := &agentv1.SiteDropCommand{}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > contract.MaxCarrierBytes ||
			(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command) != nil ||
			cacheControlMessageHasUnknown(command.ProtoReflect()) {
			continue // a malformed publication can never become valid; wait for the next one
		}
		return command, nil
	}
}

func (subscription *natsSiteDropSubscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}
