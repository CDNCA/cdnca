package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type NATSSSHAccessBusConfig struct {
	CommandStream        string
	ReceiptStream        string
	CommandSubjectPrefix string
	ReceiptSubjectPrefix string
	OperationTimeout     time.Duration
}

func DefaultNATSSSHAccessBusConfig() NATSSSHAccessBusConfig {
	return NATSSSHAccessBusConfig{
		CommandStream: contract.CommandStream, ReceiptStream: contract.ReceiptStream,
		CommandSubjectPrefix: contract.CommandSubjectPrefix, ReceiptSubjectPrefix: contract.ReceiptSubjectPrefix,
		OperationTimeout: 5 * time.Second,
	}
}

func (config NATSSSHAccessBusConfig) validate() error {
	if !validNATSName(config.CommandStream) || !validNATSName(config.ReceiptStream) || config.CommandStream == config.ReceiptStream ||
		!validSubjectPrefix(config.CommandSubjectPrefix) || !validSubjectPrefix(config.ReceiptSubjectPrefix) ||
		config.CommandSubjectPrefix == config.ReceiptSubjectPrefix || config.OperationTimeout <= 0 {
		return fmt.Errorf("invalid SSH access NATS configuration")
	}
	return nil
}

// StreamConfigs are the JetStream streams the gateway owns. Commands are not
// consumed: the stream keeps each node's newest command and every session
// reads it again (the node answers a repeated revision with its state).
func (config NATSSSHAccessBusConfig) StreamConfigs() []*nats.StreamConfig {
	return []*nats.StreamConfig{
		{Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"}, Retention: nats.LimitsPolicy,
			MaxMsgsPerSubject: 1, Discard: nats.DiscardOld, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
		{Name: config.ReceiptStream, Subjects: []string{config.ReceiptSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy,
			Discard: nats.DiscardNew, MaxMsgs: 1_000_000, MaxAge: 7 * 24 * time.Hour,
			MaxMsgSize: int32(contract.MaxCarrierBytes), Storage: nats.FileStorage, Replicas: 1, Duplicates: 2 * time.Minute},
	}
}

type NATSSSHAccessBus struct {
	js     nats.JetStreamContext
	config NATSSSHAccessBusConfig
}

// NewNATSSSHAccessBus creates (or verifies) the SSH access streams and returns the bus.
func NewNATSSSHAccessBus(ctx context.Context, connection *nats.Conn, config NATSSSHAccessBusConfig) (*NATSSSHAccessBus, error) {
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
			return nil, fmt.Errorf("ensure SSH access stream %s: %w", expected.Name, err)
		}
		if len(info.Config.Subjects) != 1 || info.Config.Subjects[0] != expected.Subjects[0] ||
			info.Config.Retention != expected.Retention || max(info.Config.MaxMsgsPerSubject, 0) != expected.MaxMsgsPerSubject {
			return nil, fmt.Errorf("SSH access stream %s configuration does not match", expected.Name)
		}
	}
	return &NATSSSHAccessBus{js: js, config: config}, nil
}

// SubscribeSSHAccess opens a per-session ephemeral consumer starting at
// the node's newest command; nothing is acknowledged.
func (bus *NATSSSHAccessBus) SubscribeSSHAccess(ctx context.Context, nodeID string) (SSHAccessSubscription, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) {
		return nil, fmt.Errorf("invalid SSH access subscription")
	}
	subject := bus.config.CommandSubjectPrefix + "." + nodeID
	subscription, err := bus.js.PullSubscribe(subject, "", nats.BindStream(bus.config.CommandStream),
		nats.DeliverLastPerSubject(), nats.AckNone(), nats.InactiveThreshold(time.Minute))
	if err != nil {
		return nil, fmt.Errorf("subscribe to SSH accesss: %w", err)
	}
	return &natsSSHAccessSubscription{subscription: subscription, config: bus.config}, nil
}

func (bus *NATSSSHAccessBus) PublishSSHAccessReceipt(ctx context.Context, nodeID string, receipt *agentv1.SSHAccessReceipt) (SSHAccessPublication, error) {
	if bus == nil || bus.js == nil || ctx == nil || !validNodeMonitoringNodeID(nodeID) || receipt == nil ||
		receipt.NodeId != nodeID || receipt.Event == nil {
		return SSHAccessPublication{}, fmt.Errorf("invalid SSH access receipt publication")
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil || len(payload) > contract.MaxCarrierBytes {
		return SSHAccessPublication{}, fmt.Errorf("encode SSH access receipt")
	}
	message := nats.NewMsg(bus.config.ReceiptSubjectPrefix + "." + nodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, receipt.Event.EventId)
	op, cancel := context.WithTimeout(ctx, bus.config.OperationTimeout)
	ack, err := bus.js.PublishMsg(message, nats.Context(op), nats.ExpectStream(bus.config.ReceiptStream))
	cancel()
	if err != nil || ack == nil || ack.Stream != bus.config.ReceiptStream || ack.Sequence == 0 {
		return SSHAccessPublication{}, fmt.Errorf("publish SSH access receipt: %w", err)
	}
	return SSHAccessPublication{Stream: ack.Stream, Sequence: ack.Sequence, Replayed: ack.Duplicate}, nil
}

type natsSSHAccessSubscription struct {
	subscription *nats.Subscription
	config       NATSSSHAccessBusConfig
}

func (subscription *natsSSHAccessSubscription) Next(ctx context.Context) (*agentv1.SSHAccessCommand, error) {
	if subscription == nil || subscription.subscription == nil || ctx == nil {
		return nil, fmt.Errorf("invalid SSH access subscription")
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
			return nil, fmt.Errorf("SSH access delivery returned %d messages", len(messages))
		}
		command := &agentv1.SSHAccessCommand{}
		if len(messages[0].Data) == 0 || len(messages[0].Data) > contract.MaxCarrierBytes ||
			(proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(messages[0].Data, command) != nil ||
			cacheControlMessageHasUnknown(command.ProtoReflect()) {
			continue // a malformed publication can never become valid; wait for the next one
		}
		return command, nil
	}
}

func (subscription *natsSSHAccessSubscription) Close() error {
	if subscription == nil || subscription.subscription == nil {
		return nil
	}
	return subscription.subscription.Unsubscribe()
}
