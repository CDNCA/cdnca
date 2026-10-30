package edgestatus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	DefaultStatusStream  = "AGENT_DEPLOYMENT_STATUS"
	DefaultStatusDurable = "control_api_edge_status"
)

type NATSConsumerConfig struct {
	Stream           string
	SubjectPrefix    string
	Durable          string
	AckWait          time.Duration
	FetchTimeout     time.Duration
	OperationTimeout time.Duration
	NakDelay         time.Duration
	MaxAckPending    int
	MaxWaiting       int
}

func DefaultNATSConsumerConfig() NATSConsumerConfig {
	return NATSConsumerConfig{
		Stream: DefaultStatusStream, SubjectPrefix: DefaultSubjectPrefix, Durable: DefaultStatusDurable,
		AckWait: 2 * time.Minute, FetchTimeout: 5 * time.Second, OperationTimeout: 5 * time.Second,
		NakDelay: time.Second, MaxAckPending: 256, MaxWaiting: 32,
	}
}

type Delivery interface {
	Subject() string
	Data() []byte
	Ack(context.Context) error
	Nak(context.Context, time.Duration) error
	Term(context.Context) error
}

type NATSConsumer struct {
	subscription *nats.Subscription
	config       NATSConsumerConfig
}

type natsDelivery struct {
	message *nats.Msg
}

func NewNATSConsumer(connection *nats.Conn, config NATSConsumerConfig) (*NATSConsumer, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("active NATS connection is required")
	}
	if !validNATSName(config.Stream) || !validNATSName(config.Durable) || !validSubjectPrefix(config.SubjectPrefix) ||
		config.AckWait <= 0 || config.FetchTimeout <= 0 || config.OperationTimeout <= 0 || config.NakDelay <= 0 ||
		config.MaxAckPending <= 0 || config.MaxWaiting <= 0 {
		return nil, fmt.Errorf("invalid deployment status consumer configuration")
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create deployment status JetStream context: %w", err)
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := js.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("find pre-created deployment status consumer: %w", err)
	}
	if !sameStatusConsumer(info, config) {
		return nil, fmt.Errorf("pre-created deployment status consumer configuration does not match")
	}
	subscription, err := js.PullSubscribe("", config.Durable, nats.Bind(config.Stream, config.Durable))
	if err != nil {
		return nil, fmt.Errorf("bind deployment status consumer: %w", err)
	}
	return &NATSConsumer{subscription: subscription, config: config}, nil
}

func (c *NATSConsumer) Next(ctx context.Context) (Delivery, error) {
	if ctx == nil {
		return nil, fmt.Errorf("deployment status fetch context is required")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, c.config.FetchTimeout)
	messages, err := c.subscription.Fetch(1, nats.Context(fetchCtx))
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			return nil, ErrNoMessage
		}
		return nil, fmt.Errorf("fetch deployment status: %w", err)
	}
	if len(messages) != 1 {
		return nil, fmt.Errorf("deployment status consumer returned %d messages", len(messages))
	}
	return &natsDelivery{message: messages[0]}, nil
}

func (c *NATSConsumer) Close() error {
	if c == nil || c.subscription == nil {
		return nil
	}
	return c.subscription.Unsubscribe()
}

func (d *natsDelivery) Subject() string { return d.message.Subject }
func (d *natsDelivery) Data() []byte    { return d.message.Data }

func (d *natsDelivery) NumDelivered() uint64 {
	metadata, err := d.message.Metadata()
	if err != nil {
		return 0
	}
	return metadata.NumDelivered
}

func (d *natsDelivery) Ack(ctx context.Context) error {
	if err := d.message.AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("ack deployment status: %w", err)
	}
	return nil
}

func (d *natsDelivery) Nak(ctx context.Context, delay time.Duration) error {
	if err := d.message.NakWithDelay(delay, nats.Context(ctx)); err != nil {
		return fmt.Errorf("nak deployment status: %w", err)
	}
	return nil
}

func (d *natsDelivery) Term(ctx context.Context) error {
	if err := d.message.Term(nats.Context(ctx)); err != nil {
		return fmt.Errorf("terminate deployment status: %w", err)
	}
	return nil
}

func sameStatusConsumer(info *nats.ConsumerInfo, expected NATSConsumerConfig) bool {
	if info == nil {
		return false
	}
	actual := info.Config
	return actual.Durable == expected.Durable && actual.FilterSubject == "" &&
		sameOrderedSubjects(actual.FilterSubjects, []string{expected.SubjectPrefix + ".*", expected.SubjectPrefix + ".generic-v2.*.*"}) &&
		actual.DeliverPolicy == nats.DeliverAllPolicy && actual.AckPolicy == nats.AckExplicitPolicy &&
		actual.AckWait == expected.AckWait && actual.MaxDeliver == -1 &&
		actual.ReplayPolicy == nats.ReplayInstantPolicy && actual.MaxAckPending == expected.MaxAckPending &&
		actual.MaxWaiting == expected.MaxWaiting && actual.MaxRequestBatch == 1 &&
		actual.MaxRequestExpires == expected.FetchTimeout
}

func sameOrderedSubjects(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}
