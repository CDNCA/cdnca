package nodepresence

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nats-io/nats.go"
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

type heartbeatJetStream interface {
	AddConsumer(string, *nats.ConsumerConfig, ...nats.JSOpt) (*nats.ConsumerInfo, error)
	ConsumerInfo(string, string, ...nats.JSOpt) (*nats.ConsumerInfo, error)
	PullSubscribe(string, string, ...nats.SubOpt) (*nats.Subscription, error)
}

type natsDelivery struct {
	message *nats.Msg
}

func NewNATSConsumer(connection *nats.Conn, config NATSConsumerConfig) (*NATSConsumer, error) {
	if connection == nil || connection.IsClosed() {
		return nil, fmt.Errorf("active NATS connection is required")
	}
	if !validNATSName(config.Stream) || !validNATSName(config.Durable) || !validSubjectPrefix(config.SubjectPrefix) ||
		config.AckWait <= 0 || config.FetchTimeout <= 0 || config.OperationTimeout <= 0 ||
		config.NakDelay <= 0 || config.MaxAckPending <= 0 || config.MaxWaiting <= 0 {
		return nil, fmt.Errorf("invalid durable heartbeat consumer configuration")
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, fmt.Errorf("create heartbeat JetStream context: %w", err)
	}
	return newNATSConsumer(js, config)
}

func newNATSConsumer(js heartbeatJetStream, config NATSConsumerConfig) (*NATSConsumer, error) {
	filterSubject := config.SubjectPrefix + ".*"
	consumerConfig := &nats.ConsumerConfig{
		Durable:           config.Durable,
		DeliverPolicy:     nats.DeliverAllPolicy,
		AckPolicy:         nats.AckExplicitPolicy,
		AckWait:           config.AckWait,
		MaxDeliver:        -1,
		FilterSubject:     filterSubject,
		ReplayPolicy:      nats.ReplayInstantPolicy,
		MaxAckPending:     config.MaxAckPending,
		MaxWaiting:        config.MaxWaiting,
		MaxRequestBatch:   1,
		MaxRequestExpires: config.FetchTimeout,
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	_, _ = js.AddConsumer(config.Stream, consumerConfig, nats.Context(operationCtx))
	cancel()
	operationCtx, cancel = context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := js.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("read durable heartbeat consumer: %w", err)
	}
	if !sameHeartbeatConsumer(info, config.Stream, consumerConfig) {
		return nil, fmt.Errorf("bind durable heartbeat consumer: server returned incompatible configuration")
	}
	subscription, err := js.PullSubscribe(filterSubject, config.Durable, nats.Bind(config.Stream, config.Durable))
	if err != nil {
		return nil, fmt.Errorf("subscribe to durable heartbeats: %w", err)
	}
	return &NATSConsumer{subscription: subscription, config: config}, nil
}

func (c *NATSConsumer) Next(ctx context.Context) (Delivery, error) {
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
		return nil, fmt.Errorf("fetch durable heartbeat: %w", err)
	}
	if len(messages) != 1 {
		return nil, fmt.Errorf("durable heartbeat fetch returned %d messages", len(messages))
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

func (d *natsDelivery) Ack(ctx context.Context) error {
	if err := d.message.AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("ack heartbeat: %w", err)
	}
	return nil
}

func (d *natsDelivery) Nak(ctx context.Context, delay time.Duration) error {
	if err := d.message.NakWithDelay(delay, nats.Context(ctx)); err != nil {
		return fmt.Errorf("nak heartbeat: %w", err)
	}
	return nil
}

func (d *natsDelivery) Term(ctx context.Context) error {
	if err := d.message.Term(nats.Context(ctx)); err != nil {
		return fmt.Errorf("terminate heartbeat: %w", err)
	}
	return nil
}

func sameHeartbeatConsumer(info *nats.ConsumerInfo, stream string, expected *nats.ConsumerConfig) bool {
	if info == nil || expected == nil || info.Stream != stream || info.Name != expected.Durable {
		return false
	}
	actual := info.Config
	return actual.Durable == expected.Durable &&
		(actual.Name == expected.Name || expected.Name == "" && actual.Name == expected.Durable) &&
		actual.DeliverPolicy == expected.DeliverPolicy && actual.OptStartSeq == expected.OptStartSeq &&
		sameOptionalTime(actual.OptStartTime, expected.OptStartTime) && actual.AckPolicy == expected.AckPolicy &&
		actual.AckWait == expected.AckWait && actual.MaxDeliver == expected.MaxDeliver &&
		slices.Equal(actual.BackOff, expected.BackOff) && sameFilterSubjects(actual, *expected) &&
		actual.ReplayPolicy == expected.ReplayPolicy &&
		actual.RateLimit == expected.RateLimit && actual.SampleFrequency == expected.SampleFrequency &&
		actual.MaxWaiting == expected.MaxWaiting && actual.MaxAckPending == expected.MaxAckPending &&
		actual.FlowControl == expected.FlowControl && actual.Heartbeat == expected.Heartbeat &&
		actual.HeadersOnly == expected.HeadersOnly && actual.MaxRequestBatch == expected.MaxRequestBatch &&
		actual.MaxRequestExpires == expected.MaxRequestExpires &&
		actual.MaxRequestMaxBytes == expected.MaxRequestMaxBytes &&
		actual.DeliverSubject == expected.DeliverSubject && actual.DeliverGroup == expected.DeliverGroup &&
		actual.InactiveThreshold == expected.InactiveThreshold && actual.Replicas == expected.Replicas &&
		actual.MemoryStorage == expected.MemoryStorage
}

func sameOptionalTime(actual, expected *time.Time) bool {
	actualZero := actual == nil || actual.IsZero()
	expectedZero := expected == nil || expected.IsZero()
	if actualZero || expectedZero {
		return actualZero && expectedZero
	}
	return actual.Equal(*expected)
}

func sameFilterSubjects(actual, expected nats.ConsumerConfig) bool {
	actualSubjects, actualValid := normalizedFilterSubjects(actual)
	expectedSubjects, expectedValid := normalizedFilterSubjects(expected)
	return actualValid && expectedValid && slices.Equal(actualSubjects, expectedSubjects)
}

func normalizedFilterSubjects(config nats.ConsumerConfig) ([]string, bool) {
	if config.FilterSubject != "" {
		if len(config.FilterSubjects) != 0 {
			return nil, false
		}
		return []string{config.FilterSubject}, true
	}
	subjects := slices.Clone(config.FilterSubjects)
	slices.Sort(subjects)
	return subjects, true
}

func validNATSName(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
