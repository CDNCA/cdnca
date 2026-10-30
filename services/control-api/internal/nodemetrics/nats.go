package nodemetrics

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

type NATSConsumerConfig struct {
	Stream           string
	Durable          string
	SubjectPrefix    string
	AckWait          time.Duration
	FetchTimeout     time.Duration
	OperationTimeout time.Duration
	NakDelay         time.Duration
	MaxAckPending    int
	MaxWaiting       int
}

func DefaultNATSConsumerConfig() NATSConsumerConfig {
	return NATSConsumerConfig{Stream: NodeMonitoringStatusStream, Durable: DefaultConsumerDurable,
		SubjectPrefix: DefaultSubjectPrefix, AckWait: 2 * time.Minute, FetchTimeout: 5 * time.Second,
		OperationTimeout: 5 * time.Second, NakDelay: time.Second, MaxAckPending: 256, MaxWaiting: 32}
}

type NATSConsumer struct {
	subscription *nats.Subscription
	config       NATSConsumerConfig
}

func NewNATSConsumer(connection *nats.Conn, config NATSConsumerConfig) (*NATSConsumer, error) {
	if connection == nil || connection.IsClosed() || !config.valid() {
		return nil, ErrInvalidConfiguration
	}
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, err
	}
	expected := expectedConsumer(config)
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	_, _ = jetstream.AddConsumer(config.Stream, expected, nats.Context(operationCtx))
	cancel()
	operationCtx, cancel = context.WithTimeout(context.Background(), config.OperationTimeout)
	info, err := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if err != nil || !sameConsumer(info, config) {
		return nil, ErrInvalidConfiguration
	}
	subscription, err := jetstream.PullSubscribe(config.SubjectPrefix+".*", config.Durable,
		nats.Bind(config.Stream, config.Durable))
	if err != nil {
		return nil, fmt.Errorf("bind node metrics consumer: %w", err)
	}
	return &NATSConsumer{subscription: subscription, config: config}, nil
}

func (consumer *NATSConsumer) Next(ctx context.Context) (Delivery, error) {
	if consumer == nil || consumer.subscription == nil || ctx == nil {
		return nil, ErrInvalidConfiguration
	}
	fetchCtx, cancel := context.WithTimeout(ctx, consumer.config.FetchTimeout)
	messages, err := consumer.subscription.Fetch(1, nats.Context(fetchCtx))
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, nats.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrNoMessage
		}
		return nil, err
	}
	if len(messages) != 1 {
		return nil, ErrInvalidDelivery
	}
	metadata, err := messages[0].Metadata()
	if err != nil || metadata == nil || metadata.Stream != consumer.config.Stream ||
		metadata.Consumer != consumer.config.Durable || metadata.Sequence.Stream == 0 ||
		metadata.Sequence.Consumer == 0 || metadata.NumDelivered == 0 {
		return nil, ErrInvalidDelivery
	}
	return &natsDelivery{message: messages[0], metadata: DeliveryMetadata{Stream: metadata.Stream,
		Durable: metadata.Consumer, StreamSequence: metadata.Sequence.Stream,
		ConsumerSequence: metadata.Sequence.Consumer, NumDelivered: metadata.NumDelivered}}, nil
}

func (consumer *NATSConsumer) Close() error {
	if consumer == nil || consumer.subscription == nil {
		return nil
	}
	return consumer.subscription.Unsubscribe()
}

type natsDelivery struct {
	message  *nats.Msg
	metadata DeliveryMetadata
}

func (delivery *natsDelivery) Subject() string            { return delivery.message.Subject }
func (delivery *natsDelivery) Data() []byte               { return append([]byte(nil), delivery.message.Data...) }
func (delivery *natsDelivery) Metadata() DeliveryMetadata { return delivery.metadata }
func (delivery *natsDelivery) Ack(ctx context.Context) error {
	return delivery.message.AckSync(nats.Context(ctx))
}
func (delivery *natsDelivery) Nak(ctx context.Context, delay time.Duration) error {
	return delivery.message.NakWithDelay(delay, nats.Context(ctx))
}
func (delivery *natsDelivery) Term(ctx context.Context) error {
	return delivery.message.Term(nats.Context(ctx))
}

func (config NATSConsumerConfig) valid() bool {
	return config.Stream == NodeMonitoringStatusStream && config.Durable == DefaultConsumerDurable &&
		config.SubjectPrefix == DefaultSubjectPrefix && config.AckWait > 0 && config.FetchTimeout > 0 &&
		config.OperationTimeout > 0 && config.NakDelay > 0 && config.MaxAckPending > 0 && config.MaxWaiting > 0
}

func expectedConsumer(config NATSConsumerConfig) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{Durable: config.Durable, Name: config.Durable,
		DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait,
		MaxDeliver: -1, FilterSubject: config.SubjectPrefix + ".*", ReplayPolicy: nats.ReplayInstantPolicy,
		MaxAckPending: config.MaxAckPending, MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1,
		MaxRequestExpires: config.FetchTimeout}
}

func sameConsumer(info *nats.ConsumerInfo, config NATSConsumerConfig) bool {
	if info == nil || info.Stream != config.Stream || info.Name != config.Durable {
		return false
	}
	actual := info.Config
	return actual.Durable == config.Durable && actual.Name == config.Durable &&
		actual.DeliverPolicy == nats.DeliverAllPolicy &&
		actual.AckPolicy == nats.AckExplicitPolicy && actual.AckWait == config.AckWait && actual.MaxDeliver == -1 &&
		actual.FilterSubject == config.SubjectPrefix+".*" && len(actual.FilterSubjects) == 0 &&
		actual.ReplayPolicy == nats.ReplayInstantPolicy && actual.MaxAckPending == config.MaxAckPending &&
		actual.MaxWaiting == config.MaxWaiting && actual.MaxRequestBatch == 1 &&
		actual.MaxRequestExpires == config.FetchTimeout && len(actual.BackOff) == 0
}
