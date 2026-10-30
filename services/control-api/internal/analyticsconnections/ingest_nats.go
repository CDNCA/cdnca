package analyticsconnections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

type Subscriber interface {
	Next(context.Context) (Delivery, error)
	PublishDeadLetter(context.Context, Delivery, Receipt) error
	Close() error
}

type connectionsJetStream interface {
	ConsumerInfo(string, string, ...nats.JSOpt) (*nats.ConsumerInfo, error)
	PublishMsg(*nats.Msg, ...nats.PubOpt) (*nats.PubAck, error)
}

type natsSubscriber struct {
	subscription     *nats.Subscription
	jetstream        connectionsJetStream
	stream           string
	durable          string
	maxDeliver       uint64
	fetchTimeout     time.Duration
	operationTimeout time.Duration
}

const (
	connectionsBatchHeader         = "Cdnca-Connections-Batch-Id"
	connectionsReceiptHeader       = "Cdnca-Connections-Receipt-Id"
	connectionsSchemaHeader        = "Cdnca-Connections-Schema-Version"
	connectionsNodeHeader          = "Cdnca-Connections-Node-Id"
	connectionsDomainHeader        = "Cdnca-Connections-Domain"
	connectionsListenPortHeader    = "Cdnca-Connections-Listen-Port"
	connectionsPayloadDigestHeader = "Cdnca-Connections-Payload-SHA256"
	connectionsDeadLetterStream    = "CONNECTIONS_DEAD_V1"
	connectionsDeadLetterSubject   = "cdnca.connections.dead.v1"
)

var ErrBrokerUnavailable = errors.New("connections broker unavailable")

func NewNATSSubscriber(connection *nats.Conn, config RuntimeConfig) (Subscriber, error) {
	if connection == nil || connection.IsClosed() {
		return nil, ErrInvalidConfiguration
	}
	js, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, ErrClickHouseUnavailable
	}
	subscription, err := js.PullSubscribe(config.Subject, config.Durable, nats.Bind(config.Stream, config.Durable), nats.ManualAck())
	if err != nil {
		return nil, fmt.Errorf("subscribe connections telemetry")
	}
	operationCtx, cancel := context.WithTimeout(context.Background(), config.OperationTimeout)
	consumerInfo, err := js.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	maxDeliver, validationErr := boundConsumerMaxDeliver(consumerInfo, config.Durable, config.Subject)
	if err != nil || validationErr != nil {
		_ = subscription.Unsubscribe()
		return nil, fmt.Errorf("read bound connections consumer")
	}
	return &natsSubscriber{
		subscription: subscription, jetstream: js, stream: config.Stream, durable: config.Durable,
		maxDeliver: maxDeliver, fetchTimeout: config.OperationTimeout, operationTimeout: config.OperationTimeout,
	}, nil
}

func boundConsumerMaxDeliver(info *nats.ConsumerInfo, durable, subject string) (uint64, error) {
	if info == nil || !validID(durable) || info.Config.Durable != durable || info.Config.AckPolicy != nats.AckExplicitPolicy ||
		info.Config.FilterSubject != subject || info.Config.MaxDeliver <= 0 {
		return 0, ErrInvalidConfiguration
	}
	return uint64(info.Config.MaxDeliver), nil
}

func (subscriber *natsSubscriber) Next(ctx context.Context) (Delivery, error) {
	if subscriber == nil || subscriber.subscription == nil || ctx == nil {
		return Delivery{}, ErrInvalidConfiguration
	}
	if err := ctx.Err(); err != nil {
		return Delivery{}, err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, subscriber.fetchTimeout)
	messages, err := subscriber.subscription.Fetch(1, nats.Context(fetchCtx))
	cancel()
	if err != nil {
		return Delivery{}, normalizeBrokerFetchError(ctx, err)
	}
	if len(messages) == 0 {
		return Delivery{}, ErrBrokerUnavailable
	}
	if len(messages) != 1 || messages[0] == nil {
		return Delivery{}, ErrInvalidDelivery
	}
	return deliveryFromNATSMessage(messages[0], subscriber.stream, subscriber.durable, subscriber.maxDeliver)
}

func normalizeBrokerFetchError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrDisconnected) || errors.Is(err, nats.ErrConnectionClosed) || errors.Is(err, nats.ErrNoResponders) {
		return ErrBrokerUnavailable
	}
	return err
}

func deliveryFromNATSMessage(message *nats.Msg, stream, durable string, configuredMaxDeliver ...uint64) (Delivery, error) {
	if message == nil || !validID(stream) || !validID(durable) {
		return Delivery{}, ErrInvalidDelivery
	}
	metadata, err := message.Metadata()
	if err != nil || metadata == nil || metadata.Stream != stream || metadata.Consumer != durable ||
		metadata.Sequence.Stream == 0 || metadata.Sequence.Consumer == 0 || metadata.NumDelivered == 0 {
		return Delivery{}, ErrInvalidDelivery
	}
	maxDeliver := metadata.NumDelivered
	if len(configuredMaxDeliver) > 1 || len(configuredMaxDeliver) == 1 && configuredMaxDeliver[0] < metadata.NumDelivered {
		return Delivery{}, ErrInvalidDelivery
	}
	if len(configuredMaxDeliver) == 1 {
		maxDeliver = configuredMaxDeliver[0]
	}
	payload := append([]byte(nil), message.Data...)
	delivery := Delivery{
		BatchID: message.Header.Get(connectionsBatchHeader), ReceiptID: message.Header.Get(connectionsReceiptHeader), Payload: payload,
		Stream: stream, Durable: durable, StreamSequence: metadata.Sequence.Stream,
		ConsumerSequence: metadata.Sequence.Consumer, MetadataVersion: DeliveryMetadataVersion,
		Attempt: metadata.NumDelivered, MaxDeliver: maxDeliver,
		PubAck: PubAck{Stream: metadata.Stream, Sequence: metadata.Sequence.Stream},
		Ack:    func(ackContext context.Context) error { return message.Ack(nats.Context(ackContext)) },
		Nak: func(nakContext context.Context, delay time.Duration) error {
			return message.NakWithDelay(delay, nats.Context(nakContext))
		},
		Term: func(termContext context.Context) error { return message.Term(nats.Context(termContext)) },
	}
	var envelope agentv1.ConnectionsMetricEnvelopeV1
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, &envelope); err != nil {
		return delivery, ErrInvalidDelivery
	}
	canonical, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&envelope)
	if err != nil || !bytes.Equal(canonical, payload) {
		return delivery, ErrInvalidDelivery
	}
	payloadDigest := sha256.Sum256(payload)
	receiptID := delivery.ReceiptID
	batchID := delivery.BatchID
	expectedSubject := ConnectionsSubjectPrefix + "." + envelope.GetInstallationId() + "." + receiptID
	expectedMessageID := receiptID + ":" + hex.EncodeToString(payloadDigest[:])
	if !validID(receiptID) || !validID(batchID) || message.Subject != expectedSubject ||
		message.Header.Get(nats.MsgIdHdr) != expectedMessageID ||
		message.Header.Get(connectionsSchemaHeader) != strconv.FormatUint(uint64(envelope.GetSchemaVersion()), 10) ||
		message.Header.Get(connectionsPayloadDigestHeader) != hex.EncodeToString(payloadDigest[:]) {
		return delivery, ErrInvalidDelivery
	}
	delivery.NodeID = envelope.GetNodeId()
	delivery.Domain = envelope.GetDomain()
	delivery.ListenPort = uint16(envelope.GetListenPort())
	delivery.Envelope = &envelope
	if ValidateDeliveryMetadata(delivery) != nil {
		return Delivery{}, ErrInvalidDelivery
	}
	return delivery, nil
}

func (subscriber *natsSubscriber) PublishDeadLetter(ctx context.Context, delivery Delivery, receipt Receipt) error {
	if subscriber == nil || subscriber.jetstream == nil || ctx == nil || subscriber.operationTimeout <= 0 ||
		ValidateDeliveryMetadata(delivery) != nil || delivery.FailureReason == DeliveryFailureNone {
		return ErrInvalidConfiguration
	}
	payload, err := deadLetterMessage(delivery, receipt)
	if err != nil {
		return err
	}
	identity := DeadLetterIdentityDigest(delivery.Stream, delivery.StreamSequence, delivery.FailureReason)
	message := nats.NewMsg(connectionsDeadLetterSubject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, hex.EncodeToString(identity[:]))
	operationCtx, cancel := context.WithTimeout(ctx, subscriber.operationTimeout)
	defer cancel()
	acknowledgement, err := subscriber.jetstream.PublishMsg(
		message, nats.Context(operationCtx), nats.ExpectStream(connectionsDeadLetterStream),
	)
	if err != nil {
		return fmt.Errorf("publish connections dead letter: %w", err)
	}
	if acknowledgement == nil || acknowledgement.Stream != connectionsDeadLetterStream || acknowledgement.Sequence == 0 {
		return ErrClickHouseOutcomeUnknown
	}
	return nil
}

func deadLetterMessage(delivery Delivery, receipt Receipt) ([]byte, error) {
	envelope, err := NewDeadLetterEnvelope(delivery, receipt)
	if err == nil {
		payload, marshalErr := json.Marshal(envelope)
		if marshalErr != nil || len(payload) > 8<<10 {
			return nil, ErrInvalidDelivery
		}
		return payload, nil
	}
	if delivery.FailureReason != DeliveryFailureInvalid || !errors.Is(err, ErrInvalidDelivery) {
		return nil, ErrInvalidDelivery
	}
	digest := sha256.Sum256(delivery.Payload)
	poison := struct {
		MetadataVersion  uint32                `json:"metadata_version"`
		Stream           string                `json:"stream"`
		Durable          string                `json:"durable"`
		StreamSequence   uint64                `json:"stream_sequence"`
		ConsumerSequence uint64                `json:"consumer_sequence"`
		Attempt          uint64                `json:"attempt"`
		MaxDeliver       uint64                `json:"max_deliver"`
		FailureReason    DeliveryFailureReason `json:"failure_reason"`
		PayloadBytes     int                   `json:"payload_bytes"`
		PayloadSHA256    string                `json:"payload_sha256"`
	}{
		DeliveryMetadataVersion, delivery.Stream, delivery.Durable, delivery.StreamSequence,
		delivery.ConsumerSequence, delivery.Attempt, delivery.MaxDeliver, delivery.FailureReason,
		len(delivery.Payload), hex.EncodeToString(digest[:]),
	}
	return json.Marshal(poison)
}

func (subscriber *natsSubscriber) Close() error {
	if subscriber == nil || subscriber.subscription == nil {
		return nil
	}
	return subscriber.subscription.Unsubscribe()
}
