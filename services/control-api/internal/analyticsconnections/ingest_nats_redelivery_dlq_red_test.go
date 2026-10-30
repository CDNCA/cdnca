package analyticsconnections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type redeliveryTestJetStream struct {
	consumerInfo *nats.ConsumerInfo
	publishAck   *nats.PubAck
	publishErr   error
	messages     []*nats.Msg
}

func (jetstream *redeliveryTestJetStream) ConsumerInfo(string, string, ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	return jetstream.consumerInfo, nil
}

func (jetstream *redeliveryTestJetStream) PublishMsg(message *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	clone := nats.NewMsg(message.Subject)
	for name, values := range message.Header {
		clone.Header[name] = append([]string(nil), values...)
	}
	clone.Data = append([]byte(nil), message.Data...)
	jetstream.messages = append(jetstream.messages, clone)
	return jetstream.publishAck, jetstream.publishErr
}

func TestNATSDeliveryUsesBrokerAttemptAndBoundConsumerMaxDeliver(t *testing.T) {
	message := validConnectionsNATSMessage(t)
	message.Header.Set("Cdnca-Connections-Attempt", "999")
	message.Header.Set("Cdnca-Connections-Max-Deliver", "999")
	delivery, err := deliveryFromNATSMessage(message, "CONNECTIONS_INGEST_V1", "control_api_connections", 7)
	if err != nil {
		t.Fatalf("delivery: %v", err)
	}
	if delivery.MetadataVersion != DeliveryMetadataVersion || delivery.Attempt != 1 || delivery.MaxDeliver != 7 ||
		delivery.Nak == nil || delivery.Term == nil {
		t.Fatalf("broker delivery authority = %#v", delivery)
	}
}

func TestBoundConsumerMaxDeliverRejectsUnboundedOrDriftedConsumer(t *testing.T) {
	valid := &nats.ConsumerInfo{Config: nats.ConsumerConfig{
		Durable: "control_api_connections", AckPolicy: nats.AckExplicitPolicy,
		FilterSubject: ConnectionsSubject, MaxDeliver: 7,
	}}
	if got, err := boundConsumerMaxDeliver(valid, "control_api_connections", ConnectionsSubject); err != nil || got != 7 {
		t.Fatalf("valid consumer = (%d, %v)", got, err)
	}
	for _, mutate := range []func(*nats.ConsumerInfo){
		func(info *nats.ConsumerInfo) { info.Config.MaxDeliver = -1 },
		func(info *nats.ConsumerInfo) { info.Config.MaxDeliver = 0 },
		func(info *nats.ConsumerInfo) { info.Config.Durable = "other" },
		func(info *nats.ConsumerInfo) { info.Config.FilterSubject = ConnectionsSubjectPrefix + ".>" },
		func(info *nats.ConsumerInfo) { info.Config.AckPolicy = nats.AckNonePolicy },
	} {
		candidate := *valid
		mutate(&candidate)
		if _, err := boundConsumerMaxDeliver(&candidate, "control_api_connections", ConnectionsSubject); err == nil {
			t.Fatalf("invalid consumer accepted: %#v", candidate.Config)
		}
	}
}

func TestNATSDeadLetterValidatesPubAckBeforeSuccessAndUsesStableIdentity(t *testing.T) {
	delivery := runtimeRedeliveryDelivery(t, 4, 4)
	delivery.FailureReason = DeliveryFailureMaxDeliver
	receipt, err := ValidateDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	jetstream := &redeliveryTestJetStream{publishAck: &nats.PubAck{Stream: connectionsDeadLetterStream, Sequence: 19, Duplicate: true}}
	subscriber := &natsSubscriber{jetstream: jetstream, operationTimeout: time.Second}

	if err := subscriber.PublishDeadLetter(context.Background(), delivery, receipt); err != nil {
		t.Fatalf("publish duplicate dead letter: %v", err)
	}
	if len(jetstream.messages) != 1 {
		t.Fatalf("messages = %d", len(jetstream.messages))
	}
	message := jetstream.messages[0]
	identity := DeadLetterIdentityDigest(delivery.Stream, delivery.StreamSequence, delivery.FailureReason)
	wantID := hex.EncodeToString(identity[:])
	if message.Subject != connectionsDeadLetterSubject || message.Header.Get(nats.MsgIdHdr) != wantID {
		t.Fatalf("dead letter identity = subject:%q id:%q", message.Subject, message.Header.Get(nats.MsgIdHdr))
	}
	for _, secret := range []string{"authorization", "cookie", "secret"} {
		if strings.Contains(strings.ToLower(string(message.Data)), secret) {
			t.Fatalf("dead letter leaked %q: %s", secret, message.Data)
		}
	}

	replayed := delivery
	replayed.ConsumerSequence++
	replayedReceipt := receipt
	replayedReceipt.ConsumerSequence++
	if err := subscriber.PublishDeadLetter(context.Background(), replayed, replayedReceipt); err != nil {
		t.Fatalf("publish replay: %v", err)
	}
	if got := jetstream.messages[1].Header.Get(nats.MsgIdHdr); got != wantID {
		t.Fatalf("consumer sequence changed message id: %q != %q", got, wantID)
	}
}

func TestNATSDeadLetterUnknownPubAckFailsClosed(t *testing.T) {
	delivery := runtimeRedeliveryDelivery(t, 4, 4)
	delivery.FailureReason = DeliveryFailureMaxDeliver
	receipt, err := ValidateDelivery(delivery)
	if err != nil {
		t.Fatal(err)
	}
	for _, acknowledgement := range []*nats.PubAck{
		nil,
		{Stream: "OTHER", Sequence: 1},
		{Stream: connectionsDeadLetterStream, Sequence: 0},
	} {
		jetstream := &redeliveryTestJetStream{publishAck: acknowledgement}
		subscriber := &natsSubscriber{jetstream: jetstream, operationTimeout: time.Second}
		if err := subscriber.PublishDeadLetter(context.Background(), delivery, receipt); err == nil {
			t.Fatalf("invalid PubAck accepted: %#v", acknowledgement)
		}
	}
	jetstream := &redeliveryTestJetStream{publishErr: context.DeadlineExceeded}
	subscriber := &natsSubscriber{jetstream: jetstream, operationTimeout: time.Second}
	if err := subscriber.PublishDeadLetter(context.Background(), delivery, receipt); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("publish error = %v", err)
	}
}

func TestInvalidPoisonDeadLetterStoresOnlyBoundedDigestEvidence(t *testing.T) {
	message := validConnectionsNATSMessage(t)
	message.Data = bytes.Repeat([]byte("authorization=Bearer secret;cookie=session-secret;"), 1024)
	delivery, parseErr := deliveryFromNATSMessage(message, "CONNECTIONS_INGEST_V1", "control_api_connections", 4)
	if !errors.Is(parseErr, ErrInvalidDelivery) || ValidateDeliveryMetadata(delivery) != nil {
		t.Fatalf("poison lost broker settlement authority: delivery=%#v error=%v", delivery, parseErr)
	}
	delivery.FailureReason = DeliveryFailureInvalid
	jetstream := &redeliveryTestJetStream{publishAck: &nats.PubAck{Stream: connectionsDeadLetterStream, Sequence: 20}}
	subscriber := &natsSubscriber{jetstream: jetstream, operationTimeout: time.Second}

	if err := subscriber.PublishDeadLetter(context.Background(), delivery, Receipt{}); err != nil {
		t.Fatalf("publish poison evidence: %v", err)
	}
	published := jetstream.messages[0]
	if len(published.Data) > 2048 {
		t.Fatalf("poison evidence bytes = %d", len(published.Data))
	}
	digest := sha256.Sum256(delivery.Payload)
	if !bytes.Contains(published.Data, []byte(hex.EncodeToString(digest[:]))) {
		t.Fatalf("poison evidence omitted payload digest: %s", published.Data)
	}
	for _, secret := range []string{"bearer secret", "session-secret"} {
		if bytes.Contains(bytes.ToLower(published.Data), []byte(secret)) {
			t.Fatalf("poison evidence leaked %q", secret)
		}
	}
}

func TestBrokerFetchErrorsUseStableRetryableClassification(t *testing.T) {
	for _, brokerErr := range []error{nats.ErrTimeout, nats.ErrDisconnected, nats.ErrConnectionClosed, nats.ErrNoResponders} {
		got := normalizeBrokerFetchError(context.Background(), brokerErr)
		if !errors.Is(got, ErrBrokerUnavailable) || errors.Is(got, context.Canceled) || errors.Is(got, context.DeadlineExceeded) {
			t.Fatalf("broker error %v normalized to %v", brokerErr, got)
		}
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := normalizeBrokerFetchError(canceled, nats.ErrTimeout); !errors.Is(got, context.Canceled) {
		t.Fatalf("canceled context normalized to %v", got)
	}
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := normalizeBrokerFetchError(deadline, nats.ErrTimeout); !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("expired context normalized to %v", got)
	}

	invalid := errors.New("invalid subscription contract")
	if got := normalizeBrokerFetchError(context.Background(), invalid); !errors.Is(got, invalid) || errors.Is(got, ErrBrokerUnavailable) {
		t.Fatalf("invalid error normalized to %v", got)
	}
}
