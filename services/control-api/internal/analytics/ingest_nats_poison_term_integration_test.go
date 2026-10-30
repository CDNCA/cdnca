package analytics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type unavailableIsolationSink struct {
	calls int
	err   error
}

func (sink *unavailableIsolationSink) Record(context.Context, IsolationRecord) error {
	sink.calls++
	return sink.err
}

type poisonProofDelivery struct {
	message        *nats.Msg
	attempts       uint64
	streamSequence uint64
}

func (delivery *poisonProofDelivery) Subject() string { return delivery.message.Subject }
func (delivery *poisonProofDelivery) Data() []byte    { return delivery.message.Data }
func (delivery *poisonProofDelivery) MessageID() string {
	return delivery.message.Header.Get(nats.MsgIdHdr)
}
func (delivery *poisonProofDelivery) Attempts() uint64       { return delivery.attempts }
func (delivery *poisonProofDelivery) StreamSequence() uint64 { return delivery.streamSequence }

func (delivery *poisonProofDelivery) Ack(ctx context.Context) error {
	if err := proofSettlementContext(ctx); err != nil {
		return err
	}
	return delivery.message.Ack()
}

func (delivery *poisonProofDelivery) Nak(ctx context.Context, delay time.Duration) error {
	if err := proofSettlementContext(ctx); err != nil {
		return err
	}
	return delivery.message.NakWithDelay(delay)
}

func (delivery *poisonProofDelivery) Term(ctx context.Context) error {
	if err := proofSettlementContext(ctx); err != nil {
		return err
	}
	return delivery.message.Term()
}

func proofSettlementContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidConfiguration
	}
	return ctx.Err()
}

func TestJetStreamPoisonIsolationFailureNeverAdvancesAckFloor(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)
	suffix := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano())
	stream := "ANALYTICS_POISON_TERM_PROOF_" + suffix
	durable := "analytics_poison_term_proof_" + suffix
	// The extra subject token keeps this proof outside the production ingest wildcard.
	subject := IngestSubjectPrefix + ".invalid." + suffix
	streamInfo, err := jetstream.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{subject}, Retention: nats.WorkQueuePolicy,
		MaxConsumers: 1, MaxMsgs: -1, MaxBytes: -1, MaxAge: 0,
		Discard: nats.DiscardNew, Storage: nats.MemoryStorage, Replicas: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupJetStreamLimitProof(t, jetstream, stream, durable)
	consumerInfo, err := jetstream.AddConsumer(stream, &nats.ConsumerConfig{
		Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: time.Minute, MaxDeliver: -1, FilterSubject: subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NATS=%s stream=%s consumer=%s subject=%s retention=%s discard=%s max_age=%s max_msgs=%d max_bytes=%d deliver_policy=%v ack_policy=%s broker_max_deliver=%d application_max_deliver=3",
		connection.ConnectedServerVersion(), stream, durable, consumerInfo.Config.FilterSubject,
		streamInfo.Config.Retention, streamInfo.Config.Discard, streamInfo.Config.MaxAge,
		streamInfo.Config.MaxMsgs, streamInfo.Config.MaxBytes, consumerInfo.Config.DeliverPolicy,
		consumerInfo.Config.AckPolicy, consumerInfo.Config.MaxDeliver)

	subscription, err := jetstream.PullSubscribe(subject, durable, nats.Bind(stream, durable))
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Unsubscribe()
	message := nats.NewMsg(subject)
	message.Header.Set(nats.MsgIdHdr, "poison-term-proof-"+suffix)
	message.Data = []byte(`{"invalid":`)
	publishAck, err := jetstream.PublishMsg(message, nats.ExpectStream(stream))
	if err != nil {
		t.Fatal(err)
	}

	var delivery *poisonProofDelivery
	for wantAttempt := uint64(1); wantAttempt <= 3; wantAttempt++ {
		messages, fetchErr := subscription.Fetch(1, nats.MaxWait(2*time.Second))
		if fetchErr != nil || len(messages) != 1 {
			t.Fatalf("fetch poison attempt %d: count=%d error=%v", wantAttempt, len(messages), fetchErr)
		}
		metadata, metadataErr := messages[0].Metadata()
		if metadataErr != nil || metadata.Sequence.Stream != publishAck.Sequence || metadata.NumDelivered != wantAttempt {
			t.Fatalf("poison metadata at attempt %d: metadata=%#v error=%v", wantAttempt, metadata, metadataErr)
		}
		if wantAttempt < 3 {
			if err := messages[0].NakWithDelay(10 * time.Millisecond); err != nil {
				t.Fatalf("NAK poison attempt %d: %v", wantAttempt, err)
			}
			continue
		}
		delivery = &poisonProofDelivery{
			message: messages[0], attempts: metadata.NumDelivered, streamSequence: metadata.Sequence.Stream,
		}
	}
	before := waitForJetStreamLimitSnapshot(t, jetstream, stream, durable, 5*time.Second, func(snapshot jetStreamLimitSnapshot) bool {
		return snapshot.numAckPending == 1 && snapshot.numPending == 0 && snapshot.ackFloor < publishAck.Sequence &&
			snapshot.streamMsgs == 1 && snapshot.firstSequence == publishAck.Sequence && snapshot.lastSequence == publishAck.Sequence
	})
	t.Logf("published sequence=%d broker_attempts=%d; before failed isolation: NumAckPending=%d NumPending=%d AckFloor.Stream=%d stream_msgs=%d stream_bytes=%d stream_first_seq=%d stream_last_seq=%d",
		publishAck.Sequence, delivery.attempts, before.numAckPending, before.numPending, before.ackFloor,
		before.streamMsgs, before.streamBytes, before.firstSequence, before.lastSequence)

	sinkFailure := errors.New("task-owned isolation sink unavailable")
	sink := &unavailableIsolationSink{err: sinkFailure}
	writer := &fakeIngestWriter{}
	processor := mustProcessor(t, time.Now().UTC(), writer, sink, IngestProcessorConfig{
		MaxDeliver: 3, NakBaseDelay: 10 * time.Millisecond, NakMaxDelay: 20 * time.Millisecond,
	})
	result, processErr := processor.Process(context.Background(), []IngestDelivery{delivery})
	if !errors.Is(processErr, sinkFailure) || sink.calls != 1 || result.Naked != 1 || result.Terminated != 0 ||
		writer.accessCalls != 0 || writer.securityCalls != 0 {
		t.Fatalf("process error=%v isolation_calls=%d result=%#v writer=%#v", processErr, sink.calls, result, writer)
	}
	messages, fetchErr := subscription.Fetch(1, nats.MaxWait(2*time.Second))
	if fetchErr != nil || len(messages) != 1 {
		t.Fatalf("fetch poison beyond max delivery: count=%d error=%v", len(messages), fetchErr)
	}
	metadata, metadataErr := messages[0].Metadata()
	if metadataErr != nil || metadata.Sequence.Stream != publishAck.Sequence || metadata.NumDelivered <= 3 {
		t.Fatalf("poison metadata beyond max delivery: metadata=%#v error=%v", metadata, metadataErr)
	}
	beyondMax := &poisonProofDelivery{
		message: messages[0], attempts: metadata.NumDelivered, streamSequence: metadata.Sequence.Stream,
	}
	beyondResult, beyondErr := processor.Process(context.Background(), []IngestDelivery{beyondMax})
	if !errors.Is(beyondErr, sinkFailure) || sink.calls != 2 || beyondResult.Naked != 1 || beyondResult.Terminated != 0 ||
		writer.accessCalls != 0 || writer.securityCalls != 0 {
		t.Fatalf("beyond-max process error=%v isolation_calls=%d result=%#v writer=%#v",
			beyondErr, sink.calls, beyondResult, writer)
	}
	after := waitForJetStreamLimitSnapshot(t, jetstream, stream, durable, 5*time.Second, func(snapshot jetStreamLimitSnapshot) bool {
		return snapshot.ackFloor < publishAck.Sequence && snapshot.streamMsgs == 1 &&
			snapshot.firstSequence == publishAck.Sequence && snapshot.lastSequence == publishAck.Sequence
	})
	if _, err := jetstream.GetMsg(stream, publishAck.Sequence); err != nil {
		t.Fatalf("NAK-preserved poison sequence %d lookup error=%v", publishAck.Sequence, err)
	}
	t.Logf("after failed isolation + NAK beyond max delivery: NumAckPending=%d NumPending=%d AckFloor.Stream=%d stream_msgs=%d stream_bytes=%d stream_first_seq=%d stream_last_seq=%d",
		after.numAckPending, after.numPending, after.ackFloor, after.streamMsgs, after.streamBytes, after.firstSequence, after.lastSequence)
}
