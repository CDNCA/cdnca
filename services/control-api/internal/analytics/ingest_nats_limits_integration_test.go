package analytics

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type jetStreamLimitProof struct {
	name                string
	maxAge              time.Duration
	maxMessages         int64
	publishEvictor      bool
	wantStreamMessages  uint64
	wantConsumerPending uint64
}

type jetStreamLimitSnapshot struct {
	numAckPending int
	numPending    uint64
	ackFloor      uint64
	streamMsgs    uint64
	streamBytes   uint64
	firstSequence uint64
	lastSequence  uint64
}

func TestJetStreamLimitEvictionAdvancesAckFloorWithoutApplicationWrite(t *testing.T) {
	connection, jetstream := connectJetStreamBlockerProof(t)

	proofs := []jetStreamLimitProof{
		{name: "max_messages", maxAge: time.Hour, maxMessages: 1, publishEvictor: true, wantStreamMessages: 1, wantConsumerPending: 1},
		{name: "max_age", maxAge: 2 * time.Second, maxMessages: 100, wantStreamMessages: 0},
	}
	for _, proof := range proofs {
		proof := proof
		t.Run(proof.name, func(t *testing.T) {
			runJetStreamLimitProof(t, jetstream, connection.ConnectedServerVersion(), proof)
		})
	}
}

func connectJetStreamBlockerProof(t *testing.T) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()
	if os.Getenv("ANALYTICS_INGEST_LIMIT_INTEGRATION") != "1" {
		t.Skip("set ANALYTICS_INGEST_LIMIT_INTEGRATION=1 to run the JetStream limit eviction proof")
	}
	natsURL := os.Getenv("ANALYTICS_INGEST_NATS_URL")
	if natsURL == "" {
		t.Fatal("ANALYTICS_INGEST_NATS_URL is required")
	}
	requireLoopbackNATSURL(t, natsURL)
	connection, err := nats.Connect(
		natsURL,
		nats.UserInfo(os.Getenv("ANALYTICS_INGEST_NATS_USER"), os.Getenv("ANALYTICS_INGEST_NATS_PASSWORD")),
		nats.Name("cdnca-analytics-limit-ack-floor-proof"),
		nats.Timeout(5*time.Second),
		nats.NoReconnect(),
	)
	if err != nil {
		t.Fatalf("connect proof NATS: %v", err)
	}
	t.Cleanup(connection.Close)
	if !serverVersionAtLeast(connection.ConnectedServerVersion(), 2, 11) {
		t.Fatalf("NATS server %q is older than 2.11", connection.ConnectedServerVersion())
	}
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal("create proof JetStream context")
	}
	return connection, jetstream
}

func runJetStreamLimitProof(t *testing.T, jetstream nats.JetStreamContext, serverVersion string, proof jetStreamLimitProof) {
	t.Helper()
	suffix := fmt.Sprintf("%s_%d_%d", proof.name, os.Getpid(), time.Now().UnixNano())
	stream := "ANALYTICS_LIMIT_ACK_PROOF_" + suffix
	durable := "analytics_limit_ack_proof_" + suffix
	subject := "cdnca.analytics.limit-ack-proof." + suffix
	streamInfo, err := jetstream.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{subject}, Retention: nats.WorkQueuePolicy,
		MaxConsumers: 1, MaxMsgs: proof.maxMessages, MaxBytes: 1 << 20, MaxAge: proof.maxAge,
		Discard: nats.DiscardOld, Storage: nats.MemoryStorage, Replicas: 1,
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
	t.Logf("NATS=%s stream=%s consumer=%s subject=%s retention=%s discard=%s max_age=%s max_msgs=%d max_bytes=%d storage=%s replicas=%d deliver_policy=%v ack_policy=%s ack_wait=%s max_deliver=%d",
		serverVersion, stream, durable, consumerInfo.Config.FilterSubject, streamInfo.Config.Retention, streamInfo.Config.Discard,
		streamInfo.Config.MaxAge, streamInfo.Config.MaxMsgs, streamInfo.Config.MaxBytes,
		streamInfo.Config.Storage, streamInfo.Config.Replicas, consumerInfo.Config.DeliverPolicy, consumerInfo.Config.AckPolicy,
		consumerInfo.Config.AckWait, consumerInfo.Config.MaxDeliver)

	subscription, err := jetstream.PullSubscribe(subject, durable, nats.Bind(stream, durable))
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Unsubscribe()
	firstAck, err := jetstream.Publish(subject, []byte("first-pending-without-application-write"), nats.ExpectStream(stream))
	if err != nil {
		t.Fatal(err)
	}
	messages, err := subscription.Fetch(1, nats.MaxWait(time.Second))
	if err != nil || len(messages) != 1 {
		t.Fatalf("fetch first pending message: count=%d error=%v", len(messages), err)
	}
	metadata, err := messages[0].Metadata()
	if err != nil || metadata.Sequence.Stream != firstAck.Sequence {
		t.Fatalf("first delivery metadata=%#v error=%v", metadata, err)
	}
	before := waitForJetStreamLimitSnapshot(t, jetstream, stream, durable, 5*time.Second, func(snapshot jetStreamLimitSnapshot) bool {
		return snapshot.numAckPending == 1 && snapshot.numPending == 0 && snapshot.ackFloor < firstAck.Sequence &&
			snapshot.streamMsgs == 1 && snapshot.firstSequence == firstAck.Sequence && snapshot.lastSequence == firstAck.Sequence
	})
	t.Logf("published first_sequence=%d; before eviction: NumAckPending=%d NumPending=%d AckFloor.Stream=%d stream_msgs=%d stream_bytes=%d stream_first_seq=%d stream_last_seq=%d",
		firstAck.Sequence, before.numAckPending, before.numPending, before.ackFloor, before.streamMsgs, before.streamBytes, before.firstSequence, before.lastSequence)

	var evictorSequence uint64
	if proof.publishEvictor {
		evictorAck, publishErr := jetstream.Publish(subject, []byte("second-forces-capacity-eviction"), nats.ExpectStream(stream))
		if publishErr != nil {
			t.Fatal(publishErr)
		}
		evictorSequence = evictorAck.Sequence
	}
	after := waitForJetStreamLimitSnapshot(t, jetstream, stream, durable, 15*time.Second, func(snapshot jetStreamLimitSnapshot) bool {
		return snapshot.numAckPending == 0 && snapshot.numPending == proof.wantConsumerPending &&
			snapshot.ackFloor >= firstAck.Sequence && snapshot.streamMsgs == proof.wantStreamMessages
	})
	if _, err := jetstream.GetMsg(stream, firstAck.Sequence); !errors.Is(err, nats.ErrMsgNotFound) {
		t.Fatalf("limit-evicted pending sequence %d lookup error=%v, want ErrMsgNotFound", firstAck.Sequence, err)
	}
	t.Logf("published evictor_sequence=%d; after eviction: NumAckPending=%d NumPending=%d AckFloor.Stream=%d stream_msgs=%d stream_bytes=%d stream_first_seq=%d stream_last_seq=%d",
		evictorSequence, after.numAckPending, after.numPending, after.ackFloor, after.streamMsgs, after.streamBytes, after.firstSequence, after.lastSequence)
	t.Logf("blocker evidence only: stream_sequence=%d disappeared and AckFloor advanced without a ClickHouse write and without application Ack/NAK/Term", firstAck.Sequence)
}

func waitForJetStreamLimitSnapshot(t *testing.T, jetstream nats.JetStreamContext, stream, durable string, timeout time.Duration, ready func(jetStreamLimitSnapshot) bool) jetStreamLimitSnapshot {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var last jetStreamLimitSnapshot
	var lastErr error
	for {
		consumerInfo, consumerErr := jetstream.ConsumerInfo(stream, durable)
		streamInfo, streamErr := jetstream.StreamInfo(stream)
		if consumerErr == nil && streamErr == nil {
			last = jetStreamLimitSnapshot{
				numAckPending: consumerInfo.NumAckPending,
				numPending:    consumerInfo.NumPending,
				ackFloor:      consumerInfo.AckFloor.Stream,
				streamMsgs:    streamInfo.State.Msgs,
				streamBytes:   streamInfo.State.Bytes,
				firstSequence: streamInfo.State.FirstSeq,
				lastSequence:  streamInfo.State.LastSeq,
			}
			if ready(last) {
				return last
			}
		} else {
			lastErr = errors.Join(consumerErr, streamErr)
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for JetStream state: last=%+v error=%v", last, lastErr)
		}
	}
}

func cleanupJetStreamLimitProof(t *testing.T, jetstream nats.JetStreamContext, stream, durable string) {
	t.Helper()
	if err := jetstream.DeleteConsumer(stream, durable); err != nil && !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Errorf("delete task-owned consumer %s: %v", durable, err)
	}
	if _, err := jetstream.ConsumerInfo(stream, durable); !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Errorf("task-owned consumer %s remains after cleanup: %v", durable, err)
	}
	if err := jetstream.DeleteStream(stream); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
		t.Errorf("delete task-owned stream %s: %v", stream, err)
	}
	if _, err := jetstream.StreamInfo(stream); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Errorf("task-owned stream %s remains after cleanup: %v", stream, err)
		return
	}
	t.Logf("cleanup verified: task-owned stream=%s and consumer=%s are absent", stream, durable)
}

func requireLoopbackNATSURL(t *testing.T, rawURL string) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse ANALYTICS_INGEST_NATS_URL: %v", err)
	}
	host := net.ParseIP(parsed.Hostname())
	if host == nil || !host.IsLoopback() {
		t.Fatalf("ANALYTICS_INGEST_NATS_URL must use an explicit loopback IP, got host %q", parsed.Hostname())
	}
}

func serverVersionAtLeast(version string, wantMajor, wantMinor int) bool {
	version = strings.TrimPrefix(version, "v")
	var major, minor int
	if _, err := fmt.Sscanf(version, "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major > wantMajor || (major == wantMajor && minor >= wantMinor)
}
