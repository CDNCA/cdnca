package eventspool

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

// L4-USAGE-01：进行中的四层会话检查点是 spool 的 l4_checkpoint.v1 记录，
// 走四层会话通道（同一 subject、同一信封、TelemetryKind 不变），信封只装
// checkpoints；结束事件带已检查点字节。检查点不参与采样。
func testCheckpoint(sequence uint32, at time.Time, up, down uint64) Envelope {
	return Envelope{
		SchemaVersion: SchemaVersion, Type: EventL4Checkpoint, EventID: "l4ckpt_" + string(rune('a'+sequence)),
		OccurredAt: at, TenantID: tenantOne, SiteID: siteOne, NodeID: nodeOne,
		ConfigVersionID: "55555555-5555-4555-8555-555555555555", StreamID: "66666666-6666-4666-8666-666666666666",
		ListenerID: "66666666-6666-4666-8666-666666666666", ConfigRevision: 9, SessionID: "17", Protocol: "tcp",
		ListenPort: 18080, StartedAt: at.Add(-time.Duration(sequence) * time.Minute), CheckpointSequence: sequence,
		RequestBytes: up, ResponseBytes: down,
	}
}

func TestL4CheckpointRecordsPublishOnTheL4Channel(t *testing.T) {
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return at.Add(time.Minute) }
	spool := newTestSpool(t, config)
	first, second := testCheckpoint(1, at, 100, 2000), testCheckpoint(2, at.Add(time.Minute), 50, 700)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{first, second}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil || len(records) != 2 {
		t.Fatalf("records = %d, %v", len(records), err)
	}
	publications, err := buildPublications(records)
	if err != nil || len(publications) != 1 {
		t.Fatalf("publications = %d, %v", len(publications), err)
	}
	publication := publications[0]
	if publication.Subject != l4SubjectPrefix+"."+nodeOne || !ValidL4Publication(publication) || publication.EventCount != 2 {
		t.Fatalf("publication = %+v valid=%t", publication, ValidL4Publication(publication))
	}
	var envelope agentv1.L4SessionEnvelopeV1
	if err := proto.Unmarshal(publication.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.GetEvents()) != 0 || len(envelope.GetCheckpoints()) != 2 {
		t.Fatalf("envelope events=%d checkpoints=%d", len(envelope.GetEvents()), len(envelope.GetCheckpoints()))
	}
	got := envelope.GetCheckpoints()[1]
	if got.GetSequence() != 2 || got.GetBytesUp() != 50 || got.GetBytesDown() != 700 || got.GetSessionId() != "17" ||
		!got.GetCheckpointAt().AsTime().Equal(at.Add(time.Minute)) || got.GetEvent().GetEventId() != second.EventID ||
		got.GetProtocol() != "tcp" || got.GetListenPort() != 18080 {
		t.Fatalf("checkpoint = %v", got)
	}
}

func TestL4CheckpointValidation(t *testing.T) {
	at := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	valid := testCheckpoint(1, at, 1, 0)
	if err := validateEnvelope(valid, identityPending); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Envelope){
		"sequence 0":   func(e *Envelope) { e.CheckpointSequence = 0 },
		"no bytes":     func(e *Envelope) { e.RequestBytes, e.ResponseBytes = 0, 0 },
		"udp":          func(e *Envelope) { e.Protocol = "udp" },
		"finalized":    func(e *Envelope) { e.FinalizedAt = at },
		"after start":  func(e *Envelope) { e.StartedAt = at.Add(time.Second) },
		"status":       func(e *Envelope) { e.StatusCode = 200 },
		"checkpointed": func(e *Envelope) { e.CheckpointedRequestBytes = 1 },
		"session log":  func(e *Envelope) { e.L4Log = &L4SessionLog{ClientIP: "192.0.2.1", EndReason: "closed"} },
	} {
		candidate := valid
		mutate(&candidate)
		if validateEnvelope(candidate, identityPending) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// 只有四层结束事件能带已检查点字节；其它类型带检查点序号拒绝。
	session := testCheckpoint(1, at, 1, 0)
	session.Type, session.CheckpointSequence, session.FinalizedAt, session.StatusCode = EventL4Session, 0, at, 200
	session.EvidenceSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	session.CheckpointedRequestBytes, session.CheckpointedResponseBytes = 5, 6
	if err := validateEnvelope(session, identityPending); err != nil {
		t.Fatalf("session with checkpointed bytes rejected: %v", err)
	}
	session.CheckpointSequence = 1
	if validateEnvelope(session, identityPending) == nil {
		t.Fatal("session with a checkpoint sequence accepted")
	}
}

// 结束事件带已检查点字节进 L4SessionEventV1；nginx 行里的 $pid 只在内存里
// 用来对上活会话登记（worker pid:$connection），不进存储也不进摘要。
func TestL4SessionCarriesCheckpointedBytesAndWorker(t *testing.T) {
	identity := TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne,
		ConfigVersionID: "55555555-5555-4555-8555-555555555555", StreamID: "66666666-6666-4666-8666-666666666666",
		ListenerID: "66666666-6666-4666-8666-666666666666", ConfigRevision: 9,
	}
	line := []byte(`{"time":"2026-08-08T12:00:05Z","connection":"17","pid":"4242","protocol":"TCP","server_port":"18080","status":"200","bytes_sent":10,"bytes_received":5,"session_time":1}`)
	envelope, err := ParseL4SourceLineBound(line, identity)
	if err != nil || envelope.L4WorkerConnection() != "4242:17" {
		t.Fatalf("envelope = %+v (%q), %v", envelope, envelope.L4WorkerConnection(), err)
	}
	withoutPID, err := ParseL4SourceLineBound([]byte(`{"time":"2026-08-08T12:00:05Z","connection":"17","protocol":"TCP","server_port":"18080","status":"200","bytes_sent":10,"bytes_received":5,"session_time":1}`), identity)
	if err != nil || withoutPID.L4WorkerConnection() != "" {
		t.Fatalf("line without pid = %q, %v", withoutPID.L4WorkerConnection(), err)
	}
	withoutPID.EvidenceSHA256 = envelope.EvidenceSHA256 // 原文不同，证据哈希本就不同
	if contentDigest(envelope) != contentDigest(withoutPID) {
		t.Fatal("the worker pid changed the stored content")
	}
	if _, err := ParseL4SourceLineBound([]byte(`{"time":"2026-08-08T12:00:05Z","connection":"17","pid":"x","protocol":"TCP","server_port":"18080","status":"200","bytes_sent":10,"bytes_received":5,"session_time":1}`), identity); err == nil {
		t.Fatal("non-numeric pid accepted")
	}
	envelope.EventID = "l4evt_one"
	envelope.CheckpointedRequestBytes, envelope.CheckpointedResponseBytes = 4, 9
	config := testConfig(t.TempDir())
	config.Now = func() time.Time { return time.Date(2026, 8, 8, 12, 1, 0, 0, time.UTC) }
	spool := newTestSpool(t, config)
	if _, err := spool.AppendBatch(context.Background(), []Envelope{envelope}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil || len(publications) != 1 {
		t.Fatalf("publications = %d, %v", len(publications), err)
	}
	var decoded agentv1.L4SessionEnvelopeV1
	if err := proto.Unmarshal(publications[0].Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	event := decoded.GetEvents()[0]
	if event.GetCheckpointedBytesUp() != 4 || event.GetCheckpointedBytesDown() != 9 || len(decoded.GetCheckpoints()) != 0 {
		t.Fatalf("event = %v", event)
	}
}

func TestL4CheckpointsAreNeverSampledOut(t *testing.T) {
	config := Config{AccessSampleEvery: 1 << 20, SecuritySampleEvery: 1 << 20}
	if shouldSampleOut(testCheckpoint(1, time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC), 1, 1), config) {
		t.Fatal("a billed checkpoint was sampled out")
	}
}
