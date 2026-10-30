package analytics

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeIngestDelivery struct {
	subject        string
	payload        []byte
	messageID      string
	installationID string
	attempts       uint64
	streamSequence uint64
	ackCount       int
	nakCount       int
	termCount      int
	nakDelay       time.Duration
	ackErr         error
	nakErr         error
	termErr        error
	ackDeadline    time.Time
	nakDeadline    time.Time
	termDeadline   time.Time
	settlementWait time.Duration
	terminalState  *fakeTerminalEvidenceState
	confirmErr     error
	checkErr       error
}

type fakeTerminalEvidenceState struct {
	mu           sync.Mutex
	bySequence   map[uint64]string
	confirmCalls int
}

func (delivery *fakeIngestDelivery) Subject() string   { return delivery.subject }
func (delivery *fakeIngestDelivery) Data() []byte      { return delivery.payload }
func (delivery *fakeIngestDelivery) MessageID() string { return delivery.messageID }
func (delivery *fakeIngestDelivery) InstallationID() string {
	if delivery.installationID == "" {
		return "test-installation"
	}
	return delivery.installationID
}
func (delivery *fakeIngestDelivery) Attempts() uint64       { return delivery.attempts }
func (delivery *fakeIngestDelivery) StreamSequence() uint64 { return delivery.streamSequence }
func (delivery *fakeIngestDelivery) Ack(ctx context.Context) error {
	delivery.ackCount++
	delivery.ackDeadline, _ = ctx.Deadline()
	time.Sleep(delivery.settlementWait)
	return delivery.ackErr
}
func (delivery *fakeIngestDelivery) Nak(ctx context.Context, delay time.Duration) error {
	delivery.nakCount++
	delivery.nakDelay = delay
	delivery.nakDeadline, _ = ctx.Deadline()
	time.Sleep(delivery.settlementWait)
	return delivery.nakErr
}
func (delivery *fakeIngestDelivery) Term(ctx context.Context) error {
	delivery.termCount++
	delivery.termDeadline, _ = ctx.Deadline()
	time.Sleep(delivery.settlementWait)
	return delivery.termErr
}

func (delivery *fakeIngestDelivery) TerminalEvidenceConfirmed(_ context.Context) (bool, error) {
	if delivery.checkErr != nil {
		return false, delivery.checkErr
	}
	if delivery.terminalState == nil {
		return false, nil
	}
	delivery.terminalState.mu.Lock()
	defer delivery.terminalState.mu.Unlock()
	_, ok := delivery.terminalState.bySequence[delivery.streamSequence]
	return ok, nil
}

func (delivery *fakeIngestDelivery) ConfirmTerminalEvidence(_ context.Context, record IsolationRecord) error {
	if delivery.confirmErr != nil {
		return delivery.confirmErr
	}
	if delivery.terminalState == nil {
		delivery.terminalState = &fakeTerminalEvidenceState{}
	}
	delivery.terminalState.mu.Lock()
	defer delivery.terminalState.mu.Unlock()
	if delivery.terminalState.bySequence == nil {
		delivery.terminalState.bySequence = make(map[uint64]string)
	}
	want := isolationMessageID(record)
	if confirmed, ok := delivery.terminalState.bySequence[record.StreamSequence]; ok && confirmed != want {
		return ErrInvalidInput
	}
	delivery.terminalState.bySequence[record.StreamSequence] = want
	delivery.terminalState.confirmCalls++
	return nil
}

type fakeIngestWriter struct {
	mu             sync.Mutex
	accessCalls    int
	securityCalls  int
	accessTokens   []string
	securityTokens []string
	accessEvents   [][]AccessEvent
	securityEvents [][]SecurityEvent
	accessErrors   []error
	securityErrors []error
	beforeWrite    func()
}

func (writer *fakeIngestWriter) WriteAccessEvents(_ context.Context, token string, events []AccessEvent) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.beforeWrite != nil {
		writer.beforeWrite()
	}
	writer.accessCalls++
	writer.accessTokens = append(writer.accessTokens, token)
	writer.accessEvents = append(writer.accessEvents, append([]AccessEvent(nil), events...))
	if len(writer.accessErrors) >= writer.accessCalls {
		return writer.accessErrors[writer.accessCalls-1]
	}
	return nil
}

func (writer *fakeIngestWriter) WriteSecurityEvents(_ context.Context, token string, events []SecurityEvent) error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.beforeWrite != nil {
		writer.beforeWrite()
	}
	writer.securityCalls++
	writer.securityTokens = append(writer.securityTokens, token)
	writer.securityEvents = append(writer.securityEvents, append([]SecurityEvent(nil), events...))
	if len(writer.securityErrors) >= writer.securityCalls {
		return writer.securityErrors[writer.securityCalls-1]
	}
	return nil
}

type blockingIngestWriter struct{}

func (blockingIngestWriter) WriteAccessEvents(ctx context.Context, _ string, _ []AccessEvent) error {
	<-ctx.Done()
	return ctx.Err()
}
func (blockingIngestWriter) WriteSecurityEvents(ctx context.Context, _ string, _ []SecurityEvent) error {
	<-ctx.Done()
	return ctx.Err()
}

type memoryIsolationSink struct {
	mu      sync.Mutex
	records []IsolationRecord
	err     error
}

func (sink *memoryIsolationSink) Record(_ context.Context, record IsolationRecord) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.records = append(sink.records, record)
	return sink.err
}

func TestIngestProcessorMergesKindsAndAcknowledgesAfterWrites(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	accessOne := newFakeDelivery(t, "access-one", now, []AccessEvent{eventAt(validAccessEvent("a-1"), now.Add(-time.Minute))})
	accessTwo := newFakeDelivery(t, "access-two", now, []AccessEvent{eventAt(validAccessEvent("a-2"), now.Add(-2*time.Minute))})
	security := newFakeSecurityDelivery(t, "security-one", now, []SecurityEvent{securityEventAt(validSecurityEvent("s-1"), now.Add(-time.Minute))})
	accessOne.streamSequence, accessTwo.streamSequence, security.streamSequence = 1, 2, 3
	writer := &fakeIngestWriter{}
	writer.beforeWrite = func() {
		if writer.accessCalls == 0 && accessOne.ackCount != 0 {
			t.Error("first access delivery was acknowledged before its ClickHouse write confirmation")
		}
		if writer.accessCalls == 1 && accessTwo.ackCount != 0 {
			t.Error("second access delivery was acknowledged before its ClickHouse write confirmation")
		}
		if writer.securityCalls == 0 && security.ackCount != 0 {
			t.Error("security delivery was acknowledged before its ClickHouse write confirmation")
		}
	}
	processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{})

	result, err := processor.Process(context.Background(), []IngestDelivery{accessOne, accessTwo, security})
	if err != nil {
		t.Fatal(err)
	}
	if result.Acknowledged != 3 || result.Naked != 0 || result.Terminated != 0 || result.WriteBatches != 3 {
		t.Fatalf("result = %#v", result)
	}
	if writer.accessCalls != 2 || len(writer.accessEvents[0]) != 1 || len(writer.accessEvents[1]) != 1 || writer.securityCalls != 1 ||
		len(writer.securityEvents[0]) != 1 || accessOne.ackCount != 1 || accessTwo.ackCount != 1 || security.ackCount != 1 {
		t.Fatalf("writer=%#v deliveries=%#v %#v %#v", writer, accessOne, accessTwo, security)
	}
}

func TestIngestProcessorDeduplicatesSameMessageAndTokenIsOrderIndependent(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	first := newFakeDelivery(t, "first", now, []AccessEvent{eventAt(validAccessEvent("a-1"), now.Add(-time.Minute))})
	firstDuplicate := *first
	second := newFakeDelivery(t, "second", now, []AccessEvent{eventAt(validAccessEvent("a-2"), now.Add(-time.Minute))})
	second.streamSequence = 2
	writer := &fakeIngestWriter{}
	processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{})
	result, err := processor.Process(context.Background(), []IngestDelivery{first, &firstDuplicate, second})
	if err != nil {
		t.Fatal(err)
	}
	if result.Acknowledged != 3 || writer.accessCalls != 2 || len(writer.accessEvents[0]) != 1 || len(writer.accessEvents[1]) != 1 {
		t.Fatalf("result=%#v writer=%#v", result, writer)
	}

	reverseWriter := &fakeIngestWriter{}
	reverseProcessor := mustProcessor(t, now, reverseWriter, &memoryIsolationSink{}, IngestProcessorConfig{})
	reverseFirst := newFakeDelivery(t, "first", now, []AccessEvent{eventAt(validAccessEvent("a-1"), now.Add(-time.Minute))})
	reverseSecond := newFakeDelivery(t, "second", now, []AccessEvent{eventAt(validAccessEvent("a-2"), now.Add(-time.Minute))})
	reverseFirst.streamSequence, reverseSecond.streamSequence = 1, 2
	if _, err := reverseProcessor.Process(context.Background(), []IngestDelivery{reverseSecond, reverseFirst}); err != nil {
		t.Fatal(err)
	}
	if writer.accessTokens[0] != reverseWriter.accessTokens[1] || writer.accessTokens[1] != reverseWriter.accessTokens[0] {
		t.Fatalf("per-message tokens changed with surrounding deliveries: %v != %v", writer.accessTokens, reverseWriter.accessTokens)
	}
	t.Run("terminal settlement failure naks for replay", func(t *testing.T) {
		termErr := errors.New("terminal settlement unavailable")
		delivery := &fakeIngestDelivery{
			subject: IngestSubjectPrefix + "." + testNodeID, payload: []byte(`{}`), messageID: "poison",
			attempts: 3, termErr: termErr,
		}
		processor := mustProcessor(t, now, &fakeIngestWriter{}, &memoryIsolationSink{}, IngestProcessorConfig{MaxDeliver: 3})
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if !errors.Is(err, termErr) || delivery.termCount != 1 || delivery.nakCount != 1 ||
			result.Terminated != 0 || result.Naked != 1 {
			t.Fatalf("error=%v delivery=%#v result=%#v", err, delivery, result)
		}
	})
}

func TestIngestProcessorWriterFailureDispositionAtApplicationCap(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		writeErr   error
		attempts   uint64
		wantNak    int
		wantTerm   int
		wantReason string
	}{
		{"retryable cap minus one", ErrTransport, 3, 1, 0, ""},
		{"retryable at cap", context.DeadlineExceeded, 4, 0, 1, "WRITER_RETRY_EXHAUSTED"},
		{"retryable beyond cap", ErrTransport, 5, 0, 1, "WRITER_RETRY_EXHAUSTED"},
		{"permanent 400", &HTTPError{StatusCode: http.StatusBadRequest}, 1, 0, 1, "WRITER_PERMANENT"},
		{"retryable 429 below cap", &HTTPError{StatusCode: http.StatusTooManyRequests}, 3, 1, 0, ""},
		// 凭据/权限故障与消息无关，须保留原消息待修复后恢复（docs/runbooks/analytics-storage.md「ACK、重试与 poison 处置」）。
		{"retryable 401 below cap", &HTTPError{StatusCode: http.StatusUnauthorized}, 1, 1, 0, ""},
		{"retryable 403 below cap", &HTTPError{StatusCode: http.StatusForbidden}, 1, 1, 0, ""},
		{"401 at cap", &HTTPError{StatusCode: http.StatusUnauthorized}, 4, 0, 1, "WRITER_RETRY_EXHAUSTED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			delivery := newFakeDelivery(t, "message", now, []AccessEvent{eventAt(validAccessEvent("event"), now.Add(-time.Minute))})
			delivery.attempts = test.attempts
			delivery.terminalState = &fakeTerminalEvidenceState{}
			sink := &memoryIsolationSink{}
			writer := &fakeIngestWriter{accessErrors: []error{test.writeErr}}
			processor := mustProcessor(t, now, writer, sink, IngestProcessorConfig{MaxDeliver: 4})
			result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
			if err != nil {
				t.Fatal(err)
			}
			if delivery.ackCount != 0 || delivery.nakCount != test.wantNak || delivery.termCount != test.wantTerm ||
				result.Naked != test.wantNak || result.Terminated != test.wantTerm {
				t.Fatalf("delivery=%#v result=%#v", delivery, result)
			}
			if test.wantReason == "" && len(sink.records) != 0 {
				t.Fatalf("unexpected isolation records: %#v", sink.records)
			}
			if test.wantReason != "" && (len(sink.records) != 1 || sink.records[0].ReasonCode != test.wantReason ||
				!sink.records[0].WireEvidenceOnly || delivery.terminalState.confirmCalls != 1) {
				t.Fatalf("records=%#v terminal_state=%#v", sink.records, delivery.terminalState)
			}
			if test.wantNak == 1 && (delivery.nakDelay < time.Second || delivery.nakDelay > 5*time.Second) {
				t.Fatalf("nak delay = %s", delivery.nakDelay)
			}
		})
	}
}

func TestIngestProcessorTerminalEvidenceFailureAndCrashRecovery(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	newDelivery := func() *fakeIngestDelivery {
		delivery := newFakeDelivery(t, "terminal-evidence", now,
			[]AccessEvent{eventAt(validAccessEvent("terminal-event"), now.Add(-time.Minute))})
		delivery.attempts = 4
		return delivery
	}

	t.Run("isolation unavailable keeps message durable", func(t *testing.T) {
		delivery := newDelivery()
		sinkErr := errors.New("isolation unavailable")
		processor := mustProcessor(t, now, &fakeIngestWriter{accessErrors: []error{ErrTransport}},
			&memoryIsolationSink{err: sinkErr}, IngestProcessorConfig{MaxDeliver: 4})
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if !errors.Is(err, sinkErr) || delivery.nakCount != 1 || delivery.termCount != 0 ||
			result.Naked != 1 || result.Terminated != 0 {
			t.Fatalf("error=%v delivery=%#v result=%#v", err, delivery, result)
		}
	})

	t.Run("terminal marker uncertainty keeps message durable", func(t *testing.T) {
		delivery := newDelivery()
		delivery.confirmErr = errors.New("terminal marker uncertain")
		sink := &memoryIsolationSink{}
		processor := mustProcessor(t, now, &fakeIngestWriter{accessErrors: []error{ErrTransport}}, sink,
			IngestProcessorConfig{MaxDeliver: 4})
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if !errors.Is(err, delivery.confirmErr) || len(sink.records) != 1 || delivery.nakCount != 1 ||
			delivery.termCount != 0 || result.Naked != 1 || result.Terminated != 0 {
			t.Fatalf("error=%v records=%#v delivery=%#v result=%#v", err, sink.records, delivery, result)
		}
	})

	t.Run("crash after evidence resumes without duplicate evidence", func(t *testing.T) {
		state := &fakeTerminalEvidenceState{}
		sink := &memoryIsolationSink{}
		first := newDelivery()
		first.terminalState = state
		first.termErr = errors.New("crash before terminal settlement")
		firstProcessor := mustProcessor(t, now, &fakeIngestWriter{accessErrors: []error{ErrTransport}}, sink,
			IngestProcessorConfig{MaxDeliver: 4})
		firstResult, firstErr := firstProcessor.Process(context.Background(), []IngestDelivery{first})
		if !errors.Is(firstErr, first.termErr) || first.termCount != 1 || first.nakCount != 1 ||
			firstResult.Naked != 1 || firstResult.Terminated != 0 || len(sink.records) != 1 {
			t.Fatalf("first error=%v records=%#v delivery=%#v result=%#v", firstErr, sink.records, first, firstResult)
		}

		redelivery := newDelivery()
		redelivery.attempts = 5
		redelivery.terminalState = state
		secondWriter := &fakeIngestWriter{accessErrors: []error{ErrTransport}}
		secondProcessor := mustProcessor(t, now, secondWriter, sink,
			IngestProcessorConfig{MaxDeliver: 4})
		secondResult, secondErr := secondProcessor.Process(context.Background(), []IngestDelivery{redelivery})
		if secondErr != nil || redelivery.termCount != 1 || redelivery.nakCount != 0 ||
			secondResult.Terminated != 1 || len(sink.records) != 1 || state.confirmCalls != 1 || secondWriter.accessCalls != 0 {
			t.Fatalf("second error=%v records=%#v delivery=%#v result=%#v state=%#v",
				secondErr, sink.records, redelivery, secondResult, state)
		}
	})
}

func TestIngestProcessorCancellationNaksClaimedMessages(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	delivery := newFakeDelivery(t, "cancelled", now, []AccessEvent{eventAt(validAccessEvent("event"), now.Add(-time.Minute))})
	processor := mustProcessor(t, now, blockingIngestWriter{}, &memoryIsolationSink{}, IngestProcessorConfig{OperationTimeout: 20 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := processor.Process(ctx, []IngestDelivery{delivery})
	if err != nil {
		t.Fatal(err)
	}
	if delivery.ackCount != 0 || delivery.nakCount != 1 || result.Naked != 1 {
		t.Fatalf("delivery=%#v result=%#v", delivery, result)
	}
}

func TestIngestProcessorSharesSettlementDeadlineAcrossBatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	for _, disposition := range []string{"ack", "nak", "term"} {
		t.Run(disposition, func(t *testing.T) {
			deliveries := make([]*fakeIngestDelivery, 3)
			inputs := make([]IngestDelivery, 3)
			writer := &fakeIngestWriter{}
			for index := range deliveries {
				messageID := fmt.Sprintf("settlement-%s-%d", disposition, index)
				if disposition == "term" {
					deliveries[index] = &fakeIngestDelivery{
						subject: IngestSubjectPrefix + "." + testNodeID,
						payload: []byte(`{"broken":`), messageID: messageID, attempts: 1,
					}
				} else {
					event := eventAt(validAccessEvent(fmt.Sprintf("event-%d", index)), now.Add(-time.Minute))
					deliveries[index] = newFakeDelivery(t, messageID, now, []AccessEvent{event})
				}
				deliveries[index].streamSequence = uint64(index + 1)
				deliveries[index].settlementWait = time.Millisecond
				inputs[index] = deliveries[index]
			}
			if disposition == "nak" {
				writer.accessErrors = []error{ErrTransport, ErrTransport, ErrTransport}
			}
			processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{})
			if _, err := processor.Process(context.Background(), inputs); err != nil {
				t.Fatal(err)
			}

			deadlines := make([]time.Time, 0, len(deliveries))
			for _, delivery := range deliveries {
				switch disposition {
				case "ack":
					deadlines = append(deadlines, delivery.ackDeadline)
				case "nak":
					deadlines = append(deadlines, delivery.nakDeadline)
				case "term":
					deadlines = append(deadlines, delivery.termDeadline)
				}
			}
			for index, deadline := range deadlines {
				if deadline.IsZero() || !deadline.Equal(deadlines[0]) {
					t.Fatalf("%s settlement deadline[%d]=%s, want shared deadline %s", disposition, index, deadline, deadlines[0])
				}
			}
		})
	}
}

func TestIngestProcessorPoisonIsolationAndSinkFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	t.Run("poison terms after isolation", func(t *testing.T) {
		delivery := &fakeIngestDelivery{
			subject: IngestSubjectPrefix + "." + testNodeID, payload: []byte(`{"secret":"must-not-log",`),
			messageID: "poison", attempts: 1, streamSequence: 9,
		}
		sink := &memoryIsolationSink{}
		processor := mustProcessor(t, now, &fakeIngestWriter{}, sink, IngestProcessorConfig{})
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if err != nil {
			t.Fatal(err)
		}
		if delivery.termCount != 1 || result.Terminated != 1 || len(sink.records) != 1 ||
			sink.records[0].ReasonCode != RejectInvalidJSON || sink.records[0].PayloadSHA256 == "" {
			t.Fatalf("delivery=%#v result=%#v records=%#v", delivery, result, sink.records)
		}
		encoded, _ := json.Marshal(sink.records[0])
		if bytes.Contains(encoded, []byte("must-not-log")) {
			t.Fatal("isolation record leaked poison payload")
		}
	})
	for _, test := range []struct {
		name      string
		attempts  uint64
		nakErr    error
		wantNaked int
	}{
		{name: "sink failure naks before max delivery", attempts: 1, wantNaked: 1},
		{name: "sink failure naks at max delivery", attempts: 3, wantNaked: 1},
		{name: "sink failure naks after max delivery", attempts: 4, wantNaked: 1},
		{name: "sink and nak failure never terms", attempts: 3, nakErr: errors.New("nak unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			delivery := &fakeIngestDelivery{
				subject: IngestSubjectPrefix + "." + testNodeID, payload: []byte(`{}`), messageID: "poison",
				attempts: test.attempts, nakErr: test.nakErr,
			}
			sinkErr := errors.New("isolation unavailable")
			sink := &memoryIsolationSink{err: sinkErr}
			processor := mustProcessor(t, now, &fakeIngestWriter{}, sink, IngestProcessorConfig{MaxDeliver: 3})
			result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
			if !errors.Is(err, sinkErr) || delivery.nakCount != 1 || delivery.termCount != 0 ||
				result.Naked != test.wantNaked || result.Terminated != 0 {
				t.Fatalf("error=%v delivery=%#v result=%#v", err, delivery, result)
			}
			if test.nakErr != nil && !errors.Is(err, test.nakErr) {
				t.Fatalf("error=%v, want joined NAK error %v", err, test.nakErr)
			}
		})
	}
}

func TestIngestProcessorPartialBatchesOverlapAndOutOfOrder(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	firstEvent := eventAt(validAccessEvent("event-1"), now.Add(-time.Minute))
	secondEvent := eventAt(validAccessEvent("event-2"), now.Add(-10*time.Minute))
	first := newFakeDelivery(t, "first", now, []AccessEvent{firstEvent, secondEvent})
	overlap := newFakeDelivery(t, "overlap", now, []AccessEvent{firstEvent})
	last := newFakeDelivery(t, "last", now, []AccessEvent{eventAt(validAccessEvent("event-3"), now.Add(-5*time.Minute))})
	first.streamSequence, overlap.streamSequence, last.streamSequence = 1, 2, 3
	writer := &fakeIngestWriter{}
	processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{MaxBatchEvents: 2})
	result, err := processor.Process(context.Background(), []IngestDelivery{first, overlap, last})
	if err != nil {
		t.Fatal(err)
	}
	if result.Acknowledged != 3 || writer.accessCalls != 3 || len(writer.accessEvents[0]) != 2 ||
		len(writer.accessEvents[1]) != 1 || len(writer.accessEvents[2]) != 1 {
		t.Fatalf("result=%#v writer=%#v", result, writer)
	}
	if !writer.accessEvents[0][0].OccurredAt.After(writer.accessEvents[0][1].OccurredAt) {
		t.Fatal("out-of-order event times were unexpectedly reordered")
	}
}

func TestIngestProcessorDoesNotLogPayloadOrWriterSecret(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	const secret = "payload-and-credential-secret"
	event := eventAt(validAccessEvent("event"), now.Add(-time.Minute))
	event.Path = "/" + secret
	delivery := newFakeDelivery(t, "message", now, []AccessEvent{event})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	processor := mustProcessor(t, now, &fakeIngestWriter{accessErrors: []error{errors.New(secret)}}, &memoryIsolationSink{}, IngestProcessorConfig{Logger: logger})
	if _, err := processor.Process(context.Background(), []IngestDelivery{delivery}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(logs.Bytes(), []byte(secret)) {
		t.Fatalf("logs leaked payload or writer error: %s", logs.String())
	}
}

func TestBoundedNakDelay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		attempt uint64
		want    time.Duration
	}{{1, time.Second}, {2, 2 * time.Second}, {3, 4 * time.Second}, {4, 5 * time.Second}, {100, 5 * time.Second}}
	for _, test := range tests {
		if got := boundedNakDelay(test.attempt, time.Second, 5*time.Second); got != test.want {
			t.Fatalf("attempt %d delay = %s, want %s", test.attempt, got, test.want)
		}
	}
}

func TestIngestProcessorAuthorityV1OrderReplayAndFailureRecovery(t *testing.T) {
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	generation := authorityGenerationV1()
	newDelivery := func(t *testing.T) *authorityOrderDeliveryV1 {
		t.Helper()
		base := newFakeDelivery(t, "authority-message", now, []AccessEvent{
			eventAt(validAccessEvent("authority-event"), now.Add(-time.Minute)),
		})
		base.installationID = generation.InstallationID
		base.streamSequence = 41
		return &authorityOrderDeliveryV1{fakeIngestDelivery: base}
	}

	t.Run("received clickhouse prepared ack and broker observation are ordered", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		writer := &authorityOrderWriterV1{history: history}
		delivery := newDelivery(t)
		delivery.history = history
		processor := authorityProcessorV1(t, now, writer, history, generation, &memoryIsolationSink{})
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if err != nil {
			t.Fatal(err)
		}
		if got := authorityOperationsV1(history); got != "received,clickhouse,pg-prepared,recovery-scheduled,nats-ack,broker-ack-observed" {
			t.Fatalf("authority operations = %q", got)
		}
		if result.Acknowledged != 1 || delivery.ackCount != 1 || history.brokerAckCount != 1 || len(history.receipts) != 1 {
			t.Fatalf("result=%#v delivery=%#v history=%#v", result, delivery, history)
		}
		if writer.token != history.receipts[0].ClickHouseToken || authorityReceiptDigestV1(history.receipts[0]) == strings.Repeat("0", sha256.Size*2) {
			t.Fatalf("writer token=%q receipt=%#v", writer.token, history.receipts[0])
		}
	})

	t.Run("restart from prepared receipt skips uncertain clickhouse replay", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		firstWriter := &authorityOrderWriterV1{history: history}
		first := newDelivery(t)
		first.history = history
		first.ackErr = errors.New("first ACK outcome unknown")
		firstProcessor := authorityProcessorV1(t, now, firstWriter, history, generation, &memoryIsolationSink{})
		if result, err := firstProcessor.Process(context.Background(), []IngestDelivery{first}); !errors.Is(err, first.ackErr) ||
			result.Acknowledged != 0 || firstWriter.calls != 1 || !history.prepared {
			t.Fatalf("first error=%v writer=%#v result=%#v history=%#v", err, firstWriter, result, history)
		}

		restartedWriter := &authorityOrderWriterV1{history: history}
		redelivery := newDelivery(t)
		redelivery.history = history
		redelivery.attempts = 2
		if !bytes.Equal(first.Data(), redelivery.Data()) {
			t.Fatal("prepared redelivery payload is not byte-identical")
		}
		restartedProcessor := authorityProcessorV1(t, now, restartedWriter, history, generation, &memoryIsolationSink{})
		result, err := restartedProcessor.Process(context.Background(), []IngestDelivery{redelivery})
		if err != nil || restartedWriter.calls != 0 || result.Acknowledged != 1 ||
			authorityOperationsV1(history) != "received,clickhouse,pg-prepared,recovery-scheduled,nats-ack,received,recovery-scheduled,nats-ack,broker-ack-observed" {
			t.Fatalf("error=%v writer=%#v result=%#v operations=%q", err, restartedWriter, result, authorityOperationsV1(history))
		}
	})

	t.Run("different digest conflict fails closed", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		history.receiveErr = ErrIngestReceiptConflict
		writer := &authorityOrderWriterV1{history: history}
		delivery := newDelivery(t)
		delivery.history = history
		sink := &memoryIsolationSink{}
		processor := authorityProcessorV1(t, now, writer, history, generation, sink)
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if err != nil || writer.calls != 0 || delivery.ackCount != 0 || result.Terminated != 1 || len(sink.records) != 1 ||
			sink.records[0].ReasonCode != RejectReceiptConflict {
			t.Fatalf("error=%v writer=%#v delivery=%#v result=%#v records=%#v", err, writer, delivery, result, sink.records)
		}
	})

	t.Run("clickhouse unknown outcome redelivers with byte-identical token and one durable identity", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		firstWriter := &authorityOrderWriterV1{history: history, err: ErrIngestWriteOutcomeUnknown}
		first := newDelivery(t)
		first.history = history
		firstProcessor := authorityProcessorV1(t, now, firstWriter, history, generation, &memoryIsolationSink{})
		firstResult, firstErr := firstProcessor.Process(context.Background(), []IngestDelivery{first})
		if firstErr != nil || firstResult.Naked != 1 || first.nakCount != 1 || first.ackCount != 0 || history.prepared ||
			authorityOperationsV1(history) != "received,clickhouse" {
			t.Fatalf("first error=%v result=%#v delivery=%#v history=%#v", firstErr, firstResult, first, history)
		}

		restartedWriter := &authorityOrderWriterV1{history: history}
		redelivery := newDelivery(t)
		redelivery.history = history
		redelivery.attempts = 2
		if !bytes.Equal(first.Data(), redelivery.Data()) {
			t.Fatal("redelivery payload is not byte-identical")
		}
		restartedProcessor := authorityProcessorV1(t, now, restartedWriter, history, generation, &memoryIsolationSink{})
		restartedResult, restartedErr := restartedProcessor.Process(context.Background(), []IngestDelivery{redelivery})
		if restartedErr != nil || restartedResult.Acknowledged != 1 || redelivery.ackCount != 1 || redelivery.nakCount != 0 ||
			!history.prepared || history.brokerAckCount != 1 || len(history.receipts) != 1 ||
			authorityOperationsV1(history) != "received,clickhouse,received,clickhouse,pg-prepared,recovery-scheduled,nats-ack,broker-ack-observed" {
			t.Fatalf("restart error=%v result=%#v delivery=%#v history=%#v", restartedErr, restartedResult, redelivery, history)
		}
		if firstWriter.token == "" || firstWriter.token != restartedWriter.token || firstWriter.token != history.receipts[0].ClickHouseToken {
			t.Fatalf("ClickHouse tokens first=%q restart=%q receipt=%q", firstWriter.token, restartedWriter.token, history.receipts[0].ClickHouseToken)
		}
	})

	t.Run("shared durable authority recovers ACK failure and reconciles after restart", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		firstWriter := &authorityOrderWriterV1{history: history}
		first := newDelivery(t)
		first.history = history
		first.ackErr = errors.New("NATS ACK outcome unknown")
		firstProcessor := authorityProcessorV1(t, now, firstWriter, history, generation, &memoryIsolationSink{})
		firstResult, firstErr := firstProcessor.Process(context.Background(), []IngestDelivery{first})
		if !errors.Is(firstErr, first.ackErr) || firstResult.Acknowledged != 0 || !history.prepared ||
			history.brokerAckCount != 0 || history.recoveryCount != 1 ||
			authorityOperationsV1(history) != "received,clickhouse,pg-prepared,recovery-scheduled,nats-ack" {
			t.Fatalf("first error=%v result=%#v history=%#v", firstErr, firstResult, history)
		}

		snapshot := IngestBrokerHistorySnapshotV1{Generation: generation, ConsumerAckFloor: 1, StreamAckFloor: 41}
		brokerSnapshotCalls := 0
		runtime := &IngestRuntime{
			history: history, historyGeneration: generation,
			brokerHistorySnapshot: func(context.Context) (IngestBrokerHistorySnapshotV1, error) {
				brokerSnapshotCalls++
				return snapshot, nil
			},
		}
		recovered, recoveryErr := runtime.RunScheduledHistoryRecovery(context.Background())
		if recoveryErr != nil || !recovered || brokerSnapshotCalls != 1 || history.recoveryClaimCount != 1 ||
			history.recoveryCompleteCount != 1 || history.recoveryScheduled ||
			history.progress.PreparedStreamFloor != 41 || history.progress.BrokerStreamAckFloor != 41 ||
			history.progress.CommittedStreamAckFloor != min(history.progress.PreparedStreamFloor, history.progress.BrokerStreamAckFloor) ||
			authorityOperationsV1(history) != "received,clickhouse,pg-prepared,recovery-scheduled,nats-ack,recovery-claimed,broker-reconciled,recovery-completed" {
			t.Fatalf("recovery error=%v recovered=%t history=%#v operations=%q", recoveryErr, recovered, history, authorityOperationsV1(history))
		}
		if recovered, err := runtime.RunScheduledHistoryRecovery(context.Background()); err != nil || recovered || brokerSnapshotCalls != 1 {
			t.Fatalf("completed recovery rerun = (%t, %v), broker snapshots=%d", recovered, err, brokerSnapshotCalls)
		}
	})

	t.Run("forged installation identity never reaches history or clickhouse", func(t *testing.T) {
		history := newRecordingIngestHistoryAuthorityV1(t, generation)
		writer := &authorityOrderWriterV1{history: history}
		delivery := newDelivery(t)
		delivery.history = history
		delivery.installationID = "22222222-2222-4222-8222-222222222222"
		sink := &memoryIsolationSink{}
		processor := authorityProcessorV1(t, now, writer, history, generation, sink)
		result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
		if err != nil || writer.calls != 0 || len(history.receipts) != 0 || delivery.ackCount != 0 ||
			result.Terminated != 1 || len(sink.records) != 1 || sink.records[0].ReasonCode != RejectIdentityMismatch {
			t.Fatalf("error=%v writer=%#v history=%#v delivery=%#v result=%#v records=%#v",
				err, writer, history, delivery, result, sink.records)
		}
	})
}

func TestNewIngestProcessorRejectsMissingHistoryBeforeClickHouseOrNATS(t *testing.T) {
	now := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	generation := authorityGenerationV1()
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	delivery := newFakeDelivery(t, "missing-history", now, []AccessEvent{
		eventAt(validAccessEvent("missing-history-event"), now.Add(-time.Minute)),
	})
	delivery.installationID = generation.InstallationID
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	writer := &authorityOrderWriterV1{history: history}
	base := IngestProcessorConfig{
		OperationTimeout: time.Second, NakBaseDelay: time.Second, NakMaxDelay: 5 * time.Second,
		MaxDeliver: 4, MaxBatchEvents: DefaultMaxEventsPerEnvelope, Now: func() time.Time { return now },
		History: history, HistoryGeneration: generation,
	}
	tests := []struct {
		name   string
		mutate func(*IngestProcessorConfig)
	}{
		{name: "nil history", mutate: func(config *IngestProcessorConfig) { config.History = nil }},
		{name: "missing generation", mutate: func(config *IngestProcessorConfig) { config.HistoryGeneration = IngestHistoryGenerationV1{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			processor, err := NewIngestProcessor(decoder, writer, &memoryIsolationSink{}, config)
			if !errors.Is(err, ErrInvalidConfiguration) || processor != nil || writer.calls != 0 || delivery.ackCount != 0 ||
				len(history.receipts) != 0 || authorityOperationsV1(history) != "" {
				t.Fatalf("processor=%#v error=%v writer=%#v delivery=%#v history=%#v", processor, err, writer, delivery, history)
			}
		})
	}
}

func mustProcessor(
	t *testing.T,
	now time.Time,
	writer IngestWriter,
	sink IsolationSink,
	config IngestProcessorConfig,
) *IngestProcessor {
	t.Helper()
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	if config.OperationTimeout == 0 {
		config.OperationTimeout = time.Second
	}
	if config.NakBaseDelay == 0 {
		config.NakBaseDelay = time.Second
	}
	if config.NakMaxDelay == 0 {
		config.NakMaxDelay = 5 * time.Second
	}
	if config.MaxDeliver == 0 {
		config.MaxDeliver = 4
	}
	if config.MaxBatchEvents == 0 {
		config.MaxBatchEvents = DefaultMaxEventsPerEnvelope
	}
	if config.History == nil {
		generation := processorFixtureGenerationV1()
		config.History = newRecordingIngestHistoryAuthorityV1(t, generation)
		config.HistoryGeneration = generation
	}
	config.Now = func() time.Time { return now }
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	processor, err := NewIngestProcessor(decoder, writer, sink, config)
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func newFakeDelivery(t *testing.T, messageID string, producedAt time.Time, events []AccessEvent) *fakeIngestDelivery {
	t.Helper()
	subject, _ := IngestSubject(testNodeID)
	return &fakeIngestDelivery{
		subject: subject, payload: marshalAccessEnvelope(t, messageID, producedAt, events),
		messageID: messageID, attempts: 1, streamSequence: 1,
	}
}

func newFakeSecurityDelivery(t *testing.T, messageID string, producedAt time.Time, events []SecurityEvent) *fakeIngestDelivery {
	t.Helper()
	subject, _ := IngestSubject(testNodeID)
	return &fakeIngestDelivery{
		subject: subject, payload: marshalSecurityEnvelope(t, messageID, producedAt, events),
		messageID: messageID, attempts: 1, streamSequence: 1,
	}
}

func securityEventAt(event SecurityEvent, occurredAt time.Time) SecurityEvent {
	event.OccurredAt = occurredAt
	return event
}
