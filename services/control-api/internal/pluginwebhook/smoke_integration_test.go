package pluginwebhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const smokeNATSURLEnv = "CDNCA_PLUGIN_WEBHOOK_SMOKE_NATS_URL"

func TestPluginWebhookNATSTLSSmoke(t *testing.T) {
	natsURL := os.Getenv(smokeNATSURLEnv)
	if natsURL == "" {
		t.Skip(smokeNATSURLEnv + " is required")
	}
	connection, err := nats.Connect(natsURL, nats.Name("cdnca-plugin-webhook-smoke"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	suffix := strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", ""))[:12]
	config := DefaultJetStreamConfig()
	config.DeliveryStream = "PWH_DELIVERY_" + strings.ToUpper(suffix)
	config.DeliveryDurable = "pwh_delivery_" + suffix
	config.DeliverySubjectPrefix = "test.pwh." + suffix + ".delivery"
	config.DeadLetterStream = "PWH_DEAD_" + strings.ToUpper(suffix)
	config.DeadLetterSubject = "test.pwh." + suffix + ".dead"
	config.AckWait = 500 * time.Millisecond
	config.FetchTimeout = 40 * time.Millisecond
	config.OperationTimeout = 100 * time.Millisecond
	config.ConsumerMaxDeliver = 8
	config.MaxAckPending = 1
	config.MaxWaiting = 4
	config.StreamMaxAge = time.Hour
	config.StreamMaxBytes = 4 << 20
	config.StreamMaxMessages = 100
	config.DeadLetterMaxAge = time.Hour
	config.DeadLetterMaxBytes = 4 << 20
	config.DuplicateWindow = time.Minute
	if err := EnsureJetStream(context.Background(), connection, config); err != nil {
		t.Fatal(err)
	}
	defer cleanupSmokeStreams(t, jetstream, config)

	secret := []byte("0123456789abcdef0123456789abcdef")
	state := &smokeWebhookState{counts: make(map[string]int)}
	serverAddress, roots, closeServer := startWebhookTLSServer(t, state.handler(t, secret))
	defer closeServer()
	port := serverPort(t, serverAddress)
	httpConfig := DefaultHTTPSenderConfig()
	httpConfig.RootCAs = roots
	httpConfig.RequestTimeout = 50 * time.Millisecond
	httpConfig.ConnectTimeout = 20 * time.Millisecond
	httpConfig.TLSHandshakeTimeout = 20 * time.Millisecond
	httpConfig.ResponseHeaderTimeout = 40 * time.Millisecond
	httpConfig.MaxResponseBytes = 1024
	httpConfig.MaxPreviewBytes = 256
	sender, err := newHTTPSender(
		httpConfig, staticSecrets{secret: secret},
		staticResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		redirectDialer(serverAddress),
	)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	deadLetters, err := NewDeadLetterStore(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	logger := &smokeAttemptLogger{}
	workerConfig := WorkerConfig{
		MaxAttempts: 3, OperationTimeout: 100 * time.Millisecond,
		Retry: RetryPolicy{BaseDelay: 10 * time.Millisecond, MaxDelay: 60 * time.Millisecond, RetryAfterMax: 60 * time.Millisecond},
		Now:   func() time.Time { return time.Now().UTC() }, RandomInt63n: func(max int64) int64 { return max - 1 },
	}
	worker, err := NewWorker(connection, config, sender, workerConfig, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = worker.Close() }()

	targetBase := "https://hooks.example.com"
	first := publishSmoke(t, publisher, targetBase+"/events", "smoke-success", "success")
	duplicate := publishSmoke(t, publisher, targetBase+"/events", "smoke-success", "success")
	if first.DeliveryID != duplicate.DeliveryID || !duplicate.Duplicate {
		t.Fatalf("duplicate publish = %#v / %#v", first, duplicate)
	}
	processUntil(t, worker, OutcomeDelivered, 2*time.Second)
	if state.count("smoke-success") != 1 {
		t.Fatalf("duplicate reached webhook %d times", state.count("smoke-success"))
	}

	started := time.Now()
	publishSmoke(t, publisher, targetBase+"/events", "smoke-429", "retry-429")
	processUntil(t, worker, OutcomeDelivered, 2*time.Second)
	if state.count("smoke-429") != 2 || time.Since(started) < 50*time.Millisecond {
		t.Fatalf("429 attempts=%d elapsed=%s", state.count("smoke-429"), time.Since(started))
	}
	publishSmoke(t, publisher, targetBase+"/events", "smoke-5xx", "retry-5xx")
	processUntil(t, worker, OutcomeDelivered, 2*time.Second)
	if state.count("smoke-5xx") != 2 {
		t.Fatalf("5xx attempts = %d", state.count("smoke-5xx"))
	}

	beforeDead := streamLastSequence(t, jetstream, config.DeadLetterStream)
	publishSmoke(t, publisher, targetBase+"/events", "smoke-401", "unauthorized")
	processUntil(t, worker, OutcomeDeadLettered, 2*time.Second)
	deadSequence := waitForNewSequence(t, jetstream, config.DeadLetterStream, beforeDead)
	record, err := deadLetters.Read(context.Background(), deadSequence, testTenantID, testInstallationID)
	if err != nil {
		t.Fatal(err)
	}
	encodedRecord, _ := json.Marshal(record)
	if record.ReasonCode != "remote_401" || record.Attempts != 1 ||
		bytes.Contains(encodedRecord, secret) || bytes.Contains(encodedRecord, []byte("response-secret")) {
		t.Fatalf("401 dead letter = %s", encodedRecord)
	}
	if _, err := deadLetters.Read(context.Background(), deadSequence, uuid.New(), testInstallationID); !errors.Is(err, ErrTenantScopeDenied) {
		t.Fatalf("cross-tenant dead-letter read error = %v", err)
	}
	state.setAllowUnauthorized(true)
	replayRequest := ReplayRequest{
		DeadLetterSequence: deadSequence, TenantID: testTenantID, InstallationID: testInstallationID,
		ReplayRequestID: "replay-401",
	}
	replay, err := deadLetters.Replay(context.Background(), replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayDuplicate, err := deadLetters.Replay(context.Background(), replayRequest)
	if err != nil {
		t.Fatal(err)
	}
	if replay.DeliveryID == first.DeliveryID || replay.DeliveryID == record.Item.DeliveryID || !replayDuplicate.Duplicate {
		t.Fatalf("replay = %#v / %#v", replay, replayDuplicate)
	}
	processUntil(t, worker, OutcomeDelivered, 2*time.Second)

	beforeDead = streamLastSequence(t, jetstream, config.DeadLetterStream)
	publishSmoke(t, publisher, targetBase+"/events", "smoke-timeout", "timeout")
	processUntil(t, worker, OutcomeDeadLettered, 3*time.Second)
	timeoutRecord, err := deadLetters.Read(
		context.Background(), waitForNewSequence(t, jetstream, config.DeadLetterStream, beforeDead),
		testTenantID, testInstallationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if timeoutRecord.ReasonCode != "timeout" || timeoutRecord.Attempts != workerConfig.MaxAttempts {
		t.Fatalf("timeout dead letter = %#v", timeoutRecord)
	}

	publishSmoke(t, publisher, targetBase+"/events", "smoke-restart", "success")
	unacked, err := worker.consumer.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(config.AckWait + 50*time.Millisecond)
	worker, err = NewWorker(connection, config, sender, workerConfig, logger)
	if err != nil {
		t.Fatal(err)
	}
	_ = unacked
	result := processUntil(t, worker, OutcomeDelivered, 2*time.Second)
	if result.Attempt < 2 || state.count("smoke-restart") != 1 {
		t.Fatalf("restart result=%#v server attempts=%d", result, state.count("smoke-restart"))
	}

	assertTamperedSignatureRejected(t, sender, secret, targetBase+"/events")
	beforeRequests := state.total()
	ssrfItem := testQueueItem(t, "smoke-ssrf", targetBase+"/metadata")
	ssrfItem.TargetURL = "https://127.0.0.1:" + port + "/metadata"
	ssrfResult := sender.Deliver(context.Background(), ssrfItem, 1)
	if ssrfResult.Code != "invalid_delivery" || state.total() != beforeRequests {
		t.Fatalf("SSRF result=%#v requests=%d/%d", ssrfResult, state.total(), beforeRequests)
	}
	logger.assertRedacted(t)
}

type smokeWebhookState struct {
	mu                sync.Mutex
	counts            map[string]int
	allowUnauthorized bool
}

func (state *smokeWebhookState) handler(t *testing.T, secret []byte) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		headers := SignatureHeaders{
			Timestamp: request.Header.Get(HeaderTimestamp), DeliveryID: request.Header.Get(HeaderDeliveryID),
			ContentSHA256: request.Header.Get(HeaderContentSHA256), Signature: request.Header.Get(HeaderSignature),
		}
		if Verify(secret, time.Now(), time.Minute, headers, body) != nil {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		var event CloudEvent
		var data struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(body, &event) != nil || json.Unmarshal(event.Data, &data) != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		state.mu.Lock()
		state.counts[event.ID]++
		attempt := state.counts[event.ID]
		allowUnauthorized := state.allowUnauthorized
		state.mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Set-Cookie", "session=response-secret")
		switch data.Mode {
		case "retry-429":
			if attempt == 1 {
				writer.Header().Set("Retry-After", "1")
				writer.WriteHeader(http.StatusTooManyRequests)
				_, _ = writer.Write([]byte(`{"token":"response-secret"}`))
				return
			}
		case "retry-5xx":
			if attempt == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		case "unauthorized":
			if !allowUnauthorized {
				writer.WriteHeader(http.StatusUnauthorized)
				_, _ = writer.Write([]byte(`{"password":"response-secret"}`))
				return
			}
		case "timeout":
			time.Sleep(100 * time.Millisecond)
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func (state *smokeWebhookState) count(eventID string) int {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.counts[eventID]
}

func (state *smokeWebhookState) total() int {
	state.mu.Lock()
	defer state.mu.Unlock()
	total := 0
	for _, count := range state.counts {
		total += count
	}
	return total
}

func (state *smokeWebhookState) setAllowUnauthorized(allowed bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.allowUnauthorized = allowed
}

type smokeAttemptLogger struct {
	mu      sync.Mutex
	records []AttemptRecord
}

func (logger *smokeAttemptLogger) Record(_ context.Context, record AttemptRecord) error {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	logger.records = append(logger.records, record)
	return nil
}

func (logger *smokeAttemptLogger) assertRedacted(t *testing.T) {
	t.Helper()
	logger.mu.Lock()
	defer logger.mu.Unlock()
	encoded, err := json.Marshal(logger.records)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("response-secret")) || bytes.Contains(encoded, []byte("Set-Cookie\":\"session=")) {
		t.Fatalf("attempt log leaked secret: %s", encoded)
	}
	if len(logger.records) < 10 {
		t.Fatalf("attempt log count = %d", len(logger.records))
	}
}

func publishSmoke(t *testing.T, publisher *Publisher, targetURL, eventID, mode string) PublishResult {
	t.Helper()
	result, err := publisher.Publish(context.Background(), PublishRequest{
		TenantID: testTenantID, InstallationID: testInstallationID, EventID: eventID,
		EventType: "io.cdnca.site.v1.updated", TargetURL: targetURL,
		OccurredAt: time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC),
		Data:       json.RawMessage(`{"mode":` + strconv.Quote(mode) + `}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func processUntil(t *testing.T, worker *Worker, outcome ProcessOutcome, timeout time.Duration) ProcessResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for ctx.Err() == nil {
		result, err := worker.ProcessOne(ctx)
		if errors.Is(err, ErrNoDelivery) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if result.Outcome == outcome {
			return result
		}
		if result.Outcome != OutcomeRetryScheduled {
			t.Fatalf("outcome = %s, want %s", result.Outcome, outcome)
		}
	}
	t.Fatalf("timed out waiting for %s", outcome)
	return ProcessResult{}
}

func streamLastSequence(t *testing.T, jetstream nats.JetStreamContext, stream string) uint64 {
	t.Helper()
	info, err := jetstream.StreamInfo(stream)
	if err != nil {
		t.Fatal(err)
	}
	return info.State.LastSeq
}

func waitForNewSequence(t *testing.T, jetstream nats.JetStreamContext, stream string, previous uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sequence := streamLastSequence(t, jetstream, stream)
		if sequence > previous {
			return sequence
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dead-letter sequence did not advance")
	return 0
}

func assertTamperedSignatureRejected(t *testing.T, sender *HTTPSender, secret []byte, targetURL string) {
	t.Helper()
	item := testQueueItem(t, "smoke-tamper", targetURL)
	body, err := json.Marshal(item.Event)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := Sign(secret, time.Now(), item.DeliveryID, body)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte(nil), body...), byte(' '))
	target, err := resolveTarget(context.Background(), targetURL, sender.resolver)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(tampered))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(HeaderDeliveryID, headers.DeliveryID)
	request.Header.Set(HeaderTimestamp, headers.Timestamp)
	request.Header.Set(HeaderContentSHA256, headers.ContentSHA256)
	request.Header.Set(HeaderSignature, headers.Signature)
	client := &http.Client{Transport: sender.transport(target), Timeout: time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tampered signature status = %d", response.StatusCode)
	}
}

func cleanupSmokeStreams(t *testing.T, jetstream nats.JetStreamContext, config JetStreamConfig) {
	t.Helper()
	for _, stream := range []string{config.DeliveryStream, config.DeadLetterStream} {
		if err := jetstream.DeleteStream(stream); err != nil && !errors.Is(err, nats.ErrStreamNotFound) {
			t.Errorf("delete stream %s: %v", stream, err)
			continue
		}
		if _, err := jetstream.StreamInfo(stream); !errors.Is(err, nats.ErrStreamNotFound) {
			t.Errorf("stream %s still exists: %v", stream, err)
		}
	}
}
