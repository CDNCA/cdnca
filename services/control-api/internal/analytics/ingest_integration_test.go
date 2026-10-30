package analytics

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestNATSClickHouseIngestLifecycle(t *testing.T) {
	if os.Getenv("ANALYTICS_INGEST_INTEGRATION") != "1" {
		t.Skip("set ANALYTICS_INGEST_INTEGRATION=1 to run the NATS and ClickHouse lifecycle test")
	}
	natsURL := os.Getenv("ANALYTICS_INGEST_NATS_URL")
	clickHouseURL := os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_URL")
	database := os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_DATABASE")
	stream := os.Getenv("ANALYTICS_INGEST_STREAM")
	durable := os.Getenv("ANALYTICS_INGEST_DURABLE")
	isolationStream := os.Getenv("ANALYTICS_INGEST_ISOLATION_STREAM")
	if natsURL == "" || clickHouseURL == "" || database == "" || stream == "" || durable == "" || isolationStream == "" {
		t.Fatal("analytics integration environment is incomplete")
	}

	connection, err := nats.Connect(natsURL,
		nats.UserInfo(os.Getenv("ANALYTICS_INGEST_NATS_USER"), os.Getenv("ANALYTICS_INGEST_NATS_PASSWORD")),
		nats.Name("cdnca-analytics-ingest-integration"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal("connect integration NATS")
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal("create integration JetStream context")
	}
	stateBucket, leaseBucket := coordinationBucketNames(JetStreamConfig{Stream: stream, Durable: durable})
	evidenceBucket := isolationEvidenceBucketName(JetStreamConfig{Stream: stream, Durable: durable})
	cleanupNATS := func() {
		_ = jetstream.DeleteConsumer(stream, durable)
		_ = jetstream.DeleteStream(stream)
		_ = jetstream.DeleteStream(isolationStream)
		_ = jetstream.DeleteKeyValue(stateBucket)
		_ = jetstream.DeleteKeyValue(leaseBucket)
		_ = jetstream.DeleteKeyValue(evidenceBucket)
	}

	config := DefaultJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.Stream = stream
	config.Durable = durable
	config.IsolationStream = isolationStream
	config.AckWait = 4 * time.Second
	config.FetchTimeout = 500 * time.Millisecond
	config.OperationTimeout = time.Second
	config.NakBaseDelay = 50 * time.Millisecond
	config.NakMaxDelay = 200 * time.Millisecond
	config.MaxDeliver = 4
	config.MaxAckPending = 4
	config.MaxWaiting = 2
	config.FetchBatch = 4
	config.StreamMaxAge = 0
	config.StreamMaxBytes = 64 << 20
	config.StreamMaxMessages = 1000
	config.IsolationMaxAge = time.Hour
	config.IsolationMaxBytes = 16 << 20
	config.DuplicateWindow = 2 * time.Minute
	config.Replicas = 1
	defer cleanupNATS()
	if _, err := jetstream.CreateKeyValue(&nats.KeyValueConfig{
		Bucket: evidenceBucket, History: 1, TTL: 0,
		MaxValueSize: isolationEvidenceMaxValueSize, MaxBytes: config.IsolationMaxBytes,
		Storage: nats.FileStorage, Replicas: config.Replicas,
	}); err != nil {
		t.Fatal(err)
	}
	setupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = EnsureIngestJetStream(setupCtx, connection, config)
	cancel()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name           string
		mutateStream   func(*nats.StreamConfig)
		mutateConsumer func(*nats.ConsumerConfig)
	}{
		{name: "max messages per subject", mutateStream: func(actual *nats.StreamConfig) {
			actual.MaxMsgsPerSubject = 1
		}},
		{name: "republish", mutateStream: func(actual *nats.StreamConfig) {
			actual.RePublish = &nats.RePublish{
				Source: IngestSubjectPrefix + "." + testNodeID, Destination: "cdnca.analytics.contract-drift." + testNodeID,
			}
		}},
		{name: "headers only", mutateConsumer: func(actual *nats.ConsumerConfig) {
			actual.HeadersOnly = true
		}},
		{name: "filter subjects", mutateConsumer: func(actual *nats.ConsumerConfig) {
			actual.FilterSubject = ""
			actual.FilterSubjects = []string{IngestSubjectPrefix + ".*"}
		}},
	} {
		t.Run("rejects "+test.name+" drift", func(t *testing.T) {
			ctx, driftCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer driftCancel()
			if test.mutateStream != nil {
				defer func() {
					if _, restoreErr := jetstream.UpdateStream(expectedIngestStream(config), nats.Context(ctx)); restoreErr != nil {
						t.Errorf("restore stream contract: %v", restoreErr)
						return
					}
					if ensureErr := EnsureIngestJetStream(ctx, connection, config); ensureErr != nil {
						t.Errorf("revalidate restored stream contract: %v", ensureErr)
					}
				}()
				info, infoErr := jetstream.StreamInfo(config.Stream, nats.Context(ctx))
				if infoErr != nil {
					t.Fatal(infoErr)
				}
				actual := info.Config
				test.mutateStream(&actual)
				if _, updateErr := jetstream.UpdateStream(&actual, nats.Context(ctx)); updateErr != nil {
					t.Fatalf("inject stream drift: %v", updateErr)
				}
			} else {
				defer func() {
					if _, restoreErr := jetstream.UpdateConsumer(config.Stream, expectedConsumer(config), nats.Context(ctx)); restoreErr != nil {
						t.Errorf("restore consumer contract: %v", restoreErr)
						return
					}
					if ensureErr := EnsureIngestJetStream(ctx, connection, config); ensureErr != nil {
						t.Errorf("revalidate restored consumer contract: %v", ensureErr)
					}
				}()
				info, infoErr := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(ctx))
				if infoErr != nil {
					t.Fatal(infoErr)
				}
				actual := info.Config
				test.mutateConsumer(&actual)
				if _, updateErr := jetstream.UpdateConsumer(config.Stream, &actual, nats.Context(ctx)); updateErr != nil {
					t.Fatalf("inject consumer drift: %v", updateErr)
				}
			}
			if ensureErr := EnsureIngestJetStream(ctx, connection, config); ensureErr == nil {
				t.Fatal("EnsureIngestJetStream accepted semantic contract drift")
			}
		})
	}

	target, err := url.Parse(clickHouseURL)
	if err != nil {
		t.Fatal("parse integration ClickHouse URL")
	}
	faultProxy := newCommitThenFailProxy(target)
	server := httptest.NewServer(faultProxy)
	defer server.Close()
	clickhouse, err := NewClient(Config{
		Endpoint: server.URL, Database: database,
		Username:     os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_USER"),
		Password:     os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_PASSWORD"),
		QueryTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	runtime := buildIntegrationRuntime(t, connection, clickhouse, config)
	firstEvent := validAccessEvent("integration-retry-event")
	firstEvent.OccurredAt = now.Add(-time.Minute)
	publishAccessEnvelope(t, jetstream, config.Stream, "integration-retry-message", now, []AccessEvent{firstEvent})

	firstResult, err := runtime.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if firstResult.Naked != 1 || firstResult.Acknowledged != 0 || faultProxy.failures.Load() != 1 {
		t.Fatalf("first uncertain write result = %#v, injected failures=%d", firstResult, faultProxy.failures.Load())
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	runtime = buildIntegrationRuntime(t, connection, clickhouse, config)
	secondResult, err := runtime.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if secondResult.Acknowledged != 1 || secondResult.Naked != 0 {
		t.Fatalf("restart redelivery result = %#v", secondResult)
	}

	poison := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
	poison.Header.Set(nats.MsgIdHdr, "integration-poison")
	setIntegrationAuthority(poison, testConfigVersionID)
	poison.Data = []byte(`{"schema_version":1,"secret":"poison-must-not-leak",`)
	ack, err := jetstream.PublishMsg(poison)
	if err != nil || ack == nil || ack.Stream != config.Stream {
		t.Fatalf("publish poison envelope: ack=%#v err=%v", ack, err)
	}
	poisonResult, err := runtime.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if poisonResult.Terminated != 1 || poisonResult.Acknowledged != 0 {
		t.Fatalf("poison result = %#v", poisonResult)
	}
	isolationInfo, err := jetstream.StreamInfo(config.IsolationStream)
	if err != nil || isolationInfo.State.Msgs != 1 {
		t.Fatalf("isolation stream state error=%v info=%#v", err, isolationInfo)
	}
	isolationMessage, err := jetstream.GetMsg(config.IsolationStream, isolationInfo.State.FirstSeq)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(isolationMessage.Data, []byte("poison-must-not-leak")) {
		t.Fatal("isolation stream leaked poison payload")
	}

	for index := 0; index < 7; index++ {
		event := validAccessEvent("integration-backlog-" + string(rune('a'+index)))
		event.OccurredAt = now.Add(-time.Duration(index+2) * time.Minute)
		publishAccessEnvelope(t, jetstream, config.Stream, "integration-backlog-message-"+string(rune('a'+index)), now, []AccessEvent{event})
	}
	securityEvent := validSecurityEvent("integration-security-event")
	securityEvent.OccurredAt = now.Add(-3 * time.Minute)
	publishSecurityEnvelope(t, jetstream, config.Stream, "integration-security-message", now, []SecurityEvent{securityEvent})

	consumerInfo, err := jetstream.ConsumerInfo(config.Stream, config.Durable)
	if err != nil || consumerInfo.Config.MaxAckPending != 4 || consumerInfo.Config.MaxWaiting != 2 ||
		consumerInfo.Config.MaxDeliver != -1 || config.MaxDeliver < 2 || consumerInfo.NumPending < 8 {
		t.Fatalf("bounded consumer before drain error=%v info=%#v", err, consumerInfo)
	}
	acknowledged := 0
	for acknowledged < 8 {
		result, runErr := runtime.RunOnce(context.Background())
		if runErr != nil {
			t.Fatal(runErr)
		}
		if result.Fetched > config.FetchBatch || result.Fetched > config.MaxAckPending {
			t.Fatalf("fetch escaped backpressure bounds: %#v", result)
		}
		acknowledged += result.Acknowledged
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	filter := Filter{From: now.Truncate(time.Hour).Add(-time.Hour), To: now.Truncate(time.Hour).Add(time.Hour)}
	summary, err := clickhouse.Summary(context.Background(), AdminScope(), filter)
	if err != nil {
		t.Fatal(err)
	}
	if summary.RequestCount != 8 || summary.SecurityEvents != 1 {
		t.Fatalf("ingest reconciliation summary = %#v", summary)
	}
	t.Logf("reconciled request_count=%d security_events=%d injected_failures=%d max_fetch=%d",
		summary.RequestCount, summary.SecurityEvents, faultProxy.failures.Load(), config.FetchBatch)
	consumerInfo, err = jetstream.ConsumerInfo(config.Stream, config.Durable)
	if err != nil || consumerInfo.NumPending != 0 || consumerInfo.NumAckPending != 0 {
		t.Fatalf("consumer backlog after drain error=%v info=%#v", err, consumerInfo)
	}

	cleanupNATS()
	if _, err := jetstream.StreamInfo(config.Stream); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("ingest stream cleanup error = %v", err)
	}
	if _, err := jetstream.StreamInfo(config.IsolationStream); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("isolation stream cleanup error = %v", err)
	}
}

type commitThenFailProxy struct {
	target       *url.URL
	reverseProxy *httputil.ReverseProxy
	failNext     atomic.Bool
	failures     atomic.Int32
}

func newCommitThenFailProxy(target *url.URL) *commitThenFailProxy {
	proxy := &commitThenFailProxy{target: target, reverseProxy: httputil.NewSingleHostReverseProxy(target)}
	proxy.failNext.Store(true)
	return proxy
}

func (proxy *commitThenFailProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !proxy.failNext.CompareAndSwap(true, false) || !strings.HasPrefix(readOnlyQuery(request), "INSERT INTO access_events") {
		proxy.reverseProxy.ServeHTTP(writer, request)
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	upstream := request.Clone(request.Context())
	upstream.URL.Scheme = proxy.target.Scheme
	upstream.URL.Host = proxy.target.Host
	upstream.Host = proxy.target.Host
	upstream.RequestURI = ""
	upstream.Body = io.NopCloser(bytes.NewReader(body))
	upstream.ContentLength = int64(len(body))
	response, err := http.DefaultClient.Do(upstream)
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		writer.WriteHeader(response.StatusCode)
		return
	}
	proxy.failures.Add(1)
	writer.WriteHeader(http.StatusServiceUnavailable)
}

func readOnlyQuery(request *http.Request) string {
	encoded, err := io.ReadAll(request.Body)
	if err != nil {
		return ""
	}
	request.Body = io.NopCloser(bytes.NewReader(encoded))
	return string(encoded)
}

func buildIntegrationRuntime(
	t *testing.T,
	connection *nats.Conn,
	writer IngestWriter,
	config JetStreamConfig,
) *IngestRuntime {
	t.Helper()
	runtime, err := buildIngestRuntimeWithLiveHistory(t, connection, writer, config, IngestDecoderConfig{},
		processorFixtureGenerationV1().InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func publishAccessEnvelope(
	t *testing.T,
	jetstream nats.JetStreamContext,
	stream, messageID string,
	producedAt time.Time,
	events []AccessEvent,
) {
	t.Helper()
	for index := range events {
		events[index].ConfigVersion = testConfigVersionID
	}
	publishIngest(t, jetstream, stream, messageID, testConfigVersionID,
		marshalAccessEnvelope(t, messageID, producedAt, events))
}

func publishSecurityEnvelope(
	t *testing.T,
	jetstream nats.JetStreamContext,
	stream, messageID string,
	producedAt time.Time,
	events []SecurityEvent,
) {
	t.Helper()
	for index := range events {
		events[index].ConfigVersion = testConfigVersionID
	}
	publishIngest(t, jetstream, stream, messageID, testConfigVersionID,
		marshalSecurityEnvelope(t, messageID, producedAt, events))
}

func publishIngest(t *testing.T, jetstream nats.JetStreamContext, stream, messageID, configVersion string, payload []byte) {
	t.Helper()
	subject, _ := IngestSubject(testNodeID)
	message := nats.NewMsg(subject)
	message.Header.Set(nats.MsgIdHdr, messageID)
	setIntegrationAuthority(message, configVersion)
	message.Data = payload
	ack, err := jetstream.PublishMsg(message)
	if err != nil || ack == nil || ack.Stream != stream {
		t.Fatalf("publish ingest envelope: ack=%#v err=%v", ack, err)
	}
}

func setIntegrationAuthority(message *nats.Msg, configVersion string) {
	message.Header.Set(ingestNodeHeader, testNodeID)
	message.Header.Set(ingestTenantHeader, testTenantID)
	message.Header.Set(ingestSiteHeader, testSiteID)
	message.Header.Set(ingestConfigHeader, configVersion)
	// Same installation as processorFixtureGenerationV1: mustProcessor's history
	// authority rejects receipts from any other installation (IDENTITY_MISMATCH).
	message.Header.Set(ingestInstallHeader, processorFixtureGenerationV1().InstallationID)
}

// buildIngestRuntimeWithLiveHistory builds the runtime the way production does
// (startup context, history authority, generation bound to the live stream and
// durable creation times); the history authority is the in-memory recorder.
func buildIngestRuntimeWithLiveHistory(
	t *testing.T,
	connection *nats.Conn,
	writer IngestWriter,
	config JetStreamConfig,
	decoder IngestDecoderConfig,
	installationID string,
) (*IngestRuntime, error) {
	t.Helper()
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return nil, err
	}
	stream, err := jetstream.StreamInfo(config.Stream)
	if err != nil {
		return nil, err
	}
	durable, err := jetstream.ConsumerInfo(config.Stream, config.Durable)
	if err != nil {
		return nil, err
	}
	generation := IngestHistoryGenerationV1{
		InstallationID: installationID, StreamName: config.Stream, DurableName: config.Durable,
		StreamCreatedUnixNano:   uint64(stream.Created.UTC().UnixNano()),
		ConsumerCreatedUnixNano: uint64(durable.Created.UTC().UnixNano()),
		HistoryEpoch:            "55555555-5555-4555-8555-555555555555", HistoryStartSequence: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	history := &perReceiptIngestHistoryV1{recordingIngestHistoryAuthorityV1: newRecordingIngestHistoryAuthorityV1(t, generation)}
	return BuildIngestRuntime(connection, writer, config, decoder, nil, ctx, history, generation)
}

// perReceiptIngestHistoryV1 keeps the receipt state per receipt key, like the
// PG authority: the shared recorder reports one state for every receipt, so
// after the first prepared receipt every new message would be acknowledged
// without a ClickHouse write.
type perReceiptIngestHistoryV1 struct {
	*recordingIngestHistoryAuthorityV1
	mu       sync.Mutex
	prepared map[IngestReceiptKeyV1]bool
}

func (history *perReceiptIngestHistoryV1) Receive(ctx context.Context, receipt IngestReceiptV1) (IngestReceiptStateV1, error) {
	if _, err := history.recordingIngestHistoryAuthorityV1.Receive(ctx, receipt); err != nil {
		return IngestReceiptStateReceived, err
	}
	history.mu.Lock()
	defer history.mu.Unlock()
	if history.prepared[receipt.Key] {
		return IngestReceiptStatePrepared, nil
	}
	return IngestReceiptStateReceived, nil
}

func (history *perReceiptIngestHistoryV1) MarkPrepared(ctx context.Context, receipt IngestReceiptV1) (IngestHistoryProgressV1, error) {
	progress, err := history.recordingIngestHistoryAuthorityV1.MarkPrepared(ctx, receipt)
	if err == nil {
		history.mu.Lock()
		if history.prepared == nil {
			history.prepared = map[IngestReceiptKeyV1]bool{}
		}
		history.prepared[receipt.Key] = true
		history.mu.Unlock()
	}
	return progress, err
}
