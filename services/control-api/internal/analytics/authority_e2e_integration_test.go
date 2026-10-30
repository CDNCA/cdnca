package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	analyticslog "github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/nats-io/nats.go"
)

func TestAuthorityNATSClickHouseReconciliation(t *testing.T) {
	if os.Getenv("ANALYTICS_INGEST_INTEGRATION") != "1" {
		t.Skip("set ANALYTICS_INGEST_INTEGRATION=1 to run the authority ingest integration test")
	}
	natsURL := os.Getenv("ANALYTICS_INGEST_NATS_URL")
	clickHouseURL := os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_URL")
	databaseName := os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_DATABASE")
	if natsURL == "" || clickHouseURL == "" || databaseName == "" {
		t.Fatal("authority ingest integration environment is incomplete")
	}

	database := newRankTestDatabase(t)
	database.reset(t)
	connection, err := nats.Connect(natsURL,
		nats.UserInfo(os.Getenv("ANALYTICS_INGEST_NATS_USER"), os.Getenv("ANALYTICS_INGEST_NATS_PASSWORD")),
		nats.Name("cdnca-obs0510-authority-e2e"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano())
	config := DefaultJetStreamConfig()
	config.IsolationKeyProvider = newRotatingIsolationKeyProvider()
	config.Stream = "OBS0510_AUTHORITY_" + suffix
	config.Durable = "obs0510_authority_" + suffix
	config.IsolationStream = "OBS0510_ISOLATION_" + suffix
	config.AckWait = 2 * time.Second
	config.FetchTimeout = 500 * time.Millisecond
	config.OperationTimeout = 500 * time.Millisecond
	config.NakBaseDelay = 25 * time.Millisecond
	config.NakMaxDelay = 100 * time.Millisecond
	config.MaxDeliver = 4
	config.MaxAckPending = 8
	config.MaxWaiting = 2
	config.FetchBatch = 4
	config.StreamMaxAge = 0
	config.StreamMaxBytes = 64 << 20
	config.StreamMaxMessages = 1000
	config.IsolationMaxAge = time.Hour
	config.IsolationMaxBytes = 16 << 20
	config.DuplicateWindow = 2 * time.Minute
	config.Replicas = 1
	evidenceBucket := isolationEvidenceBucketName(config)
	defer func() {
		_ = jetstream.DeleteConsumer(config.Stream, config.Durable)
		_ = jetstream.DeleteStream(config.Stream)
		_ = jetstream.DeleteStream(config.IsolationStream)
		stateBucket, leaseBucket := coordinationBucketNames(config)
		_ = jetstream.DeleteKeyValue(stateBucket)
		_ = jetstream.DeleteKeyValue(leaseBucket)
		_ = jetstream.DeleteKeyValue(evidenceBucket)
	}()
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
	clientConfig := Config{
		Endpoint: clickHouseURL, Database: databaseName,
		Username:     os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_USER"),
		Password:     os.Getenv("ANALYTICS_INGEST_CLICKHOUSE_PASSWORD"),
		QueryTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second,
	}
	targetClient, err := NewClient(clientConfig, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	from := now.Truncate(time.Hour).Add(-time.Hour)
	to := from.Add(2 * time.Hour)
	accessEvents := []AccessEvent{
		authorityAccessEvent("authority-access-a", from.Add(10*time.Minute), "/asset-a", "a.example.test", "2001:db8::1", "CN", "carrier-a", 200, 100),
		authorityAccessEvent("authority-access-b", from.Add(20*time.Minute), "/asset-b", "b.example.test", "2001:db8::2", "US", "carrier-b", 404, 200),
		authorityAccessEvent("authority-access-c", from.Add(30*time.Minute), "/asset-a", "a.example.test", "2001:db8::1", "CN", "carrier-a", 503, 300),
	}
	securityEvents := []SecurityEvent{authoritySecurityEvent("authority-security-a", from.Add(40*time.Minute))}
	accessEvents[2].RequestHeaders = map[string]string{"Authorization": redactedCaptureValue, "X-Request-Class": "api"}
	accessEvents[2].ResponseHeaders = map[string]string{"Set-Cookie": redactedCaptureValue}
	accessEvents[2].RequestBody = map[string]any{"account": json.Number("9007199254740993")}
	accessEvents[2].ResponseBody = map[string]any{}
	originConnectUS, originFirstByteUS, originTotalUS := uint64(1200), uint64(2400), uint64(3600)
	accessEvents[2].OriginConnectUS = &originConnectUS
	accessEvents[2].OriginFirstByteUS = &originFirstByteUS
	accessEvents[2].OriginTotalUS = &originTotalUS
	securityEvents[0].RequestHeaders = map[string]string{"Cookie": redactedCaptureValue}
	securityEvents[0].RequestBody = map[string]any{"token": redactedCaptureValue}

	target, err := clientConfigURL(clientConfig.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	faultProxy := newCommitThenFailProxy(target)
	faultServer := httptest.NewServer(faultProxy)
	defer faultServer.Close()
	faultConfig := clientConfig
	faultConfig.Endpoint = faultServer.URL
	faultClient, err := NewClient(faultConfig, faultServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	runtime := authorityRuntime(t, connection, faultClient, config, now)
	// The node (agents/edge-agent/internal/eventspool) always sends
	// response_body; the control-api model's omitempty would drop the empty
	// object, so put it back the way the node encodes it.
	accessPayload := bytes.Replace(marshalAccessEnvelope(t, "authority-access-message", now, accessEvents),
		[]byte(`"event_id":"authority-access-c",`), []byte(`"event_id":"authority-access-c","response_body":{},`), 1)
	publishAuthorityEnvelope(t, jetstream, config.Stream, "authority-access-message", accessPayload, testConfigVersionID)
	first, err := runtime.RunOnce(context.Background())
	if err != nil || first.Naked != 1 || first.Acknowledged != 0 || faultProxy.failures.Load() != 1 {
		t.Fatalf("uncertain write result=%#v error=%v failures=%d", first, err, faultProxy.failures.Load())
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(50 * time.Millisecond)
	runtime = authorityRuntime(t, connection, targetClient, config, now)
	defer runtime.Close()
	retried, err := runtime.RunOnce(context.Background())
	if err != nil || retried.Acknowledged != 1 || retried.Naked != 0 {
		t.Fatalf("redelivery result=%#v error=%v", retried, err)
	}
	publishAuthorityEnvelope(t, jetstream, config.Stream, "authority-security-message",
		marshalSecurityEnvelope(t, "authority-security-message", now, securityEvents), testConfigVersionID)
	securityResult, err := runtime.RunOnce(context.Background())
	if err != nil || securityResult.Acknowledged != 1 {
		t.Fatalf("security ingest result=%#v error=%v", securityResult, err)
	}

	scope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: from, To: to}
	summary, err := targetClient.Summary(context.Background(), scope, filter)
	if err != nil || summary.RequestCount != 3 || summary.ResponseBytes != 600 || summary.Status2xx != 1 ||
		summary.Status4xx != 1 || summary.Status5xx != 1 || summary.SecurityEvents != 1 {
		t.Fatalf("summary=%#v error=%v", summary, err)
	}
	wantRank := map[RankDimension]string{
		RankByURL: "/asset-a", RankByIP: "2001:db8::1", RankByDomain: "a.example.test",
		RankByRegion: "CN", RankByCarrier: "carrier-a",
	}
	for dimension, wantKey := range wantRank {
		page, rankErr := targetClient.Rank(context.Background(), scope, filter, dimension, 10, "")
		if rankErr != nil || len(page.Items) != 2 || page.Items[0].Key != wantKey ||
			page.Items[0].RequestCount != 2 || page.Items[0].ResponseBytes != 400 {
			t.Fatalf("rank %s page=%#v error=%v", dimension, page, rankErr)
		}
	}

	logClient, err := analyticslog.NewClient(analyticslog.ClientConfig{
		Endpoint: clickHouseURL, Database: databaseName,
		Username: clientConfig.Username, Password: clientConfig.Password, QueryTimeout: 3 * time.Second,
		CursorKeyring: analyticslog.CursorKeyring{ActiveKID: "authority-test", Keys: map[string][]byte{
			"authority-test": bytes.Repeat([]byte{0x41}, 32),
		}},
	}, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	logService, err := analyticslog.NewService(logClient)
	if err != nil {
		t.Fatal(err)
	}
	actor := analyticslog.Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{analyticslog.ReadPermission}}
	logFilter := analyticslog.Filter{From: filter.From, To: filter.To}
	firstPage, err := logService.ListAccess(context.Background(), actor, analyticslog.QueryRequest{
		Audience: analyticslog.AudienceTenant, Filter: logFilter, Limit: 2,
	})
	if err != nil || len(firstPage.Items) != 2 || firstPage.NextCursor == "" {
		t.Fatalf("access first page=%#v error=%v", firstPage, err)
	}
	secondPage, err := logService.ListAccess(context.Background(), actor, analyticslog.QueryRequest{
		Audience: analyticslog.AudienceTenant, Filter: logFilter, Limit: 2, Cursor: firstPage.NextCursor,
	})
	ids := append(logEventIDs(firstPage.Items), logEventIDs(secondPage.Items)...)
	if err != nil || strings.Join(ids, ",") != "authority-access-c,authority-access-b,authority-access-a" ||
		secondPage.NextCursor != "" || !secondPage.SnapshotAt.Equal(firstPage.SnapshotAt) {
		t.Fatalf("access pages ids=%v second=%#v error=%v", ids, secondPage, err)
	}
	latest := firstPage.Items[0]
	account, ok := latest.RequestBody["account"].(json.Number)
	if latest.InstallationID != "installation-v1" || latest.TaskID != nil || latest.JA4 != nil ||
		latest.OriginConnectUS == nil || *latest.OriginConnectUS != originConnectUS ||
		latest.OriginFirstByteUS == nil || *latest.OriginFirstByteUS != originFirstByteUS ||
		latest.OriginTotalUS == nil || *latest.OriginTotalUS != originTotalUS ||
		latest.RequestHeaders["Authorization"] != redactedCaptureValue || latest.ResponseHeaders["Set-Cookie"] != redactedCaptureValue ||
		!ok || account.String() != "9007199254740993" || latest.ResponseBody == nil || len(latest.ResponseBody) != 0 {
		t.Fatalf("access authority capture=%#v", latest)
	}
	securityPage, err := logService.ListBlockEvents(context.Background(), actor, analyticslog.QueryRequest{
		Audience: analyticslog.AudienceTenant, Filter: logFilter, Limit: 2,
	})
	if err != nil || len(securityPage.Items) != 1 || securityPage.Items[0].EventID != "authority-security-a" {
		t.Fatalf("security page=%#v error=%v", securityPage, err)
	}
	security := securityPage.Items[0]
	if security.InstallationID != "installation-v1" || security.TaskID != nil || security.JA4 != nil ||
		security.RequestHeaders["Cookie"] != redactedCaptureValue || security.RequestBody["token"] != redactedCaptureValue {
		t.Fatalf("security authority capture=%#v", security)
	}
}

func authorityRuntime(t *testing.T, connection *nats.Conn, writer IngestWriter, config JetStreamConfig, now time.Time) *IngestRuntime {
	t.Helper()
	runtime, err := buildIngestRuntimeWithLiveHistory(t, connection, writer, config,
		IngestDecoderConfig{Now: func() time.Time { return now }}, "installation-v1")
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func publishAuthorityEnvelope(t *testing.T, jetstream nats.JetStreamContext, stream, messageID string, payload []byte, configVersion string) {
	t.Helper()
	subject, _ := IngestSubject(testNodeID)
	message := nats.NewMsg(subject)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, messageID)
	message.Header.Set(ingestNodeHeader, testNodeID)
	message.Header.Set(ingestTenantHeader, testTenantID)
	message.Header.Set(ingestSiteHeader, testSiteID)
	message.Header.Set(ingestConfigHeader, configVersion)
	message.Header.Set(ingestInstallHeader, "installation-v1")
	ack, err := jetstream.PublishMsg(message)
	if err != nil || ack == nil || ack.Stream != stream {
		t.Fatalf("publish authority envelope: ack=%#v err=%v", ack, err)
	}
}

func authorityAccessEvent(eventID string, occurredAt time.Time, path, host, clientIP, country, carrier string,
	status uint16, responseBytes uint64,
) AccessEvent {
	event := validAccessEvent(eventID)
	event.OccurredAt = occurredAt
	event.ConfigVersion = testConfigVersionID
	event.Path = path
	event.Host = host
	event.ClientIP = clientIP
	event.CountryCode = country
	event.Carrier = carrier
	event.StatusCode = status
	event.ResponseBytes = responseBytes
	return event
}

func authoritySecurityEvent(eventID string, occurredAt time.Time) SecurityEvent {
	event := validSecurityEvent(eventID)
	event.OccurredAt = occurredAt
	event.ConfigVersion = testConfigVersionID
	event.Action = "block"
	return event
}

func clientConfigURL(value string) (*url.URL, error) {
	return url.Parse(value)
}

func logEventIDs(items []analyticslog.AccessLog) []string {
	ids := make([]string, len(items))
	for index, item := range items {
		ids[index] = item.EventID
	}
	return ids
}
