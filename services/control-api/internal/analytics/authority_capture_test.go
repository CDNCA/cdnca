package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type authorityFakeDelivery struct {
	*fakeIngestDelivery
	installationID string
}

func (delivery *authorityFakeDelivery) InstallationID() string { return delivery.installationID }

func TestIngestDecoderPreservesRedactedCaptureWithoutNumberLoss(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 29, 0, 0, 0, 0, time.UTC)
	event := validAccessEvent("capture-event")
	event.OccurredAt = now.Add(-time.Second)
	payload := accessCapturePayload(t, event, map[string]any{
		"request_headers":  map[string]string{"Authorization": "[REDACTED]", "X-Request-Class": "api"},
		"response_headers": map[string]string{"Set-Cookie": "[REDACTED]"},
		"request_body":     map[string]any{"account": json.Number("9007199254740993"), "token": "[REDACTED]"},
		"response_body":    map[string]any{"accepted": true},
	}, now)
	decoder, err := NewIngestDecoder(IngestDecoderConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, "capture-message", payload)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	got := decoded.AccessEvents[0]
	if got.RequestHeaders["Authorization"] != "[REDACTED]" || got.ResponseHeaders["Set-Cookie"] != "[REDACTED]" {
		t.Fatalf("capture headers = %#v / %#v", got.RequestHeaders, got.ResponseHeaders)
	}
	account, ok := got.RequestBody["account"].(json.Number)
	if !ok || account.String() != "9007199254740993" || got.ResponseBody["accepted"] != true {
		t.Fatalf("capture bodies = %#v / %#v", got.RequestBody, got.ResponseBody)
	}
}

func TestIngestDecoderRejectsUnredactedSensitiveCapture(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 29, 0, 0, 0, 0, time.UTC)
	event := validAccessEvent("capture-leak")
	event.OccurredAt = now.Add(-time.Second)
	payload := accessCapturePayload(t, event, map[string]any{
		"request_body": map[string]any{"nested": map[string]any{"api_key": "secret"}},
	}, now)
	decoder, err := NewIngestDecoder(IngestDecoderConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, "capture-message", payload); RejectionCode(err) != RejectInvalidEvent {
		t.Fatalf("Decode() error = %v, want %s", err, RejectInvalidEvent)
	}
}

func TestIngestProcessorBindsInstallationAuthorityOutsidePayload(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 29, 0, 0, 0, 0, time.UTC)
	event := validAccessEvent("installation-authority")
	event.OccurredAt = now.Add(-time.Second)
	event.InstallationID = "install-payload-1"
	delivery := &authorityFakeDelivery{
		fakeIngestDelivery: newFakeDelivery(t, "installation-message", now, []AccessEvent{event}),
		installationID:     "test-installation",
	}
	writer := &fakeIngestWriter{}
	processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{})
	result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Acknowledged != 1 || len(writer.accessEvents) != 1 || len(writer.accessEvents[0]) != 1 {
		t.Fatalf("Process() result = %#v, writes = %#v", result, writer.accessEvents)
	}
	if got := writer.accessEvents[0][0].InstallationID; got != delivery.installationID {
		t.Fatalf("installation_id = %q, want %q", got, delivery.installationID)
	}
}

func TestClickHouseWriterPersistsAuthorityCaptureAndNullSourceFields(t *testing.T) {
	t.Parallel()
	var requestBody string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		requestBody = string(encoded)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	event := validAccessEvent("capture-storage")
	event.InstallationID = "install-authority-1"
	event.RequestHeaders = map[string]string{"Authorization": "[REDACTED]", "X-Request-Class": "api"}
	event.ResponseHeaders = map[string]string{"Set-Cookie": "[REDACTED]"}
	event.RequestBody = map[string]any{"account": json.Number("9007199254740993")}
	event.ResponseBody = map[string]any{}
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if err := client.WriteAccessEvents(context.Background(), "capture-storage-batch", []AccessEvent{event}); err != nil {
		t.Fatalf("WriteAccessEvents() error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(requestBody), "\n")
	if len(lines) != 2 || lines[0] != insertAccessEventsSQL {
		t.Fatalf("write body = %q", requestBody)
	}
	var row map[string]any
	decoder := json.NewDecoder(strings.NewReader(lines[1]))
	decoder.UseNumber()
	if err := decoder.Decode(&row); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"task_id", "ja4", "origin_connect_us", "origin_first_byte_us", "origin_total_us"} {
		value, exists := row[field]
		if !exists || value != nil {
			t.Fatalf("%s = %#v, present=%t; want explicit null", field, value, exists)
		}
	}
	if row["installation_id"] != event.InstallationID || row["request_body"] != `{"account":9007199254740993}` || row["response_body"] != `{}` {
		t.Fatalf("authority capture row = %#v", row)
	}
	requestHeaders, ok := row["request_headers"].(map[string]any)
	if !ok || requestHeaders["Authorization"] != "[REDACTED]" || requestHeaders["X-Request-Class"] != "api" {
		t.Fatalf("request_headers = %#v", row["request_headers"])
	}
}

func TestNATSDeliveryInstallationComesOnlyFromTrustedHeader(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.July, 29, 0, 0, 0, 0, time.UTC)
	event := validAccessEvent("authority-header")
	event.OccurredAt = now.Add(-time.Second)
	event.InstallationID = ""
	event.ConfigVersion = "40000000-0000-0000-0000-000000000001"
	payload, err := json.Marshal(AccessIngestEnvelope{
		SchemaVersion: IngestSchemaVersion, Type: AccessEnvelopeType, MessageID: "authority-message",
		ProducedAt: now, TenantID: testTenantID, NodeID: testNodeID, Events: []AccessEvent{event},
	})
	if err != nil {
		t.Fatal(err)
	}
	message := nats.NewMsg(IngestSubjectPrefix + "." + testNodeID)
	message.Data = payload
	message.Header.Set(nats.MsgIdHdr, "authority-message")
	message.Header.Set(ingestNodeHeader, testNodeID)
	message.Header.Set(ingestTenantHeader, testTenantID)
	message.Header.Set(ingestSiteHeader, testSiteID)
	message.Header.Set(ingestConfigHeader, event.ConfigVersion)
	message.Header.Set(ingestInstallHeader, "install-authority-2")
	delivery := &natsIngestDelivery{message: message}
	if got := delivery.InstallationID(); got != "install-authority-2" {
		t.Fatalf("InstallationID() = %q", got)
	}

	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	events := object["events"].([]any)
	events[0].(map[string]any)["installation_id"] = "payload-spoof"
	spoofed, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewIngestDecoder(IngestDecoderConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(message.Subject, "authority-message", spoofed); RejectionCode(err) != RejectInvalidJSON {
		t.Fatalf("payload installation_id error = %v, want %s", err, RejectInvalidJSON)
	}
}

func accessCapturePayload(t *testing.T, event AccessEvent, capture map[string]any, producedAt time.Time) []byte {
	t.Helper()
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var eventObject map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&eventObject); err != nil {
		t.Fatal(err)
	}
	for key, value := range capture {
		eventObject[key] = value
	}
	payload, err := json.Marshal(map[string]any{
		"schema_version": IngestSchemaVersion,
		"type":           AccessEnvelopeType,
		"message_id":     "capture-message",
		"produced_at":    producedAt,
		"tenant_id":      testTenantID,
		"node_id":        testNodeID,
		"events":         []any{eventObject},
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
