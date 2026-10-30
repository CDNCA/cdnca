package analytics

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

const telemetryV2InstallationID = "install-authority-v2"

func TestTelemetryV2DecoderPreservesAuthorityAndSanitizedCapture(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	event := validAccessEvent("access-v2-event")
	event.OccurredAt = now.Add(-time.Second)
	event.ConfigVersion = "40000000-0000-0000-0000-000000000001"
	event.ListenPort = 443
	event.RequestHeaders = map[string]string{"Authorization": "[REDACTED]", "X-Request-Id": "request-v2"}
	event.ResponseHeaders = map[string]string{"Set-Cookie": "[REDACTED]"}
	event.RequestBody = map[string]any{"token": "[REDACTED]"}
	event.ResponseBody = map[string]any{"ok": true}
	payload := marshalTelemetryV2Access(t, "access-v2-message", telemetryV2InstallationID, now, event)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	subject, _ := IngestSubject(testNodeID)
	decoded, err := decoder.Decode(subject, "access-v2-message", payload)
	if err != nil {
		t.Fatalf("Decode(v2) error = %v", err)
	}
	if decoded.SchemaVersion != 2 || decoded.Kind != "access.v2" || decoded.InstallationID != telemetryV2InstallationID ||
		len(decoded.AccessEvents) != 1 || decoded.AccessEvents[0].ListenPort != 443 ||
		decoded.AccessEvents[0].RequestHeaders["Authorization"] != "[REDACTED]" ||
		decoded.AccessEvents[0].ResponseBody["ok"] != true {
		t.Fatalf("decoded v2 = %#v", decoded)
	}

	authority := ingestAuthority{
		nodeID: testNodeID, tenantID: testTenantID, siteID: testSiteID,
		configVersion: event.ConfigVersion, installationID: telemetryV2InstallationID,
	}
	if !payloadMatchesAuthority(payload, authority) {
		t.Fatal("v2 payload did not match exact broker authority")
	}
	authority.installationID = "other-installation"
	if payloadMatchesAuthority(payload, authority) {
		t.Fatal("v2 payload matched a conflicting installation authority")
	}
}

func TestTelemetryV2RejectsUntrustedTaskAndUnknownVersionWhileV1RemainsCompatible(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	subject, _ := IngestSubject(testNodeID)

	v1 := marshalAccessEnvelope(t, "access-v1-message", now, []AccessEvent{validAccessEvent("access-v1-event")})
	if _, err := decoder.Decode(subject, "access-v1-message", v1); err != nil {
		t.Fatalf("Decode(v1) error = %v", err)
	}

	event := validAccessEvent("task-v2-event")
	event.OccurredAt = now.Add(-time.Second)
	taskID := "self-reported-task"
	event.TaskID = &taskID
	payload := marshalTelemetryV2Access(t, "task-v2-message", telemetryV2InstallationID, now, event)
	if _, err := decoder.Decode(subject, "task-v2-message", payload); RejectionCode(err) != RejectInvalidEvent {
		t.Fatalf("self-reported task error = %v, want %s", err, RejectInvalidEvent)
	}

	var unknown map[string]any
	if err := json.Unmarshal(payload, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["schema_version"] = 3
	unknown["type"] = "access.v3"
	encoded, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(subject, "task-v2-message", encoded); RejectionCode(err) != RejectUnsupportedVersion {
		t.Fatalf("unknown version error = %v, want %s", err, RejectUnsupportedVersion)
	}
}

func TestTelemetryV2ProcessorRejectsInstallationConflictBeforeWrite(t *testing.T) {
	t.Parallel()
	now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
	event := validAccessEvent("install-conflict-event")
	event.OccurredAt = now.Add(-time.Second)
	delivery := &fakeIngestDelivery{
		subject:   IngestSubjectPrefix + "." + testNodeID,
		payload:   marshalTelemetryV2Access(t, "install-conflict-message", telemetryV2InstallationID, now, event),
		messageID: "install-conflict-message", installationID: "other-installation",
		attempts: 2, streamSequence: 1,
	}
	writer := &fakeIngestWriter{}
	processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{MaxDeliver: 2})
	result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Terminated != 1 || result.WriteBatches != 0 || writer.accessCalls != 0 {
		t.Fatalf("result = %#v, access writes = %d", result, writer.accessCalls)
	}
}

func marshalTelemetryV2Access(t *testing.T, messageID, installationID string, producedAt time.Time, event AccessEvent) []byte {
	t.Helper()
	encodedEvent, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var eventObject map[string]any
	if err := json.Unmarshal(encodedEvent, &eventObject); err != nil {
		t.Fatal(err)
	}
	eventObject["installation_id"] = installationID
	payload, err := json.Marshal(map[string]any{
		"schema_version":  2,
		"type":            "access.v2",
		"message_id":      messageID,
		"produced_at":     producedAt,
		"tenant_id":       testTenantID,
		"installation_id": installationID,
		"node_id":         testNodeID,
		"events":          []any{eventObject},
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
