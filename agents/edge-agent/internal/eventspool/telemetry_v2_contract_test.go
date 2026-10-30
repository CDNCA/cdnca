package eventspool

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTelemetryV2PublicationPreservesSanitizedFactsAndStableIdentity(t *testing.T) {
	tests := []struct {
		name       string
		storedType EventType
		wireType   string
	}{
		{name: "access", storedType: EventAccess, wireType: "access.v2"},
		{name: "security", storedType: EventSecurity, wireType: "security.v2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := telemetryV2ContractRecord(test.storedType)
			first, err := encodePublication([]Record{record})
			if err != nil {
				t.Fatalf("encodePublication(v2) error = %v", err)
			}
			replay, err := encodePublication([]Record{record})
			if err != nil {
				t.Fatalf("encodePublication(v2 replay) error = %v", err)
			}
			if first.MessageID == "" || first.MessageID != replay.MessageID ||
				!reflect.DeepEqual(first.Payload, replay.Payload) || !ValidPublicationMessageID(first) {
				t.Fatalf("v2 replay identity changed: first=%#v replay=%#v", first, replay)
			}

			var wire struct {
				SchemaVersion uint16                       `json:"schema_version"`
				Type          string                       `json:"type"`
				MessageID     string                       `json:"message_id"`
				Events        []map[string]json.RawMessage `json:"events"`
			}
			if err := json.Unmarshal(first.Payload, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.SchemaVersion != 2 || wire.Type != test.wireType ||
				wire.MessageID != first.MessageID || len(wire.Events) != 1 {
				t.Fatalf("v2 envelope = %#v; payload=%s", wire, first.Payload)
			}
			event := wire.Events[0]
			assertTelemetryV2JSONField(t, event, "installation_id", `""`)
			assertTelemetryV2JSONField(t, event, "task_id", "null")
			assertTelemetryV2JSONField(t, event, "request_id", `"request-v2"`)
			assertTelemetryV2JSONField(t, event, "trace_id", `"trace-v2"`)
			assertTelemetryV2JSONField(t, event, "origin_connect_us", "1200")
			assertTelemetryV2JSONField(t, event, "origin_first_byte_us", "2400")
			assertTelemetryV2JSONField(t, event, "origin_total_us", "3600")
			assertTelemetryV2JSONField(t, event, "request_headers", `{"Authorization":"[REDACTED]","X-Request-ID":"request-v2"}`)
			assertTelemetryV2JSONField(t, event, "response_headers", `{"Set-Cookie":"[REDACTED]","X-Cache":"HIT"}`)
			assertTelemetryV2JSONField(t, event, "request_body", `{"password":"[REDACTED]","profile":{"name":"alice"}}`)
			assertTelemetryV2JSONField(t, event, "response_body", `{"result":"ok","token":"[REDACTED]"}`)

			changed := record
			changed.envelope.RequestBody = map[string]any{"password": redactedValue, "profile": map[string]any{"name": "bob"}}
			changedPublication, err := encodePublication([]Record{changed})
			if err != nil {
				t.Fatalf("encodePublication(changed v2) error = %v", err)
			}
			if changedPublication.MessageID == first.MessageID || reflect.DeepEqual(changedPublication.Payload, first.Payload) {
				t.Fatal("v2 content change did not change publication identity and bytes")
			}
		})
	}

	legacyRecord := telemetryV2ContractRecord(EventAccess)
	legacyMessageID := publicationMessageID([]Record{legacyRecord})
	legacyPayload, err := json.Marshal(analyticsAccessEnvelope{
		SchemaVersion: 1, Type: string(EventAccess), MessageID: legacyMessageID,
		ProducedAt: legacyRecord.OccurredAt, TenantID: legacyRecord.TenantID,
		NodeID: legacyRecord.NodeID, Events: []analyticsAccessEvent{analyticsAccessFrom(legacyRecord.envelope)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ValidPublicationMessageID(Publication{
		MessageID: legacyMessageID, Payload: legacyPayload, FirstSequence: 1, LastSequence: 1,
		LastEventID: legacyRecord.EventID, EventCount: 1,
	}) {
		t.Fatal("legacy v1 content-bound publication identity was rejected")
	}
}

func telemetryV2ContractRecord(eventType EventType) Record {
	event := pendingAccess("evt-telemetry-v2", tenantOne)
	event.SchemaVersion = SchemaVersion
	event.Type = eventType
	event.Sequence = 1
	event.RequestID = "request-v2"
	event.TraceID = "trace-v2"
	event.OriginConnectUS = uint64Pointer(1200)
	event.OriginFirstByteUS = uint64Pointer(2400)
	event.OriginTotalUS = uint64Pointer(3600)
	event.RequestHeaders = map[string]string{"Authorization": redactedValue, "X-Request-ID": "request-v2"}
	event.ResponseHeaders = map[string]string{"Set-Cookie": redactedValue, "X-Cache": "HIT"}
	event.RequestBody = map[string]any{"password": redactedValue, "profile": map[string]any{"name": "alice"}}
	event.ResponseBody = map[string]any{"result": "ok", "token": redactedValue}
	if eventType == EventSecurity {
		event.ListenPort = 443
		event.Protocol = "https"
		event.RequestClass = "standard"
		event.CacheStatus = ""
		event.DurationUS = 0
		event.SecurityType = "waf"
		event.Action = "block"
		event.Severity = "high"
	}
	return Record{
		Sequence: event.Sequence, EventID: event.EventID, TenantID: event.TenantID,
		NodeID: event.NodeID, Type: event.Type, OccurredAt: event.OccurredAt, envelope: event,
	}
}

func assertTelemetryV2JSONField(t *testing.T, event map[string]json.RawMessage, name, want string) {
	t.Helper()
	got, ok := event[name]
	if !ok || string(got) != want {
		t.Fatalf("v2 event %s = %s, present=%t, want %s", name, got, ok, want)
	}
}
