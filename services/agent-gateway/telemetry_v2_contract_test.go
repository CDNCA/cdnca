package gateway

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const (
	telemetryKindAccessV2   agentv1.TelemetryKind = 4
	telemetryKindSecurityV2 agentv1.TelemetryKind = 5
)

func TestTelemetryV2AcceptsStrictAuthorityBoundAccessAndSecurity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, kind := range []agentv1.TelemetryKind{telemetryKindAccessV2, telemetryKindSecurityV2} {
		t.Run(telemetryV2Type(kind), func(t *testing.T) {
			batch := telemetryV2Batch(t, kind, now)
			validated, err := validateTelemetryBatch(
				batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), now,
			)
			if err != nil {
				t.Fatalf("valid telemetry v2 batch rejected: %v; payload=%s", err, batch.Records[0].Payload)
			}
			if len(validated) != 1 || validated[0].record != batch.Records[0] {
				t.Fatalf("validated telemetry v2 records = %#v", validated)
			}

			var envelope map[string]any
			if err := json.Unmarshal(batch.Records[0].Payload, &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope["installation_id"] != testTelemetryInstallationID {
				t.Fatalf("envelope installation_id = %#v", envelope["installation_id"])
			}
			events, ok := envelope["events"].([]any)
			if !ok || len(events) != 1 {
				t.Fatalf("events = %#v", envelope["events"])
			}
			event, ok := events[0].(map[string]any)
			if !ok || event["installation_id"] != testTelemetryInstallationID || event["task_id"] != nil ||
				event["listen_port"] != float64(443) || event["origin_connect_us"] != float64(10) ||
				event["origin_first_byte_us"] != float64(20) || event["origin_total_us"] != float64(30) {
				t.Fatalf("authority-bound event = %#v", event)
			}
			requestHeaders, ok := event["request_headers"].(map[string]any)
			if !ok || requestHeaders["Authorization"] != telemetryRedactedCaptureValue {
				t.Fatalf("request_headers = %#v", event["request_headers"])
			}
		})
	}
}

func TestTelemetryV2KeepsV1Compatible(t *testing.T) {
	now := time.Now().UTC()
	batch := telemetryBatch(t, 1, 1)
	if _, err := validateTelemetryBatch(
		batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), now,
	); err != nil {
		t.Fatalf("valid telemetry v1 batch rejected after v2 addition: %v", err)
	}
}

func TestTelemetryV2RejectsUnknownVersionsAndForgedAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name   string
		kind   agentv1.TelemetryKind
		mutate func(map[string]any, map[string]any)
	}{
		{name: "unknown v3 schema", kind: telemetryKindAccessV2, mutate: func(envelope, _ map[string]any) {
			envelope["schema_version"] = float64(3)
			envelope["type"] = "access.v3"
		}},
		{name: "unknown v3 kind", kind: agentv1.TelemetryKind(6)},
		{name: "v1 kind with v2 schema", kind: agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1},
		{name: "forged envelope installation", kind: telemetryKindAccessV2, mutate: func(envelope, _ map[string]any) {
			envelope["installation_id"] = "forged-installation"
		}},
		{name: "forged event installation", kind: telemetryKindAccessV2, mutate: func(_ map[string]any, event map[string]any) {
			event["installation_id"] = "forged-installation"
		}},
		{name: "empty task identity", kind: telemetryKindAccessV2, mutate: func(_ map[string]any, event map[string]any) {
			event["task_id"] = ""
		}},
		{name: "self-reported task identity", kind: telemetryKindAccessV2, mutate: func(_ map[string]any, event map[string]any) {
			event["task_id"] = "task-v2-01"
		}},
		{name: "oversized task identity", kind: telemetryKindAccessV2, mutate: func(_ map[string]any, event map[string]any) {
			event["task_id"] = strings.Repeat("t", 129)
		}},
		{name: "unredacted sensitive capture", kind: telemetryKindAccessV2, mutate: func(_ map[string]any, event map[string]any) {
			event["request_headers"] = map[string]any{"Authorization": "Bearer secret"}
		}},
		{name: "oversized capture", kind: telemetryKindAccessV2, mutate: func(_ map[string]any, event map[string]any) {
			event["response_headers"] = map[string]any{"X-Large": strings.Repeat("x", telemetryMaxCaptureHeaderValueBytes+1)}
		}},
		{name: "invalid origin timing", kind: telemetryKindAccessV2, mutate: func(_ map[string]any, event map[string]any) {
			event["origin_connect_us"] = float64(31)
		}},
		{name: "unknown strict field", kind: telemetryKindAccessV2, mutate: func(envelope, _ map[string]any) {
			envelope["future_field"] = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := telemetryV2Batch(t, telemetryKindAccessV2, now)
			batch.Records[0].Kind = test.kind
			if test.mutate != nil {
				mutateTelemetryV2Payload(t, batch.Records[0], test.mutate)
			}
			batch.BatchId = telemetryBatchID(batch.Records)
			if _, err := validateTelemetryBatch(
				batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), now,
			); err == nil {
				t.Fatalf("invalid telemetry v2 batch accepted: %s", batch.Records[0].Payload)
			}
		})
	}
}

func telemetryV2Batch(t *testing.T, kind agentv1.TelemetryKind, now time.Time) *agentv1.TelemetryBatch {
	t.Helper()
	eventID := "event-v2-01"
	typeName := telemetryV2Type(kind)
	event := map[string]any{
		"metric_version": 1, "event_id": eventID, "occurred_at": now.Add(-time.Minute),
		"tenant_id": testTelemetryTenantID, "site_id": testTelemetrySiteID, "node_id": testNodeID,
		"config_version_id": testTelemetryConfigVersionID, "installation_id": "", "task_id": nil,
		"host": "example.test", "path": "/telemetry/v2", "client_ip": "192.0.2.10", "method": "GET",
		"listen_port": 443, "protocol": "https", "status_code": 200, "request_bytes": 11, "response_bytes": 22,
		"origin_connect_us": 10, "origin_first_byte_us": 20, "origin_total_us": 30,
		"request_headers":  map[string]any{"Authorization": telemetryRedactedCaptureValue, "X-Trace": "safe"},
		"response_headers": map[string]any{"Set-Cookie": telemetryRedactedCaptureValue},
		"request_body":     map[string]any{"password": telemetryRedactedCaptureValue, "value": "safe"},
		"response_body":    map[string]any{"token": telemetryRedactedCaptureValue},
	}
	if kind == telemetryKindAccessV2 {
		event["cache_status"] = "HIT"
		event["duration_us"] = 40
	} else {
		event["request_class"] = "standard"
		event["event_type"] = "waf"
		event["action"] = "block"
		event["severity"] = "high"
	}
	envelope := map[string]any{
		"schema_version": 2, "type": typeName, "message_id": "", "produced_at": now,
		"tenant_id": testTelemetryTenantID, "node_id": testNodeID, "installation_id": "", "events": []any{event},
	}
	messageID := telemetryV2ContractMessageID(t, kind, 1, 1, envelope)
	envelope["message_id"] = messageID
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	record := &agentv1.TelemetryRecord{
		Kind: kind, MessageId: messageID, FirstSequence: 1, LastSequence: 1,
		LastEventId: eventID, EventCount: 1, Payload: payload,
	}
	return &agentv1.TelemetryBatch{
		BatchId: telemetryBatchID([]*agentv1.TelemetryRecord{record}), FirstSequence: 1, LastSequence: 1,
		Records: []*agentv1.TelemetryRecord{record},
	}
}

func telemetryV2Type(kind agentv1.TelemetryKind) string {
	if kind == telemetryKindSecurityV2 {
		return "security.v2"
	}
	return "access.v2"
}

func mutateTelemetryV2Payload(
	t *testing.T,
	record *agentv1.TelemetryRecord,
	mutate func(map[string]any, map[string]any),
) {
	t.Helper()
	var envelope map[string]any
	if err := json.Unmarshal(record.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	events, ok := envelope["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("events = %#v", envelope["events"])
	}
	event, ok := events[0].(map[string]any)
	if !ok {
		t.Fatalf("event = %#v", events[0])
	}
	mutate(envelope, event)
	envelope["message_id"] = ""
	record.MessageId = telemetryV2ContractMessageID(t, record.Kind, record.FirstSequence, record.LastSequence, envelope)
	envelope["message_id"] = record.MessageId
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	record.Payload = payload
}

func telemetryV2ContractMessageID(
	t *testing.T,
	_ agentv1.TelemetryKind,
	firstSequence, lastSequence uint64,
	envelope map[string]any,
) string {
	t.Helper()
	canonical, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("cdnca.analytics.publication.v2\x00"))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], firstSequence)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint64(encoded[:], lastSequence)
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write(canonical)
	return "msg_" + hex.EncodeToString(digest.Sum(nil))
}

// The node logs the client's User-Agent families on every access event (ge-analytics, eventspool
// analyticsAccessEvent client_browser / client_os; the control plane stores them, analytics.AccessEvent): the
// gateway accepts them (rejecting them failed every access batch of a real node) and only the
// families edgeconfig defines.
func TestTelemetryV2AcceptsClientBrowserAndOS(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	batch := telemetryV2Batch(t, telemetryKindAccessV2, now)
	mutateTelemetryV2Payload(t, batch.Records[0], func(_ map[string]any, event map[string]any) {
		event["client_browser"], event["client_os"] = "chrome", "windows"
	})
	batch.BatchId = telemetryBatchID(batch.Records)
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(),
		DefaultTelemetryConfig(), now); err != nil {
		t.Fatalf("access event with client_browser/client_os rejected: %v", err)
	}
	batch = telemetryV2Batch(t, telemetryKindAccessV2, now)
	mutateTelemetryV2Payload(t, batch.Records[0], func(_ map[string]any, event map[string]any) {
		event["client_browser"] = "netscape"
	})
	batch.BatchId = telemetryBatchID(batch.Records)
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(),
		DefaultTelemetryConfig(), now); err == nil {
		t.Fatal("unknown client_browser family accepted")
	}
}
