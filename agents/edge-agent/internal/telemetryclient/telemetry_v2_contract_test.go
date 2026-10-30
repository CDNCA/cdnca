package telemetryclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestTelemetryClientMapsV2KindsAndKeepsLegacyV1(t *testing.T) {
	publisher, err := NewPublisher(testNodeID, &captureSender{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		schemaVersion uint16
		kind          string
		want          agentv1.TelemetryKind
	}{
		{name: "legacy access", schemaVersion: 1, kind: "access.v1", want: agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1},
		{name: "legacy security", schemaVersion: 1, kind: "security.v1", want: agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1},
		{name: "v2 access", schemaVersion: 2, kind: "access.v2", want: agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V2},
		{name: "v2 security", schemaVersion: 2, kind: "security.v2", want: agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publication := telemetryContractPublication(t, test.schemaVersion, test.kind)
			record, err := publisher.record(publication)
			if err != nil {
				t.Fatalf("record(%s) error = %v", test.kind, err)
			}
			batch, err := buildWireBatch([]Record{record}, sessionLimits{
				maxRecords: 1, maxRecordBytes: 1 << 20, maxBatchBytes: 4 << 20,
			})
			if err != nil {
				t.Fatalf("buildWireBatch(%s) error = %v", test.kind, err)
			}
			if len(batch.Records) != 1 || batch.Records[0].Kind != test.want ||
				string(batch.Records[0].Payload) != string(publication.Payload) {
				t.Fatalf("wire %s = %#v, want kind %s and unchanged payload", test.kind, batch.Records, test.want)
			}
		})
	}
}

func telemetryContractPublication(t *testing.T, schemaVersion uint16, kind string) eventspool.Publication {
	t.Helper()
	eventID := "event-telemetry-contract"
	messageID := telemetryMessageID(testNodeID, testTenantID, testSiteID, testConfigID, kind, eventID, eventID)
	event := map[string]any{
		"event_id":          eventID,
		"site_id":           testSiteID,
		"config_version_id": testConfigID,
	}
	if schemaVersion == 2 {
		event = telemetryV2ContractEvent(kind, eventID)
		messageID = ""
	}
	envelope := map[string]any{
		"schema_version": schemaVersion,
		"type":           kind,
		"message_id":     messageID,
		"produced_at":    time.Unix(1_700_000_000, 0).UTC(),
		"tenant_id":      testTenantID,
		"node_id":        testNodeID,
		"events":         []map[string]any{event},
	}
	if schemaVersion == 2 {
		envelope["installation_id"] = ""
		unsigned, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		messageID = telemetryV2ContractMessageID(t, unsigned)
		envelope["message_id"] = messageID
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return eventspool.Publication{
		Subject: "cdnca.analytics.ingest.v1." + testNodeID, MessageID: messageID,
		Payload: payload, FirstSequence: 1, LastSequence: 1,
		LastEventID: eventID, EventCount: 1,
	}
}

func telemetryV2ContractEvent(kind, eventID string) map[string]any {
	event := map[string]any{
		"metric_version": 1, "event_id": eventID, "occurred_at": time.Unix(1_700_000_000, 0).UTC(),
		"tenant_id": testTenantID, "site_id": testSiteID, "node_id": testNodeID, "installation_id": "",
		"request_id": "request-contract", "trace_id": "trace-contract", "config_version_id": testConfigID,
		"task_id": nil, "host": "example.test", "path": "/telemetry", "client_ip": "192.0.2.1",
		"method": "GET", "listen_port": 443, "protocol": "https", "status_code": 200,
		"request_bytes": 10, "response_bytes": 20, "ja4": nil,
		"origin_connect_us": nil, "origin_first_byte_us": nil, "origin_total_us": nil,
		"request_headers": map[string]string{}, "response_headers": map[string]string{},
		"request_body": map[string]any{}, "response_body": map[string]any{},
	}
	if kind == "access.v2" {
		event["cache_status"] = "MISS"
		event["duration_us"] = 100
	} else {
		event["request_class"] = "standard"
		event["event_type"] = "waf"
		event["action"] = "block"
		event["severity"] = "high"
	}
	return event
}

func telemetryV2ContractMessageID(t *testing.T, payload []byte) string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var envelope map[string]json.RawMessage
	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatal("invalid v2 contract envelope")
	}
	envelope["message_id"] = json.RawMessage(`""`)
	canonical, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca.analytics.publication.v2\x00"))
	var sequence [8]byte
	binary.BigEndian.PutUint64(sequence[:], 1)
	_, _ = hash.Write(sequence[:])
	_, _ = hash.Write(sequence[:])
	_, _ = hash.Write(canonical)
	return "msg_" + hex.EncodeToString(hash.Sum(nil))
}
