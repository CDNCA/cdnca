package gateway

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestOBS12GatewayCanonicalizesAuthorityBindingAndPreservesIdentityAndTiming(t *testing.T) {
	const subscriptionID = "00000000-0000-4000-8000-000000000099"
	authorization := telemetryTestAuthorization()
	authorization.subscriptionBySite = map[telemetryScopeKey]string{
		{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}: subscriptionID,
	}
	now := time.Now()
	for _, kind := range []agentv1.TelemetryKind{
		agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1,
		agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1,
	} {
		t.Run(kind.String(), func(t *testing.T) {
			batch := telemetryCaptureBatch(t, kind, map[string]any{
				"task_id": nil, "ja4": nil,
				"origin_connect_us": uint64(1200), "origin_first_byte_us": uint64(2400), "origin_total_us": uint64(3600),
				"request_headers": nil, "response_headers": map[string]any{},
				"request_body": nil, "response_body": map[string]any{},
			})
			original := append([]byte(nil), batch.Records[0].Payload...)
			messageID, eventID := batch.Records[0].MessageId, batch.Records[0].LastEventId
			validated, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), now)
			if err != nil {
				t.Fatalf("strict source payload rejected: %v; payload=%s", err, original)
			}
			if len(validated) != 1 || validated[0].record != batch.Records[0] ||
				validated[0].record.MessageId != messageID || validated[0].record.LastEventId != eventID ||
				validated[0].record.PackageSubscriptionId != subscriptionID || bytes.Equal(validated[0].record.Payload, original) {
				t.Fatal("Gateway did not canonically bind the authorized subscription while preserving record identity")
			}
			canonical := append([]byte(nil), validated[0].record.Payload...)
			if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), now); err != nil ||
				!bytes.Equal(batch.Records[0].Payload, canonical) {
				t.Fatalf("authority-bound payload is not stable: %v", err)
			}
			switch kind {
			case agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1:
				var envelope telemetryAccessEnvelope
				if err := json.Unmarshal(canonical, &envelope); err != nil || len(envelope.Events) != 1 ||
					envelope.PackageSubscriptionID != subscriptionID || envelope.Events[0].PackageSubscriptionID != subscriptionID ||
					envelope.Events[0].TaskID != nil || envelope.Events[0].JA4 != nil ||
					envelope.Events[0].OriginConnectUS == nil || *envelope.Events[0].OriginConnectUS != 1200 ||
					envelope.Events[0].OriginFirstByteUS == nil || *envelope.Events[0].OriginFirstByteUS != 2400 ||
					envelope.Events[0].OriginTotalUS == nil || *envelope.Events[0].OriginTotalUS != 3600 {
					t.Fatalf("canonical access payload lost authority or timing: %v; payload=%s", err, canonical)
				}
			case agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1:
				var envelope telemetrySecurityEnvelope
				if err := json.Unmarshal(canonical, &envelope); err != nil || len(envelope.Events) != 1 ||
					envelope.PackageSubscriptionID != subscriptionID || envelope.Events[0].PackageSubscriptionID != subscriptionID ||
					envelope.Events[0].TaskID != nil || envelope.Events[0].JA4 != nil ||
					envelope.Events[0].OriginConnectUS == nil || *envelope.Events[0].OriginConnectUS != 1200 ||
					envelope.Events[0].OriginFirstByteUS == nil || *envelope.Events[0].OriginFirstByteUS != 2400 ||
					envelope.Events[0].OriginTotalUS == nil || *envelope.Events[0].OriginTotalUS != 3600 {
					t.Fatalf("canonical security payload lost authority or timing: %v; payload=%s", err, canonical)
				}
			}
		})
	}
}

func TestOBS12GatewayRejectsInvalidAuthorityAndOriginTiming(t *testing.T) {
	tests := []map[string]any{
		{"task_id": ""},
		{"ja4": " padded"},
		{"origin_connect_us": uint64(3000), "origin_first_byte_us": uint64(2000), "origin_total_us": uint64(4000)},
		{"origin_connect_us": -1},
		{"origin_connect_us": "0.001, 0.002"},
	}
	for index, fields := range tests {
		batch := telemetryCaptureBatch(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, fields)
		if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err == nil {
			t.Errorf("invalid authority/timing case %d was accepted: %s", index, batch.Records[0].Payload)
		}
	}
}
