package gateway

import (
	"encoding/json"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const telemetryCapturePolicyDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestTelemetryPreservesCanonicalCapturePolicyIdentity(t *testing.T) {
	batch := telemetryCaptureBatch(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, map[string]any{
		"capture_policy_revision": uint64(7), "capture_policy_digest": telemetryCapturePolicyDigest,
	})
	validated, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID},
		telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 1 {
		t.Fatalf("validated records = %d", len(validated))
	}
	var envelope struct {
		Events []struct {
			CapturePolicyRevision uint64 `json:"capture_policy_revision"`
			CapturePolicyDigest   string `json:"capture_policy_digest"`
		} `json:"events"`
	}
	if err := json.Unmarshal(validated[0].record.Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Events) != 1 || envelope.Events[0].CapturePolicyRevision != 7 ||
		envelope.Events[0].CapturePolicyDigest != telemetryCapturePolicyDigest {
		t.Fatalf("Gateway lost capture policy identity: %+v", envelope)
	}
}

func TestTelemetryRejectsMalformedCapturePolicyIdentity(t *testing.T) {
	for _, fields := range []map[string]any{
		{"capture_policy_revision": uint64(7)},
		{"capture_policy_digest": telemetryCapturePolicyDigest},
		{"capture_policy_revision": uint64(7), "capture_policy_digest": "SECRET"},
	} {
		batch := telemetryCaptureBatch(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, fields)
		if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID},
			telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now().UTC()); err == nil {
			t.Fatalf("malformed capture policy identity accepted: %+v", fields)
		}
	}
}
