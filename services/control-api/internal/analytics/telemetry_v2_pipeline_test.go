package analytics

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTelemetryV2PipelinePersistsAndAcknowledgesBothEventKinds(t *testing.T) {
	for _, kind := range []string{AccessEnvelopeTypeV2, SecurityEnvelopeTypeV2} {
		t.Run(kind, func(t *testing.T) {
			now := time.Date(2099, 1, 1, 1, 0, 0, 0, time.UTC)
			generation := processorFixtureGenerationV1()
			var event any
			if kind == AccessEnvelopeTypeV2 {
				access := validAccessEvent("pipeline-access")
				access.OccurredAt, access.InstallationID, access.ListenPort = now.Add(-time.Second), generation.InstallationID, 443
				event = access
			} else {
				security := validSecurityEvent("pipeline-security")
				security.OccurredAt, security.InstallationID = now.Add(-time.Second), generation.InstallationID
				event = security
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			fields["installation_id"] = generation.InstallationID
			payload, err := json.Marshal(map[string]any{
				"schema_version": 2, "type": kind, "message_id": "pipeline-message", "produced_at": now,
				"tenant_id": testTenantID, "node_id": testNodeID, "installation_id": generation.InstallationID,
				"events": []any{fields},
			})
			if err != nil {
				t.Fatal(err)
			}
			history := newRecordingIngestHistoryAuthorityV1(t, generation)
			writer := &fakeIngestWriter{}
			processor := mustProcessor(t, now, writer, &memoryIsolationSink{}, IngestProcessorConfig{History: history, HistoryGeneration: generation})
			delivery := &fakeIngestDelivery{subject: IngestSubjectPrefix + "." + testNodeID, payload: payload,
				messageID: "pipeline-message", installationID: generation.InstallationID, attempts: 1, streamSequence: 1}
			result, err := processor.Process(t.Context(), []IngestDelivery{delivery})
			if err != nil || result.Acknowledged != 1 || result.Terminated != 0 || result.WriteBatches != 1 ||
				writer.accessCalls+writer.securityCalls != 1 || len(history.receipts) != 1 {
				t.Fatalf("v2 not committed and acknowledged: result=%+v writes=%d err=%v", result, writer.accessCalls+writer.securityCalls, err)
			}
			for _, receipt := range history.receipts {
				if kind == AccessEnvelopeTypeV2 && (len(receipt.RealtimeExpectedCounts) != 1 || receipt.RealtimeExpectedCounts[0].ListenPort != 443) {
					t.Fatal("v2 access omitted expected-count authority")
				}
			}
			result, err = processor.Process(t.Context(), []IngestDelivery{delivery})
			if err != nil || result.Acknowledged != 1 || writer.accessCalls+writer.securityCalls != 1 {
				t.Fatalf("v2 replay wrote twice: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestCanonicalIngestV2RejectsVersionKindDrift(t *testing.T) {
	for _, test := range []struct {
		version uint16
		kind    string
	}{
		{3, "access.v3"}, {2, AccessEnvelopeType}, {2, AccessWindowEnvelopeType}, {1, AccessEnvelopeTypeV2},
	} {
		decoded := authorityDecodedIngestV1(t)
		decoded.SchemaVersion, decoded.Kind = test.version, test.kind
		if _, err := CanonicalIngestDigestV1(decoded); err == nil {
			t.Fatalf("unsupported version/kind accepted: %d/%s", test.version, test.kind)
		}
	}
}
