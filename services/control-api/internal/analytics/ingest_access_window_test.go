package analytics

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestAccessWindowIngestDecodesAuthorityBoundCoverage(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 10, 0, time.UTC)
	messageID := "access-window-message"
	payload := accessWindowIngestPayload(t, messageID, authorityGenerationV1().InstallationID,
		canonicalPackageSubscriptionIDV1, now.Add(-time.Hour).Truncate(time.Hour), nil)
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	decoded, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, messageID, payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != AccessWindowEnvelopeType || decoded.InstallationID != authorityGenerationV1().InstallationID ||
		decoded.PackageSubscriptionID != canonicalPackageSubscriptionIDV1 || len(decoded.AccessWindowContributions) != 1 ||
		len(decoded.AccessEvents) != 0 || len(decoded.SecurityEvents) != 0 {
		t.Fatalf("decoded access window = %#v", decoded)
	}
	contribution := decoded.AccessWindowContributions[0]
	if contribution.SourceWatermark != 7 || contribution.DependencyState != "ready" ||
		contribution.EvidenceSHA256 == ([32]byte{}) || !contribution.FinalizedThrough.Equal(contribution.WindowEnd) {
		t.Fatalf("decoded contribution = %#v", contribution)
	}
	receipt, err := NewIngestReceiptV1(authorityGenerationV1(), 41, decoded)
	if err != nil || len(receipt.AccessWindowContributions) != 1 || receipt.CanonicalEventSHA256 == ([32]byte{}) {
		t.Fatalf("access window receipt = %#v, error=%v", receipt, err)
	}
}

func TestAccessWindowIngestRejectsForgedOrIncompleteCoverage(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 10, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{name: "missing installation", mutate: func(envelope, _ map[string]any) { envelope["installation_id"] = "" }},
		{name: "wrong event installation", mutate: func(_, event map[string]any) { event["installation_id"] = "forged" }},
		{name: "wrong subscription", mutate: func(_, event map[string]any) {
			event["package_subscription_id"] = "40000000-0000-4000-8000-000000000002"
		}},
		{name: "unaligned window", mutate: func(_, event map[string]any) { event["window_start"] = now.Add(-time.Hour + time.Minute) }},
		{name: "zero watermark", mutate: func(_, event map[string]any) { event["source_watermark"] = float64(0) }},
		{name: "zero evidence", mutate: func(_, event map[string]any) {
			event["evidence_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{name: "unknown field", mutate: func(envelope, _ map[string]any) { envelope["future_field"] = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := accessWindowIngestPayload(t, "access-window-invalid", authorityGenerationV1().InstallationID,
				canonicalPackageSubscriptionIDV1, now.Add(-time.Hour).Truncate(time.Hour), test.mutate)
			decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
			if _, err := decoder.Decode(IngestSubjectPrefix+"."+testNodeID, "access-window-invalid", payload); err == nil {
				t.Fatal("invalid access coverage was accepted")
			}
		})
	}
}

func TestAccessWindowProcessorPersistsReceiptBeforeAckWithoutClickHouseWrite(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 10, 0, time.UTC)
	generation := authorityGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	writer := &authorityOrderWriterV1{history: history}
	messageID := "access-window-processor"
	subject, _ := IngestSubject(testNodeID)
	base := &fakeIngestDelivery{
		subject: subject, messageID: messageID, attempts: 1, streamSequence: 41,
		installationID: generation.InstallationID,
		payload: accessWindowIngestPayload(t, messageID, generation.InstallationID,
			canonicalPackageSubscriptionIDV1, now.Add(-time.Hour).Truncate(time.Hour), nil),
	}
	delivery := &authorityOrderDeliveryV1{fakeIngestDelivery: base, history: history}
	processor := authorityProcessorV1(t, now, writer, history, generation, &memoryIsolationSink{})
	result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
	if err != nil {
		t.Fatal(err)
	}
	if writer.calls != 0 || result.WriteBatches != 0 || result.Acknowledged != 1 || delivery.ackCount != 1 ||
		len(history.receipts) != 1 || len(history.receipts[0].AccessWindowContributions) != 1 ||
		authorityOperationsV1(history) != "received,pg-prepared,recovery-scheduled,nats-ack,broker-ack-observed" {
		t.Fatalf("result=%#v writer=%#v history=%#v operations=%q", result, writer, history, authorityOperationsV1(history))
	}
}

func accessWindowIngestPayload(
	t *testing.T,
	messageID, installationID, packageSubscriptionID string,
	windowStart time.Time,
	mutate func(map[string]any, map[string]any),
) []byte {
	t.Helper()
	windowEnd := windowStart.Add(time.Hour)
	event := map[string]any{
		"metric_version":          1,
		"event_id":                "access_window_10d5dd5cb6a19e1ed1a5f809236891337457c1a582f471226f64162a23568b2e",
		"window_start":            windowStart,
		"window_end":              windowEnd,
		"tenant_id":               testTenantID,
		"package_subscription_id": packageSubscriptionID,
		"site_id":                 testSiteID,
		"node_id":                 testNodeID,
		"installation_id":         installationID,
		"config_version_id":       testConfigVersionID,
		"host":                    "window.example.test",
		"listen_port":             443,
		"source_watermark":        7,
		"finalized_through":       windowEnd,
		"dependency_state":        "ready",
		"evidence_sha256":         "c1d5b12d118a967c6d7a72c9b029b6d35ee2142e607e2b7a44fa75d577b55d35",
	}
	envelope := map[string]any{
		"schema_version":          1,
		"type":                    AccessWindowEnvelopeType,
		"message_id":              messageID,
		"produced_at":             windowEnd,
		"tenant_id":               testTenantID,
		"installation_id":         installationID,
		"node_id":                 testNodeID,
		"package_subscription_id": packageSubscriptionID,
		"events":                  []any{event},
	}
	if mutate != nil {
		mutate(envelope, event)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
