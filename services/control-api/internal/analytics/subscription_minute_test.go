package analytics

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// RFC 4122 identities (edgeconfig validates version and variant).
const (
	minuteTenantID = "10000000-0000-4000-8000-000000000001"
	minuteSiteID   = "20000000-0000-4000-8000-000000000001"
	minuteNodeID   = "30000000-0000-4000-8000-000000000001"
)

type subscriptionMinuteWriterV1 struct {
	authorityOrderWriterV1
	minutes []SubscriptionMinute
}

func (writer *subscriptionMinuteWriterV1) WriteSubscriptionMinutes(_ context.Context, token string, minutes []SubscriptionMinute) error {
	writer.calls++
	writer.token = token
	writer.minutes = append(writer.minutes, minutes...)
	writer.history.record("clickhouse")
	return writer.err
}

// subscriptionMinutePayload is a gateway-bound record (subscription and
// installation filled in), as the gateway publishes it.
func subscriptionMinutePayload(t *testing.T, installationID string, minute time.Time, mutate func(*edgeconfig.SubscriptionMinuteEnvelope)) ([]byte, string) {
	t.Helper()
	event := edgeconfig.SubscriptionMinuteEvent{MetricVersion: 1, Minute: minute, TenantID: minuteTenantID,
		SubscriptionID: canonicalPackageSubscriptionIDV1, SiteID: minuteSiteID, NodeID: minuteNodeID, ConfigVersionID: testConfigVersionID,
		SubscriptionMinuteCounters: edgeconfig.SubscriptionMinuteCounters{MaxRequests: 7, MaxConnections: 3, MaxNewCPS: 2, MaxQPS: 40,
			BytesOut: 12345, PeakBPS: 98760}}
	event.EventID = edgeconfig.SubscriptionMinuteEventID(minuteNodeID, event.SubscriptionID, minute)
	envelope := edgeconfig.SubscriptionMinuteEnvelope{SchemaVersion: 1, Type: edgeconfig.SubscriptionMinuteType, ProducedAt: minute,
		TenantID: minuteTenantID, NodeID: minuteNodeID, Events: []edgeconfig.SubscriptionMinuteEvent{event}}
	envelope.MessageID = edgeconfig.SubscriptionMinuteMessageID(envelope)
	envelope.PackageSubscriptionID, envelope.InstallationID = event.SubscriptionID, installationID
	envelope.Events[0].PackageSubscriptionID, envelope.Events[0].InstallationID = event.SubscriptionID, installationID
	if mutate != nil {
		mutate(&envelope)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return payload, envelope.MessageID
}

func TestSubscriptionMinuteIngestDecodes(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 10, 0, time.UTC)
	payload, messageID := subscriptionMinutePayload(t, authorityGenerationV1().InstallationID, now.Add(-2*time.Minute).Truncate(time.Minute), nil)
	decoded, err := mustIngestDecoder(t, now, IngestDecoderConfig{}).Decode(IngestSubjectPrefix+"."+minuteNodeID, messageID, payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != SubscriptionMinuteEnvelopeType || len(decoded.SubscriptionMinutes) != 1 ||
		decoded.SubscriptionMinutes[0].MaxConnections != 3 || decoded.SubscriptionMinutes[0].PeakBPS != 98760 ||
		decoded.PackageSubscriptionID != canonicalPackageSubscriptionIDV1 {
		t.Fatalf("decoded = %#v", decoded)
	}
	receipt, err := NewIngestReceiptV1(authorityGenerationV1(), 41, decoded)
	if err != nil || receipt.CanonicalEventSHA256 == ([32]byte{}) {
		t.Fatalf("receipt = %#v, %v", receipt, err)
	}
	// The counters are part of the canonical digest.
	changed, _ := subscriptionMinutePayload(t, authorityGenerationV1().InstallationID, now.Add(-2*time.Minute).Truncate(time.Minute),
		func(e *edgeconfig.SubscriptionMinuteEnvelope) { e.Events[0].MaxQPS = 41 })
	other, err := mustIngestDecoder(t, now, IngestDecoderConfig{}).Decode(IngestSubjectPrefix+"."+minuteNodeID, messageID, changed)
	if err == nil {
		otherDigest, _ := CanonicalIngestDigestV1(other)
		if otherDigest == receipt.CanonicalEventSHA256 {
			t.Fatal("counters are not in the canonical digest")
		}
	}
}

func TestSubscriptionMinuteIngestRejectsForgery(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 10, 0, time.UTC)
	minute := now.Add(-2 * time.Minute).Truncate(time.Minute)
	tests := map[string]func(*edgeconfig.SubscriptionMinuteEnvelope){
		"unbound subscription": func(e *edgeconfig.SubscriptionMinuteEnvelope) {
			e.PackageSubscriptionID, e.Events[0].PackageSubscriptionID = "", ""
		},
		"subscription mismatch": func(e *edgeconfig.SubscriptionMinuteEnvelope) {
			e.Events[0].SubscriptionID = "40000000-0000-4000-8000-000000000002"
		},
		"wrong installation":     func(e *edgeconfig.SubscriptionMinuteEnvelope) { e.Events[0].InstallationID = "forged" },
		"forged event id":        func(e *edgeconfig.SubscriptionMinuteEnvelope) { e.Events[0].EventID = "subscription_minute_forged" },
		"unaligned minute":       func(e *edgeconfig.SubscriptionMinuteEnvelope) { e.Events[0].Minute = minute.Add(time.Second) },
		"negative counter":       func(e *edgeconfig.SubscriptionMinuteEnvelope) { e.Events[0].BytesOut = -1 },
		"two events":             func(e *edgeconfig.SubscriptionMinuteEnvelope) { e.Events = append(e.Events, e.Events[0]) },
		"message id not derived": func(e *edgeconfig.SubscriptionMinuteEnvelope) { e.Events[0].MaxRequests = 8 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			payload, messageID := subscriptionMinutePayload(t, authorityGenerationV1().InstallationID, minute, mutate)
			if _, err := mustIngestDecoder(t, now, IngestDecoderConfig{}).Decode(IngestSubjectPrefix+"."+minuteNodeID, messageID, payload); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSubscriptionMinuteProcessorWritesClickHouseBeforeAck(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 10, 0, time.UTC)
	generation := authorityGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	writer := &subscriptionMinuteWriterV1{authorityOrderWriterV1: authorityOrderWriterV1{history: history}}
	payload, messageID := subscriptionMinutePayload(t, generation.InstallationID, now.Add(-2*time.Minute).Truncate(time.Minute), nil)
	subject, _ := IngestSubject(minuteNodeID)
	base := &fakeIngestDelivery{subject: subject, messageID: messageID, attempts: 1, streamSequence: 41,
		installationID: generation.InstallationID, payload: payload}
	delivery := &authorityOrderDeliveryV1{fakeIngestDelivery: base, history: history}
	processor := authorityProcessorV1(t, now, writer, history, generation, &memoryIsolationSink{})
	result, err := processor.Process(context.Background(), []IngestDelivery{delivery})
	if err != nil {
		t.Fatal(err)
	}
	if writer.calls != 1 || len(writer.minutes) != 1 || writer.minutes[0].InstallationID != generation.InstallationID ||
		writer.token != history.receipts[0].ClickHouseToken || result.Acknowledged != 1 || delivery.ackCount != 1 {
		t.Fatalf("result=%#v writer=%#v", result, writer)
	}
	if ops := authorityOperationsV1(history); ops[:len("received,clickhouse")] != "received,clickhouse" {
		t.Fatalf("operations = %q", ops)
	}
}
