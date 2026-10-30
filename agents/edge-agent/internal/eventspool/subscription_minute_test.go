package eventspool

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const minuteSubscription = "40000000-0000-4000-8000-000000000001"

func subscriptionMinuteTestEvent(minute time.Time) edgeconfig.SubscriptionMinuteEvent {
	event := edgeconfig.SubscriptionMinuteEvent{MetricVersion: 1, Minute: minute, TenantID: tenantOne, SubscriptionID: minuteSubscription,
		SiteID: siteOne, NodeID: nodeOne, ConfigVersionID: "77777777-7777-4777-8777-777777777777",
		SubscriptionMinuteCounters: edgeconfig.SubscriptionMinuteCounters{MaxRequests: 5, MaxConnections: 3, MaxNewCPS: 2, MaxQPS: 11, BytesOut: 4096, PeakBPS: 32768}}
	event.EventID = edgeconfig.SubscriptionMinuteEventID(nodeOne, minuteSubscription, minute)
	return event
}

// A minute survives the spool, a second append of the same minute is the
// same record, and the publication carries the counters and no binding.
func TestSubscriptionMinuteSurvivesSpoolDeduplicatedAndPublishedAlone(t *testing.T) {
	spool := newTestSpool(t, testConfig(t.TempDir()))
	minute := spool.config.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	first, err := NewSubscriptionMinuteRecord(subscriptionMinuteTestEvent(minute))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSubscriptionMinuteRecord(subscriptionMinuteTestEvent(minute.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.AppendBatch(t.Context(), []Envelope{first, second}); err != nil {
		t.Fatal(err)
	}
	results, err := spool.AppendBatch(t.Context(), []Envelope{first})
	if err != nil || len(results) != 1 || !results[0].Duplicate {
		t.Fatalf("re-append = %+v %v", results, err)
	}
	capture := &windowCapturePublisher{}
	result, err := spool.Flush(t.Context(), capture, 10)
	if err != nil || result.Published != 2 || len(capture.records) != 2 {
		t.Fatalf("flush = %+v %v (%d)", result, err, len(capture.records))
	}
	for _, publication := range capture.records {
		if !ValidSubscriptionMinutePublication(publication) || ValidAccessWindowPublication(publication) {
			t.Fatal("publication not recognised as a subscription minute")
		}
	}
	var envelope edgeconfig.SubscriptionMinuteEnvelope
	if err := json.Unmarshal(capture.records[0].Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	got := envelope.Events[0]
	if got.SubscriptionID != minuteSubscription || got.MaxConnections != 3 || got.PeakBPS != 32768 ||
		envelope.InstallationID != "" || got.PackageSubscriptionID != "" || !got.Minute.Equal(minute) {
		t.Fatalf("published = %+v", envelope)
	}
	// Acknowledged records are gone.
	again := &windowCapturePublisher{}
	if result, err := spool.Flush(t.Context(), again, 10); err != nil || result.Published != 0 {
		t.Fatalf("after ack: %+v %v", result, err)
	}
}

func TestSubscriptionMinuteRecordRejectsInvalid(t *testing.T) {
	minute := time.Now().UTC().Truncate(time.Minute)
	for name, mutate := range map[string]func(*edgeconfig.SubscriptionMinuteEvent){
		"bound installation": func(e *edgeconfig.SubscriptionMinuteEvent) { e.InstallationID = "x" },
		"bound subscription": func(e *edgeconfig.SubscriptionMinuteEvent) { e.PackageSubscriptionID = minuteSubscription },
		"unaligned":          func(e *edgeconfig.SubscriptionMinuteEvent) { e.Minute = minute.Add(time.Second) },
		"event id":           func(e *edgeconfig.SubscriptionMinuteEvent) { e.EventID = "subscription_minute_x" },
		"negative":           func(e *edgeconfig.SubscriptionMinuteEvent) { e.MaxQPS = -1 },
		"subscription":       func(e *edgeconfig.SubscriptionMinuteEvent) { e.SubscriptionID = "not-a-uuid" },
	} {
		event := subscriptionMinuteTestEvent(minute)
		mutate(&event)
		if _, err := NewSubscriptionMinuteRecord(event); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
