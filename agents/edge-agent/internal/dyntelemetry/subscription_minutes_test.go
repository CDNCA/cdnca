package dyntelemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

type minuteSink struct {
	appended []eventspool.Envelope
	fail     error
}

func (sink *minuteSink) AppendBatch(_ context.Context, envelopes []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	if sink.fail != nil {
		return nil, sink.fail
	}
	sink.appended = append(sink.appended, envelopes...)
	return make([]eventspool.AppendResult, len(envelopes)), nil
}

func TestSubscriptionMinutesBindToLowestSiteAndRetryAfterSpoolFailure(t *testing.T) {
	const (
		node   = "44444444-4444-4444-8444-444444444444"
		tenant = "11111111-1111-4111-8111-111111111111"
		subA   = "40000000-0000-4000-8000-00000000000a"
		subB   = "40000000-0000-4000-8000-00000000000b"
		siteLo = "33333333-3333-4333-8333-000000000001"
		siteHi = "33333333-3333-4333-8333-000000000002"
		config = "77777777-7777-4777-8777-777777777777"
	)
	minute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	taken := 0
	clock := time.Now()
	source := &SubscriptionMinutes{NodeID: node, Now: func() time.Time { return clock },
		Sites: func() []MinuteSite {
			return []MinuteSite{
				{TenantID: tenant, SiteID: siteHi, PackageSubscriptionID: subA, ConfigVersionID: config, InstallationID: "inst"},
				{TenantID: tenant, SiteID: siteLo, PackageSubscriptionID: subA, ConfigVersionID: config, InstallationID: "inst"},
				{TenantID: tenant, SiteID: siteLo, PackageSubscriptionID: subB, ConfigVersionID: config}, // no installation
			}
		},
		Take: func(context.Context) ([]NodeMinute, error) {
			taken++
			if taken > 1 {
				return nil, nil // handed out once
			}
			return []NodeMinute{
				{SubscriptionID: subA, Minute: minute, SubscriptionMinuteCounters: edgeconfig.SubscriptionMinuteCounters{MaxConnections: 2}},
				{SubscriptionID: subB, Minute: minute},
			}, nil
		}}
	sink := &minuteSink{fail: errors.New("spool full")}
	if err := source.Sync(context.Background(), sink, 100); err == nil || len(source.pending) != 1 || source.Dropped() != 1 {
		t.Fatalf("pending=%d dropped=%d err=%v", len(source.pending), source.Dropped(), err)
	}
	sink.fail = nil
	clock = clock.Add(time.Second) // before the next take: only the retry
	if err := source.Sync(context.Background(), sink, 100); err != nil || len(sink.appended) != 1 || taken != 1 {
		t.Fatalf("appended=%d taken=%d err=%v", len(sink.appended), taken, err)
	}
	record := sink.appended[0]
	if record.SiteID != siteLo || record.SubscriptionMinute.SubscriptionID != subA || record.SubscriptionMinute.MaxConnections != 2 ||
		record.EventID != edgeconfig.SubscriptionMinuteEventID(node, subA, minute) {
		t.Fatalf("record = %+v", record)
	}
	clock = clock.Add(SubscriptionMinuteInterval)
	if err := source.Sync(context.Background(), sink, 100); err != nil || taken != 2 {
		t.Fatalf("second take: taken=%d err=%v", taken, err)
	}
}
