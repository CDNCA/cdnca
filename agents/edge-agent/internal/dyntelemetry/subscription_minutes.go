package dyntelemetry

import (
	"context"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// SubscriptionMinuteInterval: how often the finished minutes are taken from
// the workers (they keep a minute for 5 minutes, cdnca_limits STATS_TTL).
const SubscriptionMinuteInterval = 15 * time.Second

// MinuteSite is an active site the minutes of its package subscription can
// be bound to (the scope must have a telemetry installation).
type MinuteSite struct {
	TenantID, SiteID, PackageSubscriptionID, ConfigVersionID, InstallationID string
}

// NodeMinute is one finished minute cdnca_limits handed out.
type NodeMinute struct {
	SubscriptionID string
	Minute         time.Time
	edgeconfig.SubscriptionMinuteCounters
}

// SubscriptionMinutes moves cdnca_limits' finished minutes into the
// telemetry spool (ADR 0012 §6.2). Each record is bound to one active site
// of its subscription (the lowest site ID with a telemetry installation):
// the gateway authorises it against that site. A subscription without such
// a site (no telemetry installation, or no live package subscription on its
// sites) cannot be attributed and its minutes are dropped and counted.
//
// The workers hand a minute out once; the records taken but not yet
// appended stay pending and are retried (a full spool). A crash of the agent
// between taking and appending loses them.
type SubscriptionMinutes struct {
	NodeID string
	Take   func(context.Context) ([]NodeMinute, error)
	Sites  func() []MinuteSite
	Now    func() time.Time

	pending []eventspool.Envelope
	last    time.Time
	dropped uint64
}

// Sync appends what is pending and, at most every
// SubscriptionMinuteInterval, takes the finished minutes.
func (source *SubscriptionMinutes) Sync(ctx context.Context, sink eventspool.BatchSink, maxBatch int) error {
	if err := source.flush(ctx, sink, maxBatch); err != nil {
		return err
	}
	now := time.Now()
	if source.Now != nil {
		now = source.Now()
	}
	if !source.last.IsZero() && now.Sub(source.last) >= 0 && now.Sub(source.last) < SubscriptionMinuteInterval {
		return nil
	}
	source.last = now
	minutes, err := source.Take(ctx)
	if err != nil || len(minutes) == 0 {
		return err
	}
	sites := minuteSites(source.Sites())
	for _, minute := range minutes {
		site, ok := sites[minute.SubscriptionID]
		var record eventspool.Envelope
		if ok {
			event := edgeconfig.SubscriptionMinuteEvent{MetricVersion: 1, Minute: minute.Minute, TenantID: site.TenantID,
				SubscriptionID: minute.SubscriptionID, SiteID: site.SiteID, NodeID: source.NodeID, ConfigVersionID: site.ConfigVersionID,
				SubscriptionMinuteCounters: minute.SubscriptionMinuteCounters}
			event.EventID = edgeconfig.SubscriptionMinuteEventID(source.NodeID, minute.SubscriptionID, minute.Minute)
			record, err = eventspool.NewSubscriptionMinuteRecord(event)
		}
		if !ok || err != nil {
			source.dropped++
			slog.Warn("subscription minute cannot be attributed; dropped", "subscription_id", minute.SubscriptionID,
				"minute", minute.Minute, "bound_site", ok, "dropped_total", source.dropped)
			continue
		}
		source.pending = append(source.pending, record)
	}
	return source.flush(ctx, sink, maxBatch)
}

// Dropped counts the minutes that could not be attributed.
func (source *SubscriptionMinutes) Dropped() uint64 { return source.dropped }

func (source *SubscriptionMinutes) flush(ctx context.Context, sink eventspool.BatchSink, maxBatch int) error {
	for len(source.pending) > 0 {
		batch := source.pending[:min(len(source.pending), max(maxBatch, 1))]
		if _, err := sink.AppendBatch(ctx, batch); err != nil {
			return err
		}
		source.pending = source.pending[len(batch):]
	}
	source.pending = nil
	return nil
}

func minuteSites(sites []MinuteSite) map[string]MinuteSite {
	result := make(map[string]MinuteSite)
	for _, site := range sites {
		if site.PackageSubscriptionID == "" || site.InstallationID == "" {
			continue
		}
		if current, ok := result[site.PackageSubscriptionID]; !ok || site.SiteID < current.SiteID {
			result[site.PackageSubscriptionID] = site
		}
	}
	return result
}
