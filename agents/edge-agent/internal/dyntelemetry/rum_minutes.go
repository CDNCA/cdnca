package dyntelemetry

import (
	"context"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// NodeRUMMinute is one finished site minute cdnca_rum handed out.
type NodeRUMMinute struct {
	SiteID string
	Minute time.Time
	edgeconfig.RUMMinuteData
}

// RUMMinutes moves cdnca_rum's finished site minutes into the telemetry
// spool, each bound to its site. A site the node no longer
// serves, or whose scope has no telemetry installation, cannot be
// attributed: its minutes are dropped and counted. Same take-once and
// pending rules as SubscriptionMinutes.
type RUMMinutes struct {
	NodeID string
	Take   func(context.Context) ([]NodeRUMMinute, error)
	Sites  func() []MinuteSite
	Now    func() time.Time

	pending []eventspool.Envelope
	last    time.Time
	dropped uint64
}

// Sync appends what is pending and, at most every
// SubscriptionMinuteInterval, takes the finished minutes.
func (source *RUMMinutes) Sync(ctx context.Context, sink eventspool.BatchSink, maxBatch int) error {
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
	active := source.Sites()
	if len(active) == 0 {
		return nil
	}
	minutes, err := source.Take(ctx)
	if err != nil || len(minutes) == 0 {
		return err
	}
	sites := make(map[string]MinuteSite, len(active))
	for _, site := range active {
		if site.InstallationID != "" {
			sites[site.SiteID] = site
		}
	}
	for _, minute := range minutes {
		site, ok := sites[minute.SiteID]
		var record eventspool.Envelope
		if ok {
			event := edgeconfig.RUMMinuteEvent{MetricVersion: 1, Minute: minute.Minute, TenantID: site.TenantID,
				SiteID: site.SiteID, NodeID: source.NodeID, ConfigVersionID: site.ConfigVersionID, RUMMinuteData: minute.RUMMinuteData}
			event.EventID = edgeconfig.RUMMinuteEventID(source.NodeID, site.SiteID, minute.Minute)
			record, err = eventspool.NewRUMMinuteRecord(event)
		}
		if !ok || err != nil {
			source.dropped++
			slog.Warn("RUM minute cannot be attributed; dropped", "site_id", minute.SiteID, "minute", minute.Minute,
				"bound_site", ok, "dropped_total", source.dropped)
			continue
		}
		source.pending = append(source.pending, record)
	}
	return source.flush(ctx, sink, maxBatch)
}

// Dropped counts the minutes that could not be attributed.
func (source *RUMMinutes) Dropped() uint64 { return source.dropped }

func (source *RUMMinutes) flush(ctx context.Context, sink eventspool.BatchSink, maxBatch int) error {
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
