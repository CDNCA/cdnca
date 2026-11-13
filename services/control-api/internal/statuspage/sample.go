package statuspage

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// minGapMinutes: this many missed minutes in a row mean the control API was not running
// (a restart of a few seconds is not an outage). The missed minutes of control_api are
// recorded as outage once it is back; other sources have no such evidence and stay gaps.
const minGapMinutes = 3

type sampleRow struct {
	id                                     uuid.UUID
	sampled, degraded, outage, maintenance int
}

// Sample adds this minute's status of every judged component to its UTC day. A component
// with nothing to judge by (unconfigured) gets no sample: its day stays "no data" instead of
// reading as 0% or as an outage. Replicas sampling the same minute count it once (last_minute).
func (s *Service) Sample(ctx context.Context) error {
	now := s.clock()
	minute := now.Truncate(time.Minute)
	if err := s.runProbes(ctx, s.pool, now); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := syncLineGroups(ctx, tx, now); err != nil {
			return err
		}
		if _, err := seedDefaults(ctx, tx, now); err != nil {
			return err
		}
		components, err := s.componentStates(ctx, tx, now)
		if err != nil || len(components) == 0 {
			return err
		}
		rows := make([]sampleRow, 0, len(components))
		controlAPI := []uuid.UUID{}
		for _, item := range components {
			if item.Status == StatusUnconfigured {
				continue
			}
			row := sampleRow{id: item.ID, sampled: 1}
			switch item.Status {
			case StatusDegraded:
				row.degraded = 1
			case StatusOutage:
				row.outage = 1
			case StatusMaintenance:
				row.maintenance = 1
			}
			rows = append(rows, row)
			if item.Source == SourceControlAPI {
				controlAPI = append(controlAPI, item.ID)
			}
		}
		if len(rows) == 0 {
			return nil
		}
		if err := recordDetail(ctx, tx, components, minute); err != nil {
			return err
		}
		if err := fillGaps(ctx, tx, rows, controlAPI, minute); err != nil {
			return err
		}
		ids := make([]uuid.UUID, len(rows))
		sampled, degraded, outage, maintenance := make([]int32, len(rows)), make([]int32, len(rows)), make([]int32, len(rows)), make([]int32, len(rows))
		for i, row := range rows {
			ids[i], sampled[i], degraded[i], outage[i], maintenance[i] = row.id, int32(row.sampled), int32(row.degraded), int32(row.outage), int32(row.maintenance)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO status_page_daily AS d (component_id, day, sampled_minutes, degraded_minutes, outage_minutes,
			  maintenance_minutes, last_minute)
			SELECT sample.id, ($6::timestamptz AT TIME ZONE 'UTC')::date, sample.sampled, sample.degraded, sample.outage,
			  sample.maintenance, $6
			FROM unnest($1::uuid[], $2::int[], $3::int[], $4::int[], $5::int[]) AS sample(id, sampled, degraded, outage, maintenance)
			ON CONFLICT (component_id, day) DO UPDATE SET
			  sampled_minutes = d.sampled_minutes + EXCLUDED.sampled_minutes,
			  degraded_minutes = d.degraded_minutes + EXCLUDED.degraded_minutes,
			  outage_minutes = d.outage_minutes + EXCLUDED.outage_minutes,
			  maintenance_minutes = d.maintenance_minutes + EXCLUDED.maintenance_minutes,
			  last_minute = EXCLUDED.last_minute
			WHERE d.last_minute < EXCLUDED.last_minute AND d.sampled_minutes + EXCLUDED.sampled_minutes <= 1440`,
			ids, sampled, degraded, outage, maintenance, minute)
		return err
	})
}

// fillGaps adds the minutes the control API was not running (today only) as outage to the
// control_api rows, so a stopped API reads as an outage and not as a day without data.
func fillGaps(ctx context.Context, tx pgx.Tx, rows []sampleRow, controlAPI []uuid.UUID, minute time.Time) error {
	if len(controlAPI) == 0 {
		return nil
	}
	found, err := tx.Query(ctx, `SELECT component_id, last_minute, sampled_minutes FROM status_page_daily
		WHERE component_id = ANY($1::uuid[]) AND day = ($2::timestamptz AT TIME ZONE 'UTC')::date`, controlAPI, minute)
	if err != nil {
		return err
	}
	type last struct {
		at      time.Time
		sampled int
	}
	seen := map[uuid.UUID]last{}
	for found.Next() {
		var id uuid.UUID
		var item last
		if err := found.Scan(&id, &item.at, &item.sampled); err != nil {
			found.Close()
			return err
		}
		seen[id] = item
	}
	found.Close()
	if err := found.Err(); err != nil {
		return err
	}
	for i := range rows {
		previous, known := seen[rows[i].id]
		if !known {
			continue
		}
		missed := int(minute.Sub(previous.at)/time.Minute) - 1
		if missed < minGapMinutes {
			continue
		}
		missed = min(missed, 1440-previous.sampled-rows[i].sampled)
		if missed > 0 {
			rows[i].sampled += missed
			rows[i].outage += missed
		}
	}
	return nil
}

// Prune drops daily rows older than the retention.
func (s *Service) Prune(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM status_page_daily WHERE day < ($1::timestamptz AT TIME ZONE 'UTC')::date - $2::int`,
		s.clock(), RetentionDays)
	return err
}

// Run samples every minute until ctx ends and prunes once an hour.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	lastPrune := time.Time{}
	for {
		if err := s.Sample(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("status page sample failed", "error", err)
		}
		if time.Since(lastPrune) >= time.Hour {
			if _, err := s.pool.Exec(ctx, `DELETE FROM status_page_samples WHERE minute < $1`, s.clock().Add(-sampleRetention)); err != nil && ctx.Err() == nil {
				slog.Warn("status page samples prune failed", "error", err)
			}
			if err := s.Prune(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("status page prune failed", "error", err)
			}
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sampleRetention is how long the per-minute exception detail is kept.
const sampleRetention = 30 * 24 * time.Hour

// recordDetail writes one row for every component that is degraded or in outage this minute, with
// the reason (probe error, available share, offline node). It is for troubleshooting and for
// writing incidents; no page shows it. Another replica's row for the same minute stays.
func recordDetail(ctx context.Context, tx pgx.Tx, components []AdminComponent, minute time.Time) error {
	var ids []uuid.UUID
	var statuses, reasons []string
	for _, item := range components {
		if item.Status == StatusDegraded || item.Status == StatusOutage {
			ids, statuses, reasons = append(ids, item.ID), append(statuses, item.Status), append(reasons, item.reason)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO status_page_samples (component_id, minute, status, reason)
		SELECT sample.id, $4, sample.status, sample.reason FROM unnest($1::uuid[], $2::text[], $3::text[]) AS sample(id, status, reason)
		ON CONFLICT (component_id, minute) DO NOTHING`, ids, statuses, reasons, minute)
	return err
}
