package statuspage

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Public builds the public page. It reads no session and checks no
// permission: the page is either public (settings.enabled) or ErrDisabled.
func (s *Service) Public(ctx context.Context) (PublicView, error) {
	now := s.clock()
	view := PublicView{Schema: PublicSchema, GeneratedAt: now, Components: []PublicComponent{}}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT enabled, title, description, show_logo FROM status_page_settings WHERE id = 1`).
			Scan(&enabled, &view.Title, &view.Description, &view.ShowLogo); err != nil {
			return err
		}
		if !enabled {
			return ErrDisabled
		}
		components, err := componentStates(ctx, tx, now)
		if err != nil {
			return err
		}
		history, err := loadHistory(ctx, tx, now)
		if err != nil {
			return err
		}
		statuses := []string{}
		for _, item := range components {
			days, total := history.series(item.ID, now)
			view.Components = append(view.Components, PublicComponent{ID: item.ID, Name: item.Name,
				Description: item.Description, Status: item.Status, Uptime90: total, History: days})
			statuses = append(statuses, item.Status)
		}
		open, err := loadIncidents(ctx, tx, `resolved_at IS NULL AND (kind = 'incident' OR scheduled_start <= $1)`, now)
		if err != nil {
			return err
		}
		view.Active = []Incident{}
		for _, item := range open {
			if item.Kind == KindMaintenance && !item.ScheduledEnd.After(now) {
				continue // window over without being closed: not shown as in progress
			}
			view.Active = append(view.Active, item)
			statuses = append(statuses, item.Impact)
		}
		if view.Upcoming, err = loadIncidents(ctx, tx, `kind = 'maintenance' AND resolved_at IS NULL AND scheduled_start > $1
			AND scheduled_start <= $1 + interval '7 days'`, now); err != nil {
			return err
		}
		if view.Recent, err = loadIncidents(ctx, tx, `resolved_at IS NOT NULL AND resolved_at > $1`, now.AddDate(0, 0, -RecentDays)); err != nil {
			return err
		}
		view.Status = worst(statuses...)
		return nil
	})
	return view, err
}

type dayRow struct{ sampled, degraded, outage, maintenance int }

type history map[uuid.UUID]map[string]dayRow

func loadHistory(ctx context.Context, tx pgx.Tx, now time.Time) (history, error) {
	rows, err := tx.Query(ctx, `SELECT component_id, day, sampled_minutes, degraded_minutes, outage_minutes, maintenance_minutes
		FROM status_page_daily WHERE day > ($1::timestamptz AT TIME ZONE 'UTC')::date - $2::int`, now, HistoryDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := history{}
	for rows.Next() {
		var id uuid.UUID
		var day time.Time
		var row dayRow
		if err := rows.Scan(&id, &day, &row.sampled, &row.degraded, &row.outage, &row.maintenance); err != nil {
			return nil, err
		}
		if result[id] == nil {
			result[id] = map[string]dayRow{}
		}
		result[id][day.Format(time.DateOnly)] = row
	}
	return result, rows.Err()
}

// series returns the last 90 UTC days, oldest first, and the 90-day uptime.
func (h history) series(id uuid.UUID, now time.Time) ([]PublicDay, *float64) {
	days := make([]PublicDay, 0, HistoryDays)
	var sampled, outage, maintenance int
	today := now.UTC().Truncate(24 * time.Hour)
	for offset := HistoryDays - 1; offset >= 0; offset-- {
		key := today.AddDate(0, 0, -offset).Format(time.DateOnly)
		row, found := h[id][key]
		if !found || row.sampled == 0 {
			days = append(days, PublicDay{Day: key, Status: "no_data"})
			continue
		}
		sampled, outage, maintenance = sampled+row.sampled, outage+row.outage, maintenance+row.maintenance
		days = append(days, PublicDay{Day: key, Status: dayStatus(row.degraded, row.outage, row.maintenance),
			Uptime: uptime(row.sampled, row.outage, row.maintenance)})
	}
	return days, uptime(sampled, outage, maintenance)
}

// Sample adds this minute's status of every component to its UTC day.
// Replicas sampling the same minute count it once (last_minute).
func (s *Service) Sample(ctx context.Context) error {
	now := s.clock()
	minute := now.Truncate(time.Minute)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		components, err := componentStates(ctx, tx, now)
		if err != nil || len(components) == 0 {
			return err
		}
		ids := make([]uuid.UUID, len(components))
		statuses := make([]string, len(components))
		for i, item := range components {
			ids[i], statuses[i] = item.ID, item.Status
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO status_page_daily AS d (component_id, day, sampled_minutes, degraded_minutes, outage_minutes,
			  maintenance_minutes, last_minute)
			SELECT sample.id, ($3::timestamptz AT TIME ZONE 'UTC')::date, 1,
			  (sample.status = 'degraded')::int, (sample.status = 'outage')::int, (sample.status = 'maintenance')::int, $3
			FROM unnest($1::uuid[], $2::text[]) AS sample(id, status)
			ON CONFLICT (component_id, day) DO UPDATE SET
			  sampled_minutes = d.sampled_minutes + 1,
			  degraded_minutes = d.degraded_minutes + EXCLUDED.degraded_minutes,
			  outage_minutes = d.outage_minutes + EXCLUDED.outage_minutes,
			  maintenance_minutes = d.maintenance_minutes + EXCLUDED.maintenance_minutes,
			  last_minute = EXCLUDED.last_minute
			WHERE d.last_minute < EXCLUDED.last_minute AND d.sampled_minutes < 1440`, ids, statuses, minute)
		return err
	})
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
