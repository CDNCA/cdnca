package statuspage

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// Day colour tiers, the same as the platform status page: uptime under 99% is an outage day,
	// 0.1% or more of the counted minutes degraded or out is a degraded day.
	dayOutageUptime  = 0.99
	dayDegradedShare = 0.001
	groupKeyPrefix   = "g-"
)

// Public builds the public page. It reads no session and checks no
// permission: the page is either public (settings.enabled) or ErrDisabled.
func (s *Service) Public(ctx context.Context) (PublicView, error) {
	now := s.clock()
	view := PublicView{Schema: PublicSchema, GeneratedAt: now, Components: []PublicComponent{},
		Active: []PublicIncident{}, Upcoming: []PublicIncident{}, Recent: []PublicIncident{}}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT enabled, title, description, show_logo FROM status_page_settings WHERE id = 1`).
			Scan(&enabled, &view.Title, &view.Description, &view.ShowLogo); err != nil {
			return err
		}
		if !enabled {
			return ErrDisabled
		}
		groups, err := loadGroups(ctx, tx)
		if err != nil {
			return err
		}
		components, err := s.componentStates(ctx, tx, now)
		if err != nil {
			return err
		}
		hist, err := loadHistory(ctx, tx, now)
		if err != nil {
			return err
		}
		open, err := loadIncidents(ctx, tx, `resolved_at IS NULL AND (kind = 'incident' OR scheduled_start <= $1)`, now)
		if err != nil {
			return err
		}
		active := []Incident{}
		for _, item := range open {
			if item.Kind == KindMaintenance && !item.ScheduledEnd.After(now) {
				continue // window over without being closed: not shown as in progress
			}
			active = append(active, item)
		}
		upcoming, err := loadIncidents(ctx, tx, `kind = 'maintenance' AND resolved_at IS NULL AND scheduled_start > $1
			AND scheduled_start <= $1 + interval '7 days'`, now)
		if err != nil {
			return err
		}
		recent, err := loadIncidents(ctx, tx, `resolved_at IS NOT NULL AND resolved_at > $1`, now.AddDate(0, 0, -RecentDays))
		if err != nil {
			return err
		}
		built := buildPublic(groups, components, hist, append(append([]Incident{}, active...), recent...), now)
		view.Components = built.components
		visible := built.visible
		for _, item := range active {
			view.Active = append(view.Active, publicIncident(item, visible))
		}
		for _, item := range upcoming {
			view.Upcoming = append(view.Upcoming, publicIncident(item, visible))
		}
		for _, item := range recent {
			view.Recent = append(view.Recent, publicIncident(item, visible))
		}
		statuses := built.statuses
		for _, item := range active {
			statuses = append(statuses, item.Impact)
		}
		view.Status = pageStatus(len(built.components) > 0, statuses)
		return nil
	})
	return view, err
}

// pageStatus is the worst real status; a page whose components all have nothing to judge by,
// and no open incident, is unconfigured; a page without components is operational (it shows
// the "no components" note instead).
func pageStatus(hasComponents bool, statuses []string) string {
	if len(statuses) == 0 {
		if hasComponents {
			return StatusUnconfigured
		}
		return StatusOperational
	}
	return worst(statuses...)
}

func loadGroups(ctx context.Context, q queryer) ([]AdminGroup, error) {
	rows, err := q.Query(ctx, `SELECT id, name, name_en, hidden FROM status_page_groups ORDER BY sort_order, id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (AdminGroup, error) {
		var item AdminGroup
		return item, row.Scan(&item.ID, &item.Name, &item.NameEN, &item.Hidden)
	})
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

// dayTier colours one day. A day without samples is no_data; minutes in maintenance are not counted.
func dayTier(row dayRow) string {
	counted := row.sampled - row.maintenance
	switch {
	case row.sampled <= 0:
		return "no_data"
	case counted <= 0:
		return StatusMaintenance
	case *uptime(row.sampled, row.outage, row.maintenance) < dayOutageUptime:
		return StatusOutage
	case float64(row.outage+row.degraded)/float64(counted) >= dayDegradedShare:
		return StatusDegraded
	case row.maintenance > 0:
		return StatusMaintenance
	}
	return StatusOperational
}

// merge folds a child's day into its group's: the worst child of the day decides, per kind of minute.
func (r dayRow) merge(o dayRow) dayRow {
	return dayRow{sampled: max(r.sampled, o.sampled), degraded: max(r.degraded, o.degraded),
		outage: max(r.outage, o.outage), maintenance: max(r.maintenance, o.maintenance)}
}

// series returns the last 90 UTC days of rows (oldest first) and the 90-day uptime.
// ids are the components behind the entry (one, or a group's children).
func (h history) series(ids []uuid.UUID, now time.Time, events func(day time.Time) []PublicEvent) ([]PublicDay, *float64) {
	days := make([]PublicDay, 0, HistoryDays)
	var sampled, outage, maintenance int
	today := now.UTC().Truncate(24 * time.Hour)
	for offset := HistoryDays - 1; offset >= 0; offset-- {
		date := today.AddDate(0, 0, -offset)
		key := date.Format(time.DateOnly)
		var row dayRow
		for _, id := range ids {
			row = row.merge(h[id][key])
		}
		day := PublicDay{Day: key, Status: dayTier(row)}
		day.Operational, day.NoData = daySplit(elapsedMinutes(date, now), row)
		if events != nil {
			day.Events = events(date)
		}
		if row.sampled > 0 {
			sampled, outage, maintenance = sampled+row.sampled, outage+row.outage, maintenance+row.maintenance
			day.Uptime = uptime(row.sampled, row.outage, row.maintenance)
			day.Sampled, day.Degraded, day.Outage, day.Maintenance = row.sampled, row.degraded, row.outage, row.maintenance
		}
		days = append(days, day)
	}
	return days, uptime(sampled, outage, maintenance)
}

// elapsedMinutes is how many minutes of the UTC day starting at from have passed at now (1440 for a past day).
func elapsedMinutes(from, now time.Time) int {
	return min(max(int(now.Sub(from)/time.Minute), 0), 1440)
}

// daySplit returns the operational and no-data minutes of a day. Degraded, outage and maintenance
// are clamped into the sampled minutes (a group takes the worst child per kind, so they can overlap).
func daySplit(elapsed int, row dayRow) (operational, noData int) {
	bad := min(row.degraded+row.outage+row.maintenance, row.sampled)
	return row.sampled - bad, max(elapsed-row.sampled, 0)
}
