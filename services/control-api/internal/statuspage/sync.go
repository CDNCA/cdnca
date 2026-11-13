package statuspage

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// syncLineGroups gives the page a component for every line group, so it
// works as soon as it is public. It runs in the caller's transaction and
// does nothing while the page is not public.
//
//   - First run, no component yet: one line_group component per group, named
//     after the group.
//   - First run with components: the existing groups are only recorded, so the
//     administrator's list stays as it is.
//   - Later runs: only groups created since then are added. A group whose
//     component the administrator removed is recorded as seen and stays out.
//
// It returns whether the component list changed.
func syncLineGroups(ctx context.Context, tx pgx.Tx, now time.Time) (bool, error) {
	var enabled, synced bool
	if err := tx.QueryRow(ctx, `SELECT enabled, lines_synced_at IS NOT NULL FROM status_page_settings WHERE id = 1 FOR UPDATE`).
		Scan(&enabled, &synced); err != nil {
		return false, err
	}
	if !enabled {
		return false, nil
	}
	var existing int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM status_page_components`).Scan(&existing); err != nil {
		return false, err
	}
	rows, err := tx.Query(ctx, `SELECT g.id, g.tenant_scope_id, g.name FROM node_line_groups g
		WHERE g.deleted_at IS NULL AND g.purpose = 'general'
		  AND EXISTS (SELECT 1 FROM access_scopes s WHERE s.id = g.tenant_scope_id AND s.kind = 'platform' AND s.tenant_id IS NULL)
		  AND NOT EXISTS (SELECT 1 FROM status_page_line_group_seen v WHERE v.line_group_id = g.id)
		ORDER BY g.created_at, g.id`)
	if err != nil {
		return false, err
	}
	type group struct {
		id, scope uuid.UUID
		name      string
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (group, error) {
		var item group
		return item, row.Scan(&item.id, &item.scope, &item.name)
	})
	if err != nil {
		return false, err
	}
	add := !synced && existing == 0 || synced
	changed := false
	if add && len(groups) > 0 {
		names, err := componentNames(ctx, tx)
		if err != nil {
			return false, err
		}
		var order int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(sort_order) + 1, 0) FROM status_page_components`).Scan(&order); err != nil {
			return false, err
		}
		// New line-group components join the access network group when the administrator has one.
		var access *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM status_page_groups WHERE lower(name) = lower($1)`, accessGroupName).Scan(&access); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
		for _, item := range groups {
			if existing >= MaxComponents || order > 1000 {
				break // recorded as seen only once a component exists for it
			}
			id, err := uuid.NewV7()
			if err != nil {
				return false, err
			}
			name := uniqueName(componentNameFrom(item.name), names)
			if _, err := tx.Exec(ctx, `INSERT INTO status_page_components
				(id, name, description, source, line_group_scope_id, line_group_id, group_id, manual_status, sort_order, created_at, updated_at)
				VALUES ($1, $2, '', 'line_group', $3, $4, $7, 'operational', $5, $6, $6)`,
				id, name, item.scope, item.id, order, now, access); err != nil {
				return false, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO status_page_line_group_seen (line_group_id, seen_at) VALUES ($1, $2)
				ON CONFLICT DO NOTHING`, item.id, now); err != nil {
				return false, err
			}
			names[strings.ToLower(name)] = true
			existing++
			order++
			changed = true
		}
	} else if len(groups) > 0 {
		ids := make([]uuid.UUID, len(groups))
		for i, item := range groups {
			ids[i] = item.id
		}
		if _, err := tx.Exec(ctx, `INSERT INTO status_page_line_group_seen (line_group_id, seen_at)
			SELECT unnest($1::uuid[]), $2 ON CONFLICT DO NOTHING`, ids, now); err != nil {
			return false, err
		}
	}
	if !synced {
		if _, err := tx.Exec(ctx, `UPDATE status_page_settings SET lines_synced_at = $1 WHERE id = 1`, now); err != nil {
			return false, err
		}
	}
	if changed {
		if _, err := tx.Exec(ctx, `UPDATE status_page_settings SET revision = revision + 1, updated_at = $1 WHERE id = 1`, now); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func componentNames(ctx context.Context, tx pgx.Tx) (map[string]bool, error) {
	rows, err := tx.Query(ctx, `SELECT lower(name) FROM status_page_components`)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(list))
	for _, name := range list {
		names[name] = true
	}
	return names, nil
}

// componentNameFrom makes a line group name fit a component name: no control
// characters, trimmed, at most 64 characters, never empty.
func componentNameFrom(value string) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(value, "")))
	if utf8.RuneCountInString(value) > 64 {
		value = strings.TrimSpace(string([]rune(value)[:64]))
	}
	if value == "" {
		return "-"
	}
	return value
}

// uniqueName appends " 2", " 3"... (inside the 64 characters) until the
// lower-cased name is free.
func uniqueName(base string, taken map[string]bool) string {
	if !taken[strings.ToLower(base)] {
		return base
	}
	for n := 2; ; n++ {
		suffix := " " + strconv.Itoa(n)
		head := []rune(base)
		if len(head)+len(suffix) > 64 {
			head = head[:64-len(suffix)]
		}
		candidate := strings.TrimSpace(string(head)) + suffix
		if !taken[strings.ToLower(candidate)] {
			return candidate
		}
	}
}
