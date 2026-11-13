package statuspage

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// defaultGroup is one recommended group and the components it starts with.
// The line-group components of the first group come from syncLineGroups.
type defaultGroup struct {
	name, nameEN string
	components   []defaultComponent
}

type defaultComponent struct {
	name, nameEN, source string
}

// recommended is what a new status page shows: access network (the line groups), console and
// API, nodes, DNS and certificates. The administrator may rename, regroup, hide or delete any of it.
var recommended = []defaultGroup{
	{name: "访问网络", nameEN: "Access network"},
	{name: "控制台与 API", nameEN: "Console and API", components: []defaultComponent{
		{"主控 API", "Control API", SourceControlAPI},
		{"用户控制台", "User console", SourceWebConsole},
	}},
	{name: "节点", nameEN: "Nodes", components: []defaultComponent{
		{"节点网关", "Node gateway", SourceGateway},
		{"节点总体在线率", "Node availability", SourceNodeOverall},
	}},
	{name: "DNS 与证书", nameEN: "DNS and certificates", components: []defaultComponent{
		{"DNS 解析同步", "DNS sync", SourceDNSSync},
		{"证书签发与续期", "Certificate issuance and renewal", SourceCertIssue},
	}},
}

// accessGroupName is the group new line-group components join.
const accessGroupName = "访问网络"

// seedDefaults adds the recommended groups and components once, after the page is public
// (defaults_seeded_at). It never touches what the administrator already has: existing
// components stay where they are, names already taken are skipped, line-group components
// without a group join the access network group. It returns whether anything changed.
func seedDefaults(ctx context.Context, tx pgx.Tx, now time.Time) (bool, error) {
	var enabled, seeded bool
	if err := tx.QueryRow(ctx, `SELECT enabled, defaults_seeded_at IS NOT NULL FROM status_page_settings WHERE id = 1 FOR UPDATE`).
		Scan(&enabled, &seeded); err != nil {
		return false, err
	}
	if !enabled || seeded {
		return false, nil
	}
	var components, groups int
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM status_page_components)::int, (SELECT count(*) FROM status_page_groups)::int`).
		Scan(&components, &groups); err != nil {
		return false, err
	}
	var order, groupOrder int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(sort_order) + 1, 0) FROM status_page_components`).Scan(&order); err != nil {
		return false, err
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(sort_order) + 1, 0) FROM status_page_groups`).Scan(&groupOrder); err != nil {
		return false, err
	}
	names, err := componentNames(ctx, tx)
	if err != nil {
		return false, err
	}
	groupIDs := map[string]uuid.UUID{}
	existing, err := tx.Query(ctx, `SELECT lower(name), id FROM status_page_groups`)
	if err != nil {
		return false, err
	}
	for existing.Next() {
		var name string
		var id uuid.UUID
		if err := existing.Scan(&name, &id); err != nil {
			existing.Close()
			return false, err
		}
		groupIDs[name] = id
	}
	existing.Close()
	if err := existing.Err(); err != nil {
		return false, err
	}
	changed := false
	for _, group := range recommended {
		id, found := groupIDs[strings.ToLower(group.name)]
		if !found {
			if len(groupIDs) >= MaxGroups || groupOrder > 1000 {
				continue
			}
			var err error
			if id, err = uuid.NewV7(); err != nil {
				return false, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO status_page_groups (id, name, name_en, sort_order, hidden, created_at, updated_at)
				VALUES ($1, $2, $3, $4, false, $5, $5)`, id, group.name, group.nameEN, groupOrder, now); err != nil {
				return false, err
			}
			groupIDs[strings.ToLower(group.name)] = id
			groupOrder++
			changed = true
		}
		for _, item := range group.components {
			if components >= MaxComponents || order > 1000 || names[strings.ToLower(item.name)] {
				continue
			}
			itemID, err := uuid.NewV7()
			if err != nil {
				return false, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO status_page_components
				(id, name, name_en, description, source, group_id, manual_status, sort_order, created_at, updated_at)
				VALUES ($1, $2, $3, '', $4, $5, 'operational', $6, $7, $7)`, itemID, item.name, item.nameEN, item.source, id, order, now); err != nil {
				return false, err
			}
			names[strings.ToLower(item.name)] = true
			components++
			order++
			changed = true
		}
	}
	if id, found := groupIDs[strings.ToLower(accessGroupName)]; found {
		tag, err := tx.Exec(ctx, `UPDATE status_page_components SET group_id = $1, updated_at = $2
			WHERE source = 'line_group' AND group_id IS NULL`, id, now)
		if err != nil {
			return false, err
		}
		changed = changed || tag.RowsAffected() > 0
	}
	if _, err := tx.Exec(ctx, `UPDATE status_page_settings SET defaults_seeded_at = $1 WHERE id = 1`, now); err != nil {
		return false, err
	}
	if changed {
		if _, err := tx.Exec(ctx, `UPDATE status_page_settings SET revision = revision + 1, updated_at = $1 WHERE id = 1`, now); err != nil {
			return false, err
		}
	}
	return changed, nil
}

// markSeeded records that the administrator has curated the list, so no default is added later.
func markSeeded(ctx context.Context, tx pgx.Tx, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE status_page_settings SET defaults_seeded_at = COALESCE(defaults_seeded_at, $1) WHERE id = 1`, now)
	return err
}
