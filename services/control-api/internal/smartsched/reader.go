package smartsched

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnamelines"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LineView is one line of GET /v1/node-line-groups/{id}/smart-schedule.
type LineView struct {
	Scope        string    `json:"scope"`
	DNSLine      string    `json:"dns_line"`
	Source       string    `json:"source"`
	Selected     []Pick    `json:"selected"`
	FallbackFrom string    `json:"fallback_from,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ProbeSourceView says which latency sources are available: dnspup (the
// module.probe.dnspup plugin probing node addresses) and peer nodes.
// Both false: there is no latency and every line keeps its static set.
type ProbeSourceView struct {
	DNSPup    bool `json:"dnspup"`
	PeerNodes bool `json:"peer_nodes"`
}

// Reader implements nodescheduler.SmartScheduleReader.
type Reader struct {
	Now func() time.Time
}

func (reader Reader) now() time.Time {
	if reader.Now == nil {
		return time.Now().UTC()
	}
	return reader.Now().UTC()
}

func (reader Reader) dnsLine(scope string) string {
	if province, carrier, ok := ParseScope(scope); ok {
		line, _ := dnsproviderremote.ProvinceCarrierLine(province, carrier)
		return line
	}
	line, _ := cnamelines.DNSLine(scope)
	return line
}

func (reader Reader) Lines(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, revision int64) (any, error) {
	rows, err := tx.Query(ctx, `SELECT line_scope,source,fallback_from,selected,changed_at
		FROM node_line_smart_selections
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND group_revision=$3 AND refreshed_at>$4
		ORDER BY position(':' IN line_scope)>0, line_scope`, scopeID, groupID, revision,
		reader.now().Add(-SelectionFreshFor))
	if err != nil {
		return nil, err
	}
	lines, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (LineView, error) {
		var value LineView
		var raw []byte
		if err := row.Scan(&value.Scope, &value.Source, &value.FallbackFrom, &raw, &value.UpdatedAt); err != nil {
			return value, err
		}
		value.UpdatedAt = value.UpdatedAt.UTC()
		value.Selected = []Pick{}
		if err := json.Unmarshal(raw, &value.Selected); err != nil {
			return value, err
		}
		value.DNSLine = reader.dnsLine(value.Scope)
		return value, nil
	})
	if lines == nil {
		lines = []LineView{}
	}
	return lines, err
}

func (reader Reader) ProbeSource(ctx context.Context, tx pgx.Tx) (any, error) {
	var view ProbeSourceView
	err := tx.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM node_dnspup_probe_results WHERE observed_at>$1),
			EXISTS (SELECT 1 FROM node_peer_probe_results WHERE observed_at>$1 AND checkpoints @> '[{"ok":true}]'
			        AND EXISTS (SELECT 1 FROM jsonb_array_elements(checkpoints) item WHERE item->>'id'<>'controller'))`,
		reader.now().Add(-time.Hour)).Scan(&view.DNSPup, &view.PeerNodes)
	return view, err
}

func (reader Reader) Matrix(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, window int) (any, error) {
	rows, err := Matrix(ctx, tx, scopeID, groupID, reader.now(), window)
	if rows == nil {
		rows = []MatrixRow{}
	}
	return map[string]any{"rows": rows}, err
}

// ProvinceLines: every DNS provider of a site on this line group writes
// province lines (no site yet: whether the platform's zones would).
func (reader Reader) ProvinceLines(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT provider.provider_type
		FROM cname_allocation_targets frozen
		JOIN cname_allocations allocation ON allocation.tenant_id=frozen.tenant_id AND allocation.job_id=frozen.job_id
		 AND allocation.state='done' AND allocation.mode='site'
		JOIN dns_zones zone ON zone.scope_id=frozen.tenant_scope_id AND zone.id=frozen.zone_id
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		WHERE frozen.node_group_scope_id=$1 AND frozen.node_group_id=$2`, scopeID, groupID)
	if err != nil {
		return false, err
	}
	providers, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return false, err
	}
	if len(providers) == 0 {
		return false, nil
	}
	for _, provider := range providers {
		if !dnsproviderremote.SupportsProvinceLines(provider) || len(dnsproviderremote.SupportedLines(provider)) < 2 {
			return false, nil
		}
	}
	return true, nil
}
