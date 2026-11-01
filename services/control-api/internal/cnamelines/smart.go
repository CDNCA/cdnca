package cnamelines

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/jackc/pgx/v5"
)

// smartSelectionFreshFor matches smartsched.SelectionFreshFor: an older
// selection (the selector stopped) is ignored and the line keeps today's set.
const smartSelectionFreshFor = 10 * time.Minute

var carrierScopes = []string{"telecom", "unicom", "mobile"}

// isProvinceScope: "<province>:<carrier>" (migration 609).
func isProvinceScope(scope string) bool { return strings.Contains(scope, ":") }

func provinceCarrier(scope string) string {
	_, carrier, _ := strings.Cut(scope, ":")
	return carrier
}

// lineFor is the unified DNS line of a carrier or province scope.
func lineFor(scope string) (string, bool) {
	if province, carrier, ok := strings.Cut(scope, ":"); ok {
		if !slices.Contains(carrierScopes, carrier) {
			return "", false
		}
		return dnsproviderremote.ProvinceCarrierLine(province, carrier)
	}
	return DNSLine(scope)
}

func lineSupported(providerType, scope string) bool {
	if isProvinceScope(scope) {
		_, ok := lineFor(scope)
		return ok && dnsproviderremote.SupportsProvinceLines(providerType)
	}
	return Supported(providerType, scope)
}

// WithSmart overlays smart selections on the static plan: a selected line
// takes the selection (equal weights), a province line still tracked but no
// longer selected is retired (empty set). With no selection the plan is
// returned unchanged and no line is equal-weighted (smart scheduling off).
func WithSmart(plan map[string]Set, smart map[string]Set, tracked []string) (map[string]Set, map[string]bool) {
	equal := map[string]bool{}
	for scope, set := range smart {
		plan[scope], equal[scope] = set, true
	}
	for _, scope := range tracked {
		if _, planned := plan[scope]; !planned && isProvinceScope(scope) {
			plan[scope], equal[scope] = Set{A: []string{}, AAAA: []string{}}, true
		}
	}
	return plan, equal
}

// smartLines are the line sets of the site's line group from fresh smart
// selections (enabled schedule, same group revision). A latency selection is
// limited to addresses still published (empty after that: the line keeps
// its static set); a fallback selection is an empty set (the line is not
// written and answers from the level above). Static selections and province
// lines the provider cannot write are left out.
func (worker *Worker) smartLines(ctx context.Context, item site, endpoints []Endpoint) (map[string]Set, error) {
	rows, err := worker.pool.Query(ctx, `SELECT selection.line_scope,selection.source,selection.selected
		FROM node_line_smart_selections selection
		JOIN node_line_group_smart_schedules schedule ON schedule.tenant_scope_id=selection.tenant_scope_id
		 AND schedule.line_group_id=selection.line_group_id AND schedule.enabled
		WHERE selection.tenant_scope_id=$1 AND selection.line_group_id=$2 AND selection.group_revision=$3
		  AND selection.source IN ('latency','fallback') AND selection.refreshed_at>$4
		  AND (position(':' IN selection.line_scope)=0 OR schedule.granularity='province_carrier')
		ORDER BY selection.line_scope`, item.GroupScopeID, item.GroupID, item.GroupRevision,
		worker.now().UTC().Add(-smartSelectionFreshFor))
	if err != nil {
		return nil, err
	}
	type row struct {
		scope, source string
		selected      []byte
	}
	selections, err := pgx.CollectRows(rows, func(collectable pgx.CollectableRow) (row, error) {
		var value row
		return value, collectable.Scan(&value.scope, &value.source, &value.selected)
	})
	if err != nil {
		return nil, err
	}
	published := map[string]bool{}
	for _, endpoint := range endpoints {
		if address, err := netip.ParseAddr(endpoint.Address); err == nil {
			published[address.String()] = true
		}
	}
	out := map[string]Set{}
	for _, selection := range selections {
		if isProvinceScope(selection.scope) && !lineSupported(item.ProviderType, selection.scope) {
			continue
		}
		set := Set{A: []string{}, AAAA: []string{}}
		if selection.source == "latency" {
			var picks []struct {
				Address string `json:"address"`
			}
			if json.Unmarshal(selection.selected, &picks) != nil {
				continue
			}
			for _, pick := range picks {
				address, err := netip.ParseAddr(pick.Address)
				if err != nil || !published[address.String()] {
					continue
				}
				if address.Is4() {
					set.A = append(set.A, address.String())
				} else {
					set.AAAA = append(set.AAAA, address.String())
				}
			}
			if set.Empty() {
				continue
			}
			slices.Sort(set.A)
			slices.Sort(set.AAAA)
			set.A, set.AAAA = slices.Compact(set.A), slices.Compact(set.AAAA)
		}
		out[selection.scope] = set
	}
	return out, nil
}
