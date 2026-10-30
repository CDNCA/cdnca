package marketsupply

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Node plugins on the leaf.
// The grant's tags.plugins are what the supply includes; a market tenant
// runs only those. Its own configuration is never changed: publication and
// the automatic defence snapshot read market_supply_tenant_plugins and leave
// out what depends on a plugin outside the set (edgepublish rule pack mounts,
// autodefense snapshot sites). Base protection (access control, basic CC,
// rate limits, the in-house WAF base rules) needs no plugin and always runs.

// Plugin codes of NodePlugins the leaf enforces per market tenant.
const (
	PluginAutoDefense     = "module.autodefense"
	PluginAutoDefenseAuto = "module.autodefense.auto"
)

// applyPlugins records g's plugin set and automatic defence caps for the
// tenant. A change advances the tenant's edge source revision and queues an
// automatic publication (its policy names the pool's nodes, ensureDelivery),
// so a plugin that left the supply is withheld and one that came back
// returns without anyone touching the site.
func (s *Service) applyPlugins(ctx context.Context, tenant tenantRef, g grant.Grant) error {
	plugins := slices.Clone(g.Tags.Plugins)
	slices.Sort(plugins)
	plugins = slices.Compact(plugins)
	if plugins == nil {
		plugins = []string{}
	}
	var caps []byte
	if g.AutoDefenseCaps != nil {
		normalized, err := g.AutoDefenseCaps.Normalize()
		if err != nil {
			return err
		}
		if caps, err = json.Marshal(normalized); err != nil {
			return err
		}
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var current []string
		var currentCaps []byte
		err := tx.QueryRow(ctx, `SELECT plugins, autodefense_caps FROM market_supply_tenant_plugins
			WHERE tenant_scope_id=$1 FOR UPDATE`, tenant.scopeID).Scan(&current, &currentCaps)
		found := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if found && slices.Equal(current, plugins) && sameCaps(currentCaps, caps) {
			_, err := tx.Exec(ctx, `UPDATE market_supply_tenant_plugins SET grant_id=$2 WHERE tenant_scope_id=$1`,
				tenant.scopeID, g.GrantID)
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO market_supply_tenant_plugins(tenant_scope_id,grant_id,plugins,autodefense_caps,updated_at)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT (tenant_scope_id) DO UPDATE SET grant_id=EXCLUDED.grant_id,
			plugins=EXCLUDED.plugins, autodefense_caps=EXCLUDED.autodefense_caps, updated_at=EXCLUDED.updated_at`,
			tenant.scopeID, g.GrantID, plugins, caps, s.now().UTC()); err != nil {
			return err
		}
		if !found {
			return nil // a new tenant has nothing published yet
		}
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, tenant.scopeID); err != nil {
			return err
		}
		_, err = edgeautopublish.EnqueueSystemTx(ctx, tx, edgeautopublish.SystemEnqueueInput{
			TargetScopeID: tenant.scopeID, SourceKind: edgeautopublish.SourceModuleEntitlement,
			SourceResourceID: g.GrantID, SourceRequestID: "market-plugins-" + g.GrantID.String(),
		})
		return err
	})
}

func sameCaps(a, b []byte) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	var x, y spec.AutoDefenseCaps
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil &&
		x.MaxLevel == y.MaxLevel && slices.Equal(x.ModulesAllowed, y.ModulesAllowed)
}

// TenantPlugins is what a market tenant's latest grant allows.
type TenantPlugins struct {
	Plugins []string
	Caps    *spec.AutoDefenseCaps
}

// Has reports whether the supply includes plugin.
func (p TenantPlugins) Has(plugin string) bool { return slices.Contains(p.Plugins, plugin) }

// tenantPlugins reads the tenant's row; ok is false for a tenant without one.
func tenantPlugins(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenant uuid.UUID) (TenantPlugins, bool, error) {
	var out TenantPlugins
	var caps []byte
	err := q.QueryRow(ctx, `SELECT plugins, autodefense_caps FROM market_supply_tenant_plugins WHERE tenant_scope_id=$1`,
		tenant).Scan(&out.Plugins, &caps)
	if errors.Is(err, pgx.ErrNoRows) {
		return TenantPlugins{}, false, nil
	}
	if err != nil {
		return TenantPlugins{}, false, err
	}
	if caps != nil {
		out.Caps = &spec.AutoDefenseCaps{}
		if err := json.Unmarshal(caps, out.Caps); err != nil {
			return TenantPlugins{}, false, err
		}
	}
	return out, true, nil
}
