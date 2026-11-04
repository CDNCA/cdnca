package marketsupply

// Seller L2 for market supply: the seller
// names one of its own L2 configurations (l2_topology_configs of the platform
// scope) on a supply group (node_line_groups.l2_config_id). A subscriber's
// site whose L2 mode is "follow the package" then goes through that L2 on the
// seller's nodes (edgepublish reads the site's line group); the
// subscriber never names the seller's L2 nodes (custom stays site_l2_custom).
//
// Usable: the configuration is live and has an enabled member on an active
// node with an address. The pool report carries it per node (l2) so the
// market only accepts an offer declaring L2 its supply has, and a leaf
// answers BlockerL2Unavailable when a site follows the package on a supply
// without usable L2.

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BlockerL2Unavailable (advisory, OK reply): the site follows the package's
// L2 but the seller's supply has no usable L2 configuration, so the leaf's
// nodes go straight to the origin.
const BlockerL2Unavailable = "l2_unavailable"

// ErrSupplyL2Unusable: the named L2 configuration is not a live one of the
// platform scope with an enabled member on an active node.
var ErrSupplyL2Unusable = errors.New("market supply group: L2 configuration unusable")

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// usableL2 is the condition on config (alias config) for a usable L2.
const usableL2 = `config.deleted_at IS NULL AND EXISTS (SELECT 1 FROM l2_topology_nodes member
	JOIN nodes node ON node.id=member.node_id AND node.admin_state='active'
	  AND COALESCE(host(node.ipv4), host(node.ipv6), '') <> ''
	WHERE member.tenant_scope_id=config.tenant_scope_id AND member.config_id=config.id
	  AND member.enabled AND member.deleted_at IS NULL)`

// checkL2Config refuses a configuration that is not usable in the platform scope.
func checkL2Config(ctx context.Context, q rowQuerier, platform, configID uuid.UUID) error {
	var usable bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM l2_topology_configs config
		WHERE config.tenant_scope_id=$1 AND config.id=$2 AND `+usableL2+`)`, platform, configID).Scan(&usable); err != nil {
		return err
	}
	if !usable {
		return ErrSupplyL2Unusable
	}
	return nil
}

// groupL2Usable reports whether the supply group's current L2 configuration
// is usable (false without one or for an unknown group).
func groupL2Usable(ctx context.Context, q rowQuerier, groupID uuid.UUID) (bool, error) {
	var usable bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM node_line_groups line_group
		JOIN l2_topology_configs config ON config.tenant_scope_id=line_group.tenant_scope_id
		  AND config.id=line_group.l2_config_id
		WHERE line_group.id=$1 AND line_group.deleted_at IS NULL AND `+usableL2+`)`, groupID).Scan(&usable)
	return usable, err
}

// SupplyL2Option is one of the platform's live L2 configurations a seller
// may name on a supply group (only usable ones are accepted).
type SupplyL2Option struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	Region string    `json:"region"`
	Mode   string    `json:"mode"`
	Usable bool      `json:"usable"`
}

// L2Options lists the platform's live L2 configurations for 供货管理 (the
// seller gate, not node_scheduling.read).
func (s *SupplyGroups) L2Options(ctx context.Context, actor SupplyActor) ([]SupplyL2Option, error) {
	rows, err := s.pool.Query(ctx, `SELECT config.id, config.name, config.region, config.mode, `+usableL2+`
		FROM l2_topology_configs config JOIN access_scopes scope ON scope.id=config.tenant_scope_id AND scope.kind='platform'
		WHERE config.tenant_scope_id=$1 AND config.deleted_at IS NULL ORDER BY config.display_id`, actor.ScopeID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (SupplyL2Option, error) {
		var o SupplyL2Option
		return o, row.Scan(&o.ID, &o.Name, &o.Region, &o.Mode, &o.Usable)
	})
}

// PoolL2 reports whether a pool (a local supply group id) has usable L2, for
// the pool report (marketprobe.Config.L2). A ref that is not a group id has none.
func (s *SupplyGroups) PoolL2(ctx context.Context, ref string) (bool, error) {
	groupID, err := uuid.Parse(ref)
	if err != nil {
		return false, nil
	}
	return groupL2Usable(ctx, s.pool, groupID)
}

// l2Advisory: a revision following the package's L2 on a supply without
// usable L2 is served straight to the origin, and says so.
func (s *Service) l2Advisory(ctx context.Context, actor serviceActor, g grant.Grant, c siteconf.Config) ([]siteconf.Blocker, error) {
	if c.Forwarding != nil && c.Forwarding.L2Off {
		return nil, nil
	}
	poolID, err := s.pool_(ctx, actor.scopeID, g.NodePoolRef)
	if err != nil {
		return nil, err
	}
	usable, err := groupL2Usable(ctx, s.pool, poolID)
	if err != nil || usable {
		return nil, err
	}
	return []siteconf.Blocker{{Code: BlockerL2Unavailable}}, nil
}
