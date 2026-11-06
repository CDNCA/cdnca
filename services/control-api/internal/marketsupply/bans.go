package marketsupply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/bansync"
	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The root subscriber's ban list of a market site (
// libs/marketproto/bansync): the leaf writes it onto the grant's own leaf
// site through its ban list library, whose distributor sends it to the nodes
// serving the site; the reply carries what was refused and how far those
// nodes are. A supply the market stopped takes no ban list, and its
// subscriber's bans are lifted (a paused supply only leaves DNS, its nodes
// still serve, so its bans stay), as are those of a subscription that no
// longer has an active grant (sweepBans).

// BanList is the leaf's ban list library (securityban.Store).
type BanList interface {
	ApplyMarket(ctx context.Context, sync securityban.MarketSync) (securityban.MarketResult, error)
	ActiveMarketTenants(ctx context.Context) ([]securityban.MarketTenant, error)
	ReleaseMarketTenant(ctx context.Context, tenant securityban.MarketTenant, reason string) (int, error)
}

// BanDelivery reports a leaf site's nodes (securityban.Distributor); nil
// when the leaf does not send ban lists to nodes.
type BanDelivery interface {
	SiteDelivery(ctx context.Context, siteID uuid.UUID, since time.Time) (bansync.Nodes, error)
}

// Release reasons of a subscriber's bans (audit).
const (
	banReleaseEnded  = "subscription_ended"
	banReleasePaused = "supply_paused"
)

// WithBanList lets subscribers send their ban lists (bansync.OpSync);
// without it the leaf answers ErrCodeUnavailable. delivery may be nil.
func (s *Service) WithBanList(list BanList, delivery BanDelivery) *Service {
	s.bans, s.banDelivery = list, delivery
	return s
}

func (s *Service) syncBans(ctx context.Context, header envelope.Header, payload []byte, g grant.Grant, tenant tenantRef,
	reply siteconf.Reply,
) (siteconf.Reply, error) {
	fail := func(code string) (siteconf.Reply, error) {
		reply.Error = code
		return reply, nil
	}
	if s.bans == nil {
		return fail(bansync.ErrCodeUnavailable)
	}
	var req bansync.Request
	if json.Unmarshal(payload, &req) != nil || req.Normalize() != nil {
		return fail(bansync.ErrCodeInvalid)
	}
	reply.SiteID, reply.LeafSiteID = req.SiteID, &req.LeafSiteID
	s.mu.Lock()
	ended := s.activeKeys != nil && !s.activeKeys[Key(g)]
	s.mu.Unlock()
	if ended {
		return fail(bansync.ErrCodeEnded)
	}
	held, err := s.supplyHeld(ctx, tenant.scopeID)
	if err != nil {
		return siteconf.Reply{}, err
	}
	if held {
		return fail(bansync.ErrCodePaused)
	}
	// Where the leaf recorded the subscriber site's leaf site (634), the
	// snapshot must name that one.
	applied, err := s.loadApplied(ctx, tenant, req.SiteID)
	if err != nil {
		return siteconf.Reply{}, err
	}
	if applied.found && (applied.leafSite == nil || *applied.leafSite != req.LeafSiteID) {
		return fail(bansync.ErrCodeSiteNotFound)
	}
	result, err := s.bans.ApplyMarket(ctx, securityban.MarketSync{TenantScopeID: tenant.scopeID, Key: Key(g), Request: req,
		RequestID: "market-" + header.MessageID.String()})
	switch {
	case errors.Is(err, securityban.ErrMarketSiteNotFound):
		return fail(bansync.ErrCodeSiteNotFound)
	case errors.Is(err, securityban.ErrMarketRateLimited):
		return fail(bansync.ErrCodeRateLimited)
	case err != nil:
		return siteconf.Reply{}, err
	}
	status := bansync.Status{Revision: result.Revision, Accepted: result.Accepted, Refused: result.Refused,
		Nodes: bansync.Nodes{State: bansync.NodesOff}}
	if s.banDelivery != nil {
		if status.Nodes, err = s.banDelivery.SiteDelivery(ctx, req.LeafSiteID, result.ChangedAt); err != nil {
			return siteconf.Reply{}, err
		}
	}
	reply.Revision = result.Revision
	reply.Status, _ = json.Marshal(status)
	reply.OK = true
	return reply, nil
}

// supplyHeld: the market stopped the tenant's supply (pause leaves the nodes serving).
func (s *Service) supplyHeld(ctx context.Context, scope uuid.UUID) (bool, error) {
	var held bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM market_supply_limits
		WHERE tenant_scope_id=$1 AND hold_action='stop')`, scope).Scan(&held)
	return held, err
}

// sweepBans releases the subscriber bans of every market tenant whose key is
// not in active (nil: not known, only holds count) or whose supply is held.
func (s *Service) sweepBans(ctx context.Context, active map[string]bool) error {
	if s.bans == nil {
		return nil
	}
	tenants, err := s.bans.ActiveMarketTenants(ctx)
	if err != nil || len(tenants) == 0 {
		return err
	}
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT tenant_scope_id FROM market_supply_limits WHERE hold_action='stop'`)
	if err != nil {
		return err
	}
	heldScopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	held := map[uuid.UUID]bool{}
	for _, scope := range heldScopes {
		held[scope] = true
	}
	var errs []error
	for _, tenant := range tenants {
		reason := ""
		switch {
		case active != nil && !active[tenant.Key]:
			reason = banReleaseEnded
		case held[tenant.ScopeID]:
			reason = banReleasePaused
		default:
			continue
		}
		if _, err := s.bans.ReleaseMarketTenant(ctx, tenant, reason); err != nil {
			errs = append(errs, fmt.Errorf("market bans %s: %w", tenant.Key, err))
		}
	}
	return errors.Join(errs...)
}
