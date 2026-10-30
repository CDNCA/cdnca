package marketsupply

import (
	"context"
	"errors"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/securityiplist"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The WAF's IP lists and CRS application types on the leaf
// (fix-mktsiteconf3 ⑥): each subscriber list becomes one list of the leaf
// tenant (named leafIPListName, kept equal to the carried contents), and
// the application types become the leaf site's CRS override.

// SiteCRSApps is the subset of sitecrs.Store the leaf drives.
type SiteCRSApps interface {
	SetAppsSystem(ctx context.Context, scopeID, siteID, userID uuid.UUID, apps []string, requestID string) (bool, error)
}

// IPLists is the subset of securityiplist.Store the leaf drives.
type IPLists interface {
	Create(ctx context.Context, actor securityiplist.Actor, request securityiplist.WriteRequest) (securityiplist.List, error)
	Update(ctx context.Context, actor securityiplist.Actor, request securityiplist.WriteRequest) (securityiplist.List, error)
}

// WithWAFExtras lets market WAF blocks carry IP lists and CRS application
// types; without them such a block is refused (unsupported_waf).
func (s *Service) WithWAFExtras(crs SiteCRSApps, lists IPLists) *Service {
	s.crs, s.ipLists = crs, lists
	return s
}

// applyIPLists writes the block's lists as the tenant's and returns the leaf
// list ID of every subscriber list ID. An unchanged list writes nothing.
func (s *Service) applyIPLists(ctx context.Context, tenant tenantRef, waf *siteWAF, key string) (map[string]uuid.UUID, error) {
	if len(waf.IPLists) == 0 {
		return nil, nil
	}
	if s.ipLists == nil {
		return nil, errors.New("market supply: IP lists are not configured")
	}
	actor := securityiplist.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	keys := make([]string, 0, len(waf.IPLists))
	for subscriberID := range waf.IPLists {
		keys = append(keys, subscriberID)
	}
	slices.Sort(keys)
	out := make(map[string]uuid.UUID, len(keys))
	for _, subscriberID := range keys {
		input, err := securityiplist.Normalize(securityiplist.Input{Name: leafIPListName(waf.IPLists[subscriberID].Name, subscriberID),
			Description: "market", Entries: waf.IPLists[subscriberID].CIDRs})
		if err != nil {
			return nil, err
		}
		id, revision, entries, err := s.leafIPList(ctx, tenant, input.Name)
		if err != nil {
			return nil, err
		}
		listKey := key + "-ipl-" + subscriberID[:8]
		switch {
		case id == uuid.Nil:
			created, err := s.ipLists.Create(ctx, actor, securityiplist.WriteRequest{Input: input,
				IdempotencyKey: listKey + "-create", RequestID: key})
			if err != nil {
				return nil, err
			}
			id = created.ID
		case !slices.Equal(entries, input.Entries):
			if _, err := s.ipLists.Update(ctx, actor, securityiplist.WriteRequest{ListID: id, ExpectedRevision: revision,
				Input: input, IdempotencyKey: listKey + "-r" + itoa(revision), RequestID: key}); err != nil {
				return nil, err
			}
		}
		out[subscriberID] = id
	}
	return out, nil
}

func (s *Service) leafIPList(ctx context.Context, tenant tenantRef, name string) (uuid.UUID, int64, []string, error) {
	var id uuid.UUID
	var revision int64
	var entries []string
	err := s.pool.QueryRow(ctx, `SELECT id, revision, entries FROM security_ip_lists
		WHERE owner_scope_id=$1 AND name=$2 AND deleted_at IS NULL`, tenant.scopeID, name).Scan(&id, &revision, &entries)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, nil, nil
	}
	return id, revision, entries, err
}

// applyCRSApps sets the leaf site's application types (none clears them).
func (s *Service) applyCRSApps(ctx context.Context, tenant tenantRef, leafSiteID uuid.UUID, waf *siteWAF, key string) error {
	if s.crs == nil {
		if len(waf.CRSApps) > 0 {
			return errors.New("market supply: site CRS is not configured")
		}
		return nil
	}
	_, err := s.crs.SetAppsSystem(ctx, tenant.scopeID, leafSiteID, tenant.userID, waf.CRSApps, key)
	return err
}
