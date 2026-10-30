package securityactivation

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrNoTargetNodes: a start or rollback named no nodes and the site's line
// groups (its own, its package's primary/backup) serve no active node.
var ErrNoTargetNodes = errors.New("security activation site has no target nodes")

// ErrExpiryTooLate: expires_at is past now + Config.CandidateTTL (15 minutes
// by default); told apart from other invalid input so the page can say so.
var ErrExpiryTooLate = errors.New("security activation expires_at exceeds the candidate ttl")

// siteTargets resolves the targets of a start or rollback that named none
// (10-22 自动下发: a tenant cannot see node IDs, so the release targets the
// nodes of the site's package line groups, as automatic publication does).
// A request naming nodes keeps them; canary 0 becomes 1. The targets are
// resolved before validation so the digest, the capability wait and the
// candidate all carry concrete nodes.
func (store *Store) siteTargets(ctx context.Context, scopeID, siteID uuid.UUID, nodes []uuid.UUID, canary int) ([]uuid.UUID, int, error) {
	if len(nodes) > 0 {
		return nodes, canary, nil
	}
	if canary == 0 {
		canary = 1
	}
	if scopeID == uuid.Nil || siteID == uuid.Nil {
		return nil, canary, ErrInvalidInput
	}
	var resolved []uuid.UUID
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		resolved, err = edgeautopublish.SiteTargetNodeIDsTx(ctx, tx, scopeID, siteID)
		return err
	})
	if err != nil {
		return nil, canary, err
	}
	if len(resolved) == 0 {
		return nil, canary, ErrNoTargetNodes
	}
	return canonicalNodes(resolved), canary, nil
}

// rollbackSite is the site of the candidate a rollback restores, read in the
// actor's own scope only (another scope's candidate resolves nothing and the
// rollback's own authorization refuses it).
// rollbackSite is the candidate's site and tenant scope. A tenant actor only
// sees its own candidates; a platform actor (site-parity3b) any tenant's,
// still authorized against that tenant scope by Rollback itself.
func (store *Store) rollbackSite(ctx context.Context, actor securitypolicy.Actor, candidateID uuid.UUID) (uuid.UUID, uuid.UUID, error) {
	var siteID, scopeID uuid.UUID
	err := store.pool.QueryRow(ctx, `SELECT site_id,tenant_scope_id FROM security_policy_activation_candidates
		WHERE id=$1 AND ($2 OR tenant_scope_id=$3)`, candidateID, actor.ScopeKind == "platform", actor.ScopeID).
		Scan(&siteID, &scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, ErrNotFound
	}
	return siteID, scopeID, err
}

// SiteTenantScope is the tenant scope a security activation of the site runs
// in: a tenant actor's own scope; for a platform administrator acting on a
// tenant's site from the site edit page (site-parity3b), the site's scope.
// Authorization against that scope stays with each operation.
func (store *Store) SiteTenantScope(ctx context.Context, actor securitypolicy.Actor, siteID uuid.UUID) (uuid.UUID, error) {
	if store == nil || store.pool == nil || !validActor(actor) || siteID == uuid.Nil {
		return uuid.Nil, ErrInvalidInput
	}
	return siteTenantScopeTx(ctx, store.pool, actor, siteID)
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func siteTenantScopeTx(ctx context.Context, database rowQuerier, actor securitypolicy.Actor, siteID uuid.UUID) (uuid.UUID, error) {
	if actor.ScopeKind != "platform" {
		return actor.ScopeID, nil
	}
	var scopeID uuid.UUID
	err := database.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1 AND deleted_at IS NULL`, siteID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	return scopeID, err
}
