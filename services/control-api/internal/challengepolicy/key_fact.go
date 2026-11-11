package challengepolicy

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/jackc/pgx/v5"
)

// KeyFactIssuer writes the HMAC key fact of a policy revision
// (challengepublication.KeyFactIssuer).
type KeyFactIssuer interface {
	IssueTx(context.Context, pgx.Tx, challengepublication.KeyFactIssueRequest) error
}

// UseKeyFactIssuer makes every enabled revision carry its HMAC key fact,
// written in the revision's transaction: without it no policy can publish.
func (store *Store) UseKeyFactIssuer(issuer KeyFactIssuer) {
	if store != nil && !isNilDependency(issuer) {
		store.keyFacts = issuer
	}
}

func (store *Store) issueKeyFact(ctx context.Context, tx pgx.Tx, actor Actor, item storedPolicy) error {
	if store.keyFacts == nil || !item.Enabled || item.Deleted {
		return nil
	}
	return store.keyFacts.IssueTx(ctx, tx, challengepublication.KeyFactIssueRequest{
		TenantScopeID: item.TenantScopeID, TenantID: item.TenantID, SiteID: item.SiteID, PolicyID: item.ID,
		Host: item.Host, KeyReference: item.KeyReference, PolicyRevision: item.Revision,
		ActorScopeID: actor.ScopeID, ActorUserID: actor.UserID,
	})
}
