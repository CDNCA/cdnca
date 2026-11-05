package marketsupply

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The leaf applies a subscriber's site requests in the order they were sent,
// never an older one over a newer one (migration 634 market_supply_site_revisions).
// The relay redelivers every message from cursor 0 to a runtime that did not
// resume from its acknowledged cursor (an old supply.commit_site
// replayed after a restart wrote the old site fields and CC policy back), and
// the subscriber's reconciler may resend a revision after a newer one applied.
//
// Two orders decide it:
//   - the relay sequence of the message (strictly increasing per recipient):
//     a request at or below the last applied one is a replay of what already
//     ran, whatever it carries (a commit, a rollback, a delete);
//   - the subscriber revision, a rollback ordered as the revision it rolls
//     back (RollbackOf): a commit below the highest revision applied is stale.
//
// A request newer by revision is applied even at a lower sequence, so a
// relay whose sequence restarted cannot stop the leaf.

type relaySeqKey struct{}

// WithRelaySeq tells Handle the relay sequence of the message it handles
// (marketruntime); 0 or unset: unknown, only the revision order applies.
func WithRelaySeq(ctx context.Context, seq int64) context.Context {
	return context.WithValue(ctx, relaySeqKey{}, seq)
}

// RelaySeq is the relay sequence WithRelaySeq set (0: none).
func RelaySeq(ctx context.Context) int64 {
	seq, _ := ctx.Value(relaySeqKey{}).(int64)
	return seq
}

// appliedSite is what the leaf last applied for one subscriber site.
type appliedSite struct {
	found    bool
	leafSite *uuid.UUID
	applied  int64 // subscriber revision running (0 after a delete)
	high     int64 // highest revision applied, a rollback counted as what it rolls back
	seq      int64 // relay sequence of the last applied request
}

func (s *Service) loadApplied(ctx context.Context, tenant tenantRef, siteID uuid.UUID) (appliedSite, error) {
	var out appliedSite
	err := s.pool.QueryRow(ctx, `SELECT leaf_site_id, applied_revision, high_revision, relay_seq
		FROM market_supply_site_revisions WHERE tenant_scope_id=$1 AND site_id=$2`, tenant.scopeID, siteID).
		Scan(&out.leafSite, &out.applied, &out.high, &out.seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return appliedSite{}, nil
	}
	out.found = err == nil
	return out, err
}

// order is the revision a commit is ordered by.
func order(revision, rollbackOf int64) int64 { return max(revision, rollbackOf) }

// staleCommit: the commit must not be applied over what the leaf runs.
func (a appliedSite) staleCommit(ordered, seq int64) bool {
	if !a.found {
		return false
	}
	return ordered < a.high || ordered == a.high && seq > 0 && seq <= a.seq
}

// staleDelete: the delete was sent before the last request the leaf applied.
func (a appliedSite) staleDelete(seq int64) bool {
	return a.found && seq > 0 && seq <= a.seq
}

// saveApplied records an applied commit (revision, ordered as ordered) or,
// with leafSite nil and revision 0, an applied delete. The highest revision
// and the sequence never move back.
func (s *Service) saveApplied(ctx context.Context, tenant tenantRef, siteID uuid.UUID, leafSite *uuid.UUID,
	revision, ordered, seq int64,
) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO market_supply_site_revisions
			(tenant_scope_id, site_id, leaf_site_id, applied_revision, high_revision, relay_seq, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (tenant_scope_id, site_id) DO UPDATE SET leaf_site_id=EXCLUDED.leaf_site_id,
			applied_revision=EXCLUDED.applied_revision,
			high_revision=GREATEST(market_supply_site_revisions.high_revision, EXCLUDED.high_revision),
			relay_seq=GREATEST(market_supply_site_revisions.relay_seq, EXCLUDED.relay_seq),
			updated_at=EXCLUDED.updated_at`,
		tenant.scopeID, siteID, leafSite, revision, max(ordered, revision), seq, s.now().UTC())
	return err
}
