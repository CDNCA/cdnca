package securitypolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SiteProfileChange is one site whose effective CRS profile a WAF library
// edit may have changed (the new library version is already written).
type SiteProfileChange struct {
	ScopeID        uuid.UUID
	SiteID         uuid.UUID
	ActorUserID    uuid.UUID
	ActorScopeKind string
	RequestID      string
	Now            time.Time
}

// SiteProfileChangeHook suspends and restores a site's rule pack mounts for
// its CRS profile as the transaction now sees it (editing a WAF
// library's profile is like changing a site's: it takes effect, mounts the
// profile no longer covers are suspended, covered ones restored). It is set
// by rulepackcontrol (which imports this package); nil leaves mounts alone.
var SiteProfileChangeHook func(ctx context.Context, tx pgx.Tx, change SiteProfileChange) error

// applyLibraryProfileChangeTx runs the hook for every site bound to a WAF
// library whose managed WAF (profile, exclusions, on/off) the edit changed.
func applyLibraryProfileChangeTx(ctx context.Context, tx pgx.Tx, actor Actor, requestID string, before, after Policy,
	now time.Time) error {
	if SiteProfileChangeHook == nil || before.Kind != KindWAF && after.Kind != KindWAF {
		return nil
	}
	previous, _ := json.Marshal(PolicyManagedWAF(before))
	current, _ := json.Marshal(PolicyManagedWAF(after))
	if string(previous) == string(current) {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT tenant_scope_id, site_id FROM security_policy_site_bindings
		WHERE policy_id=$1 AND policy_kind=$2 ORDER BY site_id`, after.ID, KindWAF)
	if err != nil {
		return fmt.Errorf("list sites of WAF library: %w", err)
	}
	var sites []SiteProfileChange
	for rows.Next() {
		change := SiteProfileChange{ActorUserID: actor.UserID, ActorScopeKind: actor.ScopeKind, RequestID: requestID, Now: now}
		if err := rows.Scan(&change.ScopeID, &change.SiteID); err != nil {
			rows.Close()
			return err
		}
		sites = append(sites, change)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, change := range sites {
		if err := SiteProfileChangeHook(ctx, tx, change); err != nil {
			return fmt.Errorf("site %s rule pack mounts: %w", change.SiteID, err)
		}
	}
	return nil
}
