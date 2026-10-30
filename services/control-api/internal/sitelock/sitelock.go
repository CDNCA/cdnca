// Package sitelock is the shared write guard for site sub-resources (cache,
// security bindings, HTTP policy, challenge, protocol, origin auth). A site
// locked by a platform administrator is read-only for tenant actors; platform
// actors keep maintenance access, matching internal/site (FX31).
package sitelock

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrLocked reports that a tenant actor tried to change a locked site.
var ErrLocked = errors.New("site is locked")

// RequireUnlocked fails with ErrLocked when any of siteIDs is locked and the
// acting scope is a tenant scope. Missing or deleted sites are left to the
// caller's own lookup. It takes FOR SHARE locks so a concurrent lock/unlock
// serializes with the caller's write.
func RequireUnlocked(ctx context.Context, tx pgx.Tx, actorScopeID uuid.UUID, siteIDs ...uuid.UUID) error {
	if len(siteIDs) == 0 {
		return nil
	}
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, actorScopeID).Scan(&kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrLocked
		}
		return fmt.Errorf("load site lock actor scope: %w", err)
	}
	if kind == "platform" {
		return nil
	}
	var lockedID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM sites
		WHERE id=ANY($1) AND deleted_at IS NULL AND locked_at IS NOT NULL
		ORDER BY id LIMIT 1 FOR SHARE`, siteIDs).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check site lock: %w", err)
	}
	return ErrLocked
}
