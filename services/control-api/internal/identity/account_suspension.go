package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Account suspension stops serving.
// Before this, edge publication filtered only site and package state, so the
// sites of a disabled user, a suspended membership or a suspended/closed
// tenant kept serving on the nodes. The worker below takes them off:
//
//   - hold: every serving site (enabled, status active) whose owner is not
//     active is disabled, a hold records it, and the scope is republished at
//     once (system trigger account_suspension).
//   - release: when the owner is active again, only the held sites that are
//     still disabled are enabled again, and the scope is republished at once.
//
// Sites a tenant or administrator disabled for any other reason are never
// held, so they are not re-enabled by a reactivation; package_expired and
// traffic_exceeded sites already serve nothing and keep their status.

const (
	AccountSuspensionOperationDisable = "site.batch.disable"
	AccountSuspensionOperationEnable  = "site.batch.enable"
)

// AccountSuspensionRepublisher makes a committed site change effective on the
// nodes immediately, in the caller's transaction.
type AccountSuspensionRepublisher interface {
	RepublishNowTx(ctx context.Context, tx pgx.Tx, request SecondaryVerificationRepublish) error
}

type AccountSuspensionEnforcement struct {
	Held     int // owners whose sites were stopped in this pass
	Released int // owners whose sites were restored in this pass
}

// ownerSuspensionSQL is the reason an owner (users u, memberships m,
// tenants t) does not serve, or NULL while it does.
const ownerSuspensionSQL = `CASE WHEN u.status<>'active' THEN 'user_disabled'
	WHEN m.status<>'active' THEN 'membership_suspended'
	WHEN t.status<>'active' THEN 'tenant_suspended' END`

const ownerJoinSQL = `JOIN users u ON u.id=site.owner_user_id
	JOIN memberships m ON m.scope_id=site.scope_id AND m.user_id=site.owner_user_id
	JOIN access_scopes scope ON scope.id=site.scope_id
	LEFT JOIN tenants t ON t.id=scope.tenant_id`

// suspendableSiteSQL: a serving site of a suspended owner, not held yet and
// without a DNS provider mutation in flight (089 forbids changing it).
const suspendableSiteSQL = `site.deleted_at IS NULL AND site.enabled AND site.status='active'
	AND (` + ownerSuspensionSQL + `) IS NOT NULL
	AND NOT EXISTS(SELECT 1 FROM account_suspension_site_holds hold WHERE hold.site_id=site.id AND hold.released_at IS NULL)
	AND NOT EXISTS(SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
		WHERE claim.site_id=site.id AND claim.state IN ('claimed','uncertain'))`

// releasableSiteSQL: an open hold whose owner serves again.
const releasableSiteSQL = `hold.released_at IS NULL AND (` + ownerSuspensionSQL + `) IS NULL
	AND NOT EXISTS(SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
		WHERE claim.site_id=site.id AND claim.state IN ('claimed','uncertain'))`

// EnforceAccountSuspensions handles up to limit owners, one transaction (and
// at most one republication) per owner.
func (s *Store) EnforceAccountSuspensions(ctx context.Context, republisher AccountSuspensionRepublisher, limit int) (AccountSuspensionEnforcement, error) {
	var result AccountSuspensionEnforcement
	if s == nil || s.pool == nil || republisher == nil || limit < 1 || limit > 1000 {
		return result, errors.New("account suspension enforcement is not configured")
	}
	for range limit {
		released, err := s.changeOneAccountSuspension(ctx, republisher, false)
		if err != nil {
			return result, fmt.Errorf("release account suspension holds: %w", err)
		}
		if released {
			result.Released++
			continue
		}
		held, err := s.changeOneAccountSuspension(ctx, republisher, true)
		if err != nil {
			return result, fmt.Errorf("hold suspended account sites: %w", err)
		}
		if !held {
			break
		}
		result.Held++
	}
	return result, nil
}

type suspensionCandidate struct {
	siteID   uuid.UUID
	revision int64
	heldAt   time.Time
	reason   string
}

func (s *Store) changeOneAccountSuspension(ctx context.Context, republisher AccountSuspensionRepublisher, hold bool) (bool, error) {
	handled := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		var scopeID, ownerID uuid.UUID
		var err error
		if hold {
			err = tx.QueryRow(ctx, `SELECT site.scope_id,site.owner_user_id FROM sites site `+ownerJoinSQL+`
				WHERE `+suspendableSiteSQL+` ORDER BY site.scope_id,site.owner_user_id LIMIT 1`).Scan(&scopeID, &ownerID)
		} else {
			err = tx.QueryRow(ctx, `SELECT hold.scope_id,hold.owner_user_id FROM account_suspension_site_holds hold
				JOIN sites site ON site.id=hold.site_id `+ownerJoinSQL+`
				WHERE `+releasableSiteSQL+` ORDER BY hold.scope_id,hold.owner_user_id LIMIT 1`).Scan(&scopeID, &ownerID)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		handled = true
		// Publication lock order: configuration scope before resource rows.
		fromRevision, err := lockConfigurationScopeTx(ctx, tx, scopeID)
		if err != nil {
			return err
		}
		var rows pgx.Rows
		if hold {
			rows, err = tx.Query(ctx, `SELECT site.id,site.revision,now(),(`+ownerSuspensionSQL+`) FROM sites site `+ownerJoinSQL+`
				WHERE site.scope_id=$1 AND site.owner_user_id=$2 AND `+suspendableSiteSQL+`
				ORDER BY site.id FOR UPDATE OF site SKIP LOCKED`, scopeID, ownerID)
		} else {
			rows, err = tx.Query(ctx, `SELECT site.id,site.revision,hold.held_at,hold.reason FROM account_suspension_site_holds hold
				JOIN sites site ON site.id=hold.site_id `+ownerJoinSQL+`
				WHERE hold.scope_id=$1 AND hold.owner_user_id=$2 AND `+releasableSiteSQL+`
				ORDER BY site.id FOR UPDATE OF hold,site`, scopeID, ownerID)
		}
		if err != nil {
			return err
		}
		candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (suspensionCandidate, error) {
			var item suspensionCandidate
			return item, row.Scan(&item.siteID, &item.revision, &item.heldAt, &item.reason)
		})
		if err != nil {
			return err
		}
		action, operation, requestID := "site.account_suspension.stop", AccountSuspensionOperationDisable, "account-suspension:"+ownerID.String()
		if !hold {
			action, operation, requestID = "site.account_suspension.restore", AccountSuspensionOperationEnable, "account-suspension-release:"+ownerID.String()
		}
		changed := 0
		for _, site := range candidates {
			if hold {
				// sites_check2: enabled=false goes with status='disabled'.
				command, err := tx.Exec(ctx, `UPDATE sites SET enabled=false,status='disabled',revision=revision+1,updated_at=$3
					WHERE id=$1 AND revision=$2 AND deleted_at IS NULL`, site.siteID, site.revision, now)
				if err != nil {
					return err
				}
				if command.RowsAffected() != 1 {
					continue
				}
				if _, err := tx.Exec(ctx, `INSERT INTO account_suspension_site_holds(site_id,held_at,scope_id,owner_user_id,reason)
					VALUES($1,$2,$3,$4,$5)`, site.siteID, now, scopeID, ownerID, site.reason); err != nil {
					return err
				}
			} else {
				// Undo only our change: a site someone enabled, deleted or
				// changed to another status since keeps its state.
				command, err := tx.Exec(ctx, `UPDATE sites SET enabled=true,status='active',revision=revision+1,updated_at=$2
					WHERE id=$1 AND deleted_at IS NULL AND NOT enabled AND status='disabled'`, site.siteID, now)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE account_suspension_site_holds SET released_at=$3 WHERE site_id=$1 AND held_at=$2`,
					site.siteID, site.heldAt, now); err != nil {
					return err
				}
				if command.RowsAffected() != 1 {
					continue
				}
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: action, ResourceType: "site",
				ResourceID: site.siteID.String(), RequestID: requestID, Result: "success", ReasonCode: site.reason,
				Changes: []audit.Change{{Field: "enabled", Before: hold, After: !hold}},
				Payload: map[string]any{"trigger": "account_suspension", "reason_code": site.reason, "owner_user_id": ownerID.String()}}); err != nil {
				return err
			}
			changed++
		}
		if changed == 0 {
			return nil
		}
		return republisher.RepublishNowTx(ctx, tx, SecondaryVerificationRepublish{ScopeID: scopeID, UserID: ownerID,
			FromRevision: fromRevision, Operation: operation, RequestID: requestID})
	})
	return handled, err
}
