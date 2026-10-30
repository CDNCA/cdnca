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

// FX57 deadline enforcement. An overdue lock_sites request stops the user's
// sites: each site is disabled (taken off the nodes) and locked against tenant
// changes, a hold row records exactly which of the two the control plane did,
// and the scope is republished at once. When the request is completed (or
// switched off, or its deadline moved into the future) the holds are released:
// only the recorded change is undone, so sites stopped or locked for any other
// reason stay as they are, and the scope is republished at once again.

const (
	SecondaryVerificationOperationDisable = "site.batch.disable"
	SecondaryVerificationOperationEnable  = "site.batch.enable"
)

// SecondaryVerificationRepublisher makes a committed site change effective on
// the nodes immediately. It runs in the caller's
// transaction, after the scope's configuration row is locked and the sites
// were changed; fromRevision is the scope's source revision before them.
type SecondaryVerificationRepublisher interface {
	RepublishNowTx(ctx context.Context, tx pgx.Tx, request SecondaryVerificationRepublish) error
}

type SecondaryVerificationRepublish struct {
	ScopeID      uuid.UUID
	UserID       uuid.UUID
	FromRevision int64
	Operation    string
	RequestID    string
}

// SecondaryVerificationEnforcement is one pass of the deadline worker.
type SecondaryVerificationEnforcement struct {
	Held     int // requests whose sites were stopped in this pass
	Released int // requests whose holds were released in this pass
}

// secondaryVerificationDueSQL: an enabled lock_sites request past its deadline
// without an approved reverification.
const secondaryVerificationDueSQL = `v.enabled AND v.expiry_action='lock_sites' AND v.deadline<=$1 AND NOT ` + secondaryVerificationCompletedSQL

// heldSiteCandidateSQL: a live site of the request's user that is not held yet,
// is serving (active) or unlocked (there is something to stop), and has no DNS
// provider mutation in flight (089 forbids changing it meanwhile). Sites that
// are package_expired/traffic_exceeded already serve nothing and keep their
// status (traffic enforcement recovers them); they are only locked.
const heldSiteCandidateSQL = `site.scope_id=v.scope_id AND site.owner_user_id=v.user_id AND site.deleted_at IS NULL
	AND (site.enabled AND site.status='active' OR site.locked_at IS NULL)
	AND NOT EXISTS(SELECT 1 FROM identity_secondary_verification_site_holds hold
		WHERE hold.site_id=site.id AND hold.released_at IS NULL)
	AND NOT EXISTS(SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
		WHERE claim.site_id=site.id AND claim.state IN ('claimed','uncertain'))`

// releasableHoldSQL: an open hold whose site can be changed now.
const releasableHoldSQL = `hold.scope_id=v.scope_id AND hold.user_id=v.user_id AND hold.released_at IS NULL
	AND NOT EXISTS(SELECT 1 FROM dns_reconcile_provider_mutation_claims claim
		WHERE claim.site_id=hold.site_id AND claim.state IN ('claimed','uncertain'))`

// EnforceSecondaryVerificationDeadlines handles up to limit requests, one
// transaction (and at most one republication) per request.
func (s *Store) EnforceSecondaryVerificationDeadlines(ctx context.Context, republisher SecondaryVerificationRepublisher, limit int) (SecondaryVerificationEnforcement, error) {
	var result SecondaryVerificationEnforcement
	if s == nil || s.pool == nil || republisher == nil || limit < 1 || limit > 1000 {
		return result, ErrSecondaryVerificationUnavailable
	}
	for range limit {
		released, err := s.releaseOneSecondaryVerification(ctx, republisher)
		if err != nil {
			return result, fmt.Errorf("release secondary verification holds: %w", err)
		}
		if released {
			result.Released++
			continue
		}
		held, err := s.holdOneSecondaryVerification(ctx, republisher)
		if err != nil {
			return result, fmt.Errorf("enforce secondary verification deadline: %w", err)
		}
		if !held {
			break
		}
		result.Held++
	}
	return result, nil
}

type secondaryVerificationClaim struct {
	scopeID, userID, operator uuid.UUID
	revision                  int64
}

func (s *Store) claimSecondaryVerificationTx(ctx context.Context, tx pgx.Tx, condition string, now time.Time) (secondaryVerificationClaim, bool, error) {
	var claim secondaryVerificationClaim
	err := tx.QueryRow(ctx, `SELECT v.scope_id,v.user_id,v.revision,v.updated_by_user_id
		FROM identity_user_secondary_verification v WHERE `+condition+`
		ORDER BY v.deadline NULLS LAST,v.scope_id,v.user_id LIMIT 1 FOR UPDATE OF v SKIP LOCKED`, now).
		Scan(&claim.scopeID, &claim.userID, &claim.revision, &claim.operator)
	if errors.Is(err, pgx.ErrNoRows) {
		return claim, false, nil
	}
	return claim, err == nil, err
}

// lockConfigurationScopeTx takes the publication lock order (configuration
// scope before resource rows) and returns the revision before this change.
func lockConfigurationScopeTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (int64, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, scopeID); err != nil {
		return 0, err
	}
	var revision int64
	err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID).Scan(&revision)
	return revision, err
}

func (s *Store) holdOneSecondaryVerification(ctx context.Context, republisher SecondaryVerificationRepublisher) (bool, error) {
	handled := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		claim, found, err := s.claimSecondaryVerificationTx(ctx, tx, secondaryVerificationDueSQL+
			` AND EXISTS(SELECT 1 FROM sites site WHERE `+heldSiteCandidateSQL+`)`, now)
		if err != nil || !found {
			return err
		}
		handled = true
		fromRevision, err := lockConfigurationScopeTx(ctx, tx, claim.scopeID)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT site.id,site.revision,site.enabled AND site.status='active',site.locked_at IS NULL
			FROM identity_user_secondary_verification v JOIN sites site ON `+heldSiteCandidateSQL+`
			WHERE v.scope_id=$1 AND v.user_id=$2 ORDER BY site.id FOR UPDATE OF site SKIP LOCKED`, claim.scopeID, claim.userID)
		if err != nil {
			return err
		}
		type candidate struct {
			id                uuid.UUID
			revision          int64
			enabled, unlocked bool
		}
		sites, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
			var item candidate
			return item, row.Scan(&item.id, &item.revision, &item.enabled, &item.unlocked)
		})
		if err != nil {
			return err
		}
		requestID := "secondary-verification:" + claim.userID.String()
		held := 0
		for _, site := range sites {
			// sites_check2: enabled=false goes with status='disabled'.
			command, err := tx.Exec(ctx, `UPDATE sites SET
				enabled=CASE WHEN $7 THEN false ELSE enabled END,
				status=CASE WHEN $7 THEN 'disabled' ELSE status END,
				lock_reason=CASE WHEN $3 THEN $4 ELSE lock_reason END,
				locked_at=CASE WHEN $3 THEN $5 ELSE locked_at END,
				locked_by_user_id=CASE WHEN $3 THEN $6 ELSE locked_by_user_id END,
				revision=revision+1,updated_by_user_id=$6,updated_at=$5
				WHERE id=$1 AND revision=$2 AND deleted_at IS NULL`,
				site.id, site.revision, site.unlocked, SecondaryVerificationLockReason, now, claim.operator, site.enabled)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO identity_secondary_verification_site_holds
				(site_id,held_at,scope_id,user_id,request_revision,disabled_site,locked_site) VALUES($1,$2,$3,$4,$5,$6,$7)`,
				site.id, now, claim.scopeID, claim.userID, claim.revision, site.enabled, site.unlocked); err != nil {
				return err
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: claim.scopeID, Action: "site.lock", ResourceType: "site",
				ResourceID: site.id.String(), RequestID: requestID, Result: "success", Payload: map[string]any{
					"version": site.revision + 1, "locked": site.unlocked, "disabled": site.enabled,
					"reason": SecondaryVerificationLockReason, "trigger": SecondaryVerificationEventType}}); err != nil {
				return err
			}
			held++
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_user_secondary_verification SET enforced_at=COALESCE(enforced_at,$3)
			WHERE scope_id=$1 AND user_id=$2`, claim.scopeID, claim.userID, now); err != nil {
			return err
		}
		if held > 0 {
			if err := republisher.RepublishNowTx(ctx, tx, SecondaryVerificationRepublish{ScopeID: claim.scopeID, UserID: claim.userID,
				FromRevision: fromRevision, Operation: SecondaryVerificationOperationDisable, RequestID: requestID}); err != nil {
				return fmt.Errorf("republish stopped sites: %w", err)
			}
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: claim.scopeID, Action: "identity.user.secondary_verification.enforce",
			ResourceType: "user", ResourceID: claim.userID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"revision": claim.revision, "stopped_sites": held, "republished": held > 0}})
	})
	return handled, err
}

func (s *Store) releaseOneSecondaryVerification(ctx context.Context, republisher SecondaryVerificationRepublisher) (bool, error) {
	handled := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC().Truncate(time.Microsecond)
		claim, found, err := s.claimSecondaryVerificationTx(ctx, tx, `NOT COALESCE((`+secondaryVerificationDueSQL+`),false)
			AND EXISTS(SELECT 1 FROM identity_secondary_verification_site_holds hold WHERE `+releasableHoldSQL+`)`, now)
		if err != nil || !found {
			return err
		}
		handled = true
		fromRevision, err := lockConfigurationScopeTx(ctx, tx, claim.scopeID)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT hold.site_id,hold.held_at,hold.disabled_site,hold.locked_site
			FROM identity_user_secondary_verification v JOIN identity_secondary_verification_site_holds hold ON `+releasableHoldSQL+`
			JOIN sites site ON site.id=hold.site_id
			WHERE v.scope_id=$1 AND v.user_id=$2 ORDER BY hold.site_id FOR UPDATE OF hold,site`, claim.scopeID, claim.userID)
		if err != nil {
			return err
		}
		type held struct {
			siteID           uuid.UUID
			heldAt           time.Time
			disabled, locked bool
		}
		holds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (held, error) {
			var item held
			return item, row.Scan(&item.siteID, &item.heldAt, &item.disabled, &item.locked)
		})
		if err != nil {
			return err
		}
		requestID := "secondary-verification-release:" + claim.userID.String()
		restored := 0
		for _, hold := range holds {
			// Undo only our change, and only while the site still carries our
			// lock: an administrator who has since unlocked or re-locked it
			// for another reason owns the site's state now.
			command, err := tx.Exec(ctx, `UPDATE sites SET
				enabled=CASE WHEN $2 AND status='disabled' THEN true ELSE enabled END,
				status=CASE WHEN $2 AND status='disabled' THEN 'active' ELSE status END,
				lock_reason=CASE WHEN $3 THEN NULL ELSE lock_reason END,
				locked_at=CASE WHEN $3 THEN NULL ELSE locked_at END,
				locked_by_user_id=CASE WHEN $3 THEN NULL ELSE locked_by_user_id END,
				revision=revision+1,updated_at=$5
				WHERE id=$1 AND deleted_at IS NULL AND (NOT $3 OR lock_reason=$4)`,
				hold.siteID, hold.disabled, hold.locked, SecondaryVerificationLockReason, now)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE identity_secondary_verification_site_holds SET released_at=$3
				WHERE site_id=$1 AND held_at=$2`, hold.siteID, hold.heldAt, now); err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				continue
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: claim.scopeID, Action: "site.unlock", ResourceType: "site",
				ResourceID: hold.siteID.String(), RequestID: requestID, Result: "success", Payload: map[string]any{
					"unlocked": hold.locked, "enabled": hold.disabled, "trigger": SecondaryVerificationEventType}}); err != nil {
				return err
			}
			restored++
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_user_secondary_verification SET enforced_at=NULL
			WHERE scope_id=$1 AND user_id=$2 AND NOT EXISTS(SELECT 1 FROM identity_secondary_verification_site_holds hold
			  WHERE hold.scope_id=$1 AND hold.user_id=$2 AND hold.released_at IS NULL)`, claim.scopeID, claim.userID); err != nil {
			return err
		}
		if restored > 0 {
			if err := republisher.RepublishNowTx(ctx, tx, SecondaryVerificationRepublish{ScopeID: claim.scopeID, UserID: claim.userID,
				FromRevision: fromRevision, Operation: SecondaryVerificationOperationEnable, RequestID: requestID}); err != nil {
				return fmt.Errorf("republish restored sites: %w", err)
			}
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: claim.scopeID, Action: "identity.user.secondary_verification.release",
			ResourceType: "user", ResourceID: claim.userID.String(), RequestID: requestID, Result: "success",
			Payload: map[string]any{"revision": claim.revision, "restored_sites": restored, "republished": restored > 0}})
	})
	return handled, err
}
