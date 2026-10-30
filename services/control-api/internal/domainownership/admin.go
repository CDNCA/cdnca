package domainownership

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type AdminFilter struct {
	Apex, Status string
	Limit        int
}

// AdminListOwnerships lists proofs across accounts without their tokens.
func (s *Service) AdminListOwnerships(ctx context.Context, actor Actor, filter AdminFilter) ([]Ownership, error) {
	if filter.Status != "" && filter.Status != StatusPending && filter.Status != StatusVerified &&
		filter.Status != StatusExpired && filter.Status != StatusRevoked {
		return nil, ErrInvalidInput
	}
	apex := ""
	if filter.Apex != "" {
		var err error
		if apex, err = normalizeApex(filter.Apex); err != nil {
			return nil, ErrInvalidInput
		}
	}
	limit := filter.Limit
	if limit < 1 || limit > maxListLimit {
		limit = maxListLimit
	}
	var items []Ownership
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatform(ctx, tx, actor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+ownershipColumns+` FROM domain_ownerships
			WHERE ($1='' OR apex=$1) AND ($2='' OR status=$2)
			ORDER BY updated_at DESC, id DESC LIMIT $3`, apex, filter.Status, limit)
		if err != nil {
			return err
		}
		items, err = collectOwnerships(rows, false)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("admin list domain ownerships: %w", err)
	}
	return items, nil
}

// AdminRevokeOwnership withdraws an account's proof (appeals handled by the
// platform), audited in both the platform and the account's stream.
func (s *Service) AdminRevokeOwnership(ctx context.Context, actor Actor, id uuid.UUID, requestID string) (Ownership, error) {
	if id == uuid.Nil || !domaintrust.ValidMetadata(requestID) {
		return Ownership{}, ErrInvalidInput
	}
	var result Ownership
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatform(ctx, tx, actor); err != nil {
			return err
		}
		var scopeID uuid.UUID
		var apex string
		if err := tx.QueryRow(ctx, `SELECT scope_id,apex FROM domain_ownerships WHERE id=$1 FOR UPDATE`, id).
			Scan(&scopeID, &apex); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var err error
		result, err = revokeTx(ctx, tx, s.auditor, actor, scopeID, apex, requestID, s.clock())
		return err
	})
	if err != nil {
		return Ownership{}, fmt.Errorf("admin revoke domain ownership: %w", err)
	}
	result.Token = ""
	return result, nil
}

// AdminListSuspensions lists claim suspensions, open ones by default.
func (s *Service) AdminListSuspensions(ctx context.Context, actor Actor, includeReleased bool, limit int) ([]Suspension, error) {
	if limit < 1 || limit > maxListLimit {
		limit = maxListLimit
	}
	var items []Suspension
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatform(ctx, tx, actor); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+suspensionColumns+` FROM domain_claim_suspensions
			WHERE $1 OR released_at IS NULL ORDER BY created_at DESC, id DESC LIMIT $2`, includeReleased, limit)
		if err != nil {
			return err
		}
		items, err = scanSuspensions(rows, true)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("admin list claim suspensions: %w", err)
	}
	return items, nil
}

// AdminReleaseSuspension upholds an appeal. It is refused while another
// account still holds the domain unsuspended, because both sites would then
// serve it; the site itself stays disabled until its owner re-enables it.
func (s *Service) AdminReleaseSuspension(ctx context.Context, actor Actor, id uuid.UUID, requestID string) (Suspension, error) {
	if id == uuid.Nil || !domaintrust.ValidMetadata(requestID) {
		return Suspension{}, ErrInvalidInput
	}
	var result Suspension
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizePlatform(ctx, tx, actor); err != nil {
			return err
		}
		var item Suspension
		var claimant uuid.UUID
		err := tx.QueryRow(ctx, `SELECT `+suspensionColumns+` FROM domain_claim_suspensions WHERE id=$1 FOR UPDATE`, id).
			Scan(&item.ID, &item.ScopeID, &item.SiteID, &item.Domain, &claimant, &item.CreatedAt,
				&item.ReleasedAt, &item.ReleaseReason)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		item.ClaimantScopeID = &claimant
		if item.ReleasedAt != nil {
			result = item
			return nil
		}
		if _, err := tx.Exec(ctx, `SELECT lock_site_domains_299(ARRAY[$1::text])`, item.Domain); err != nil {
			return err
		}
		var held bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM site_domain_active active
			WHERE (active.scope_id,active.site_id) <> ($1,$2) AND (
				active.canonical_domain=$3 OR
				($3 NOT LIKE '*.%' AND active.canonical_domain='*.' || site_domain_family_299($3)) OR
				($3 LIKE '*.%' AND active.canonical_domain NOT LIKE '*.%' AND active.family_domain=substring($3 FROM 3))
			) AND NOT EXISTS (
				SELECT 1 FROM domain_claim_suspensions other
				WHERE other.scope_id=active.scope_id AND other.site_id=active.site_id AND
				      other.canonical_domain=active.canonical_domain AND other.released_at IS NULL))`,
			item.ScopeID, item.SiteID, item.Domain).Scan(&held); err != nil {
			return err
		}
		if held {
			return ErrStillClaimed
		}
		now := s.clock()
		if err := tx.QueryRow(ctx, `UPDATE domain_claim_suspensions SET released_at=$2,release_reason='admin_released',
			released_by_user_id=$3 WHERE id=$1 RETURNING released_at`, id, now, actor.UserID).Scan(&item.ReleasedAt); err != nil {
			return err
		}
		item.ReleaseReason = "admin_released"
		result = item
		return appendOrdered(ctx, tx, s.auditor, []audit.Event{
			{ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: "site.domain_claim.release",
				ResourceType: "site", ResourceID: item.SiteID.String(), RequestID: requestID, Result: "success",
				Payload: map[string]any{"domain": item.Domain, "suspension_id": id.String()}},
			{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "domain_claim.admin_release",
				ResourceType: "domain_claim_suspension", ResourceID: id.String(), RequestID: requestID, Result: "success",
				Payload: map[string]any{"domain": item.Domain, "target_scope_id": item.ScopeID.String()}},
		})
	})
	if err != nil {
		return Suspension{}, fmt.Errorf("admin release claim suspension: %w", err)
	}
	return result, nil
}
