package identityverification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// SelfStatus is the applicant's own verification standing. It carries no
// fingerprint, document, organization or material facts.
type SelfStatus struct {
	// PersonVerified is true once an initial personal case was approved; the
	// identity_verified_persons fact is append-only.
	PersonVerified bool
	VerifiedAt     *time.Time
	// LatestCase is the applicant's most recent case of any kind, if any.
	LatestCase *Case
}

// CurrentStatus reads the authenticated applicant's verification standing in
// their own tenant scope under the same live IAM check as reading an owned case.
func (s *Service) CurrentStatus(ctx context.Context, actor Actor) (SelfStatus, error) {
	if !validActor(actor) {
		return SelfStatus{}, ErrInvalidInput
	}
	var result SelfStatus
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeWrite(ctx, tx, actor, actor.ScopeID, permissionSelfManage); err != nil {
			return err
		}
		var approvedAt time.Time
		err := tx.QueryRow(ctx, `SELECT approved_at FROM identity_verified_persons
			WHERE tenant_scope_id=$1 AND applicant_user_id=$2`, actor.ScopeID, actor.UserID).Scan(&approvedAt)
		switch {
		case err == nil:
			verifiedAt := storeTime(approvedAt)
			result.PersonVerified, result.VerifiedAt = true, &verifiedAt
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		stored, err := scanCase(tx.QueryRow(ctx, caseQuery+`
			WHERE verification_case.tenant_scope_id=$1 AND verification_case.applicant_user_id=$2
			ORDER BY verification_case.created_at DESC,verification_case.id DESC LIMIT 1`,
			actor.ScopeID, actor.UserID))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		latest := redactCase(stored, storeTime(s.now()))
		result.LatestCase = &latest
		return nil
	})
	if err != nil {
		return SelfStatus{}, fmt.Errorf("read identity verification status: %w", mapStoreError(err))
	}
	return result, nil
}
