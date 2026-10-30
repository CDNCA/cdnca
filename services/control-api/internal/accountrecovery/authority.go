package accountrecovery

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type accountRecoveryRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func beginAccountRecoveryAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	operation iamstage2b.Operation,
	scopes []uuid.UUID,
) ([]uuid.UUID, error) {
	locked, err := iamstage2b.BeginAuthorityMutation(ctx, tx, operation, scopes)
	if err != nil {
		return nil, ErrUnavailable
	}
	return locked, nil
}

func assertAccountRecoveryAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	operation iamstage2b.Operation,
	scopes []uuid.UUID,
) error {
	if err := iamstage2b.AssertAuthorityMutation(ctx, tx, operation, scopes); err != nil {
		return ErrUnavailable
	}
	return nil
}

func accountRecoveryAuthorityScopes(
	ctx context.Context,
	query accountRecoveryRowQuerier,
	userID uuid.UUID,
	inputScopeID uuid.UUID,
) ([]uuid.UUID, error) {
	var scopes []uuid.UUID
	err := query.QueryRow(ctx, `SELECT array_agg(authority_scope.scope_id ORDER BY authority_scope.scope_id)
		FROM (
			SELECT $2::uuid AS scope_id
			UNION
			SELECT membership.scope_id FROM memberships membership WHERE membership.user_id=$1
			UNION
			SELECT session.scope_id FROM auth_sessions session WHERE session.user_id=$1
		) authority_scope`, userID, inputScopeID).Scan(&scopes)
	if err != nil {
		return nil, err
	}
	return scopes, nil
}

func sameChallengeHint(
	before challengeRecord,
	beforeErr error,
	after challengeRecord,
	afterErr error,
) bool {
	beforeMissing := errors.Is(beforeErr, pgx.ErrNoRows)
	afterMissing := errors.Is(afterErr, pgx.ErrNoRows)
	if beforeMissing || afterMissing {
		return beforeMissing && afterMissing
	}
	return beforeErr == nil && afterErr == nil && before.ID == after.ID && before.UserID == after.UserID
}

func stableAccountRecoveryError(err error) error {
	if err == nil || errors.Is(err, ErrUnavailable) {
		return err
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		return ErrUnavailable
	}
	return err
}
