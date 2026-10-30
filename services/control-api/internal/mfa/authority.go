package mfa

import (
	"bytes"
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type mfaRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func beginMFAMutation(
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

func assertMFAMutation(
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

func assertMFATenantAuthorityMutation(
	ctx context.Context,
	tx pgx.Tx,
	operation iamstage2b.Operation,
	lockedScopes []uuid.UUID,
	actorScopeID uuid.UUID,
	tenantID uuid.UUID,
	expectedTenantScopeID uuid.UUID,
) error {
	currentTenantScopeID, err := mfaTenantAuthorityScope(ctx, tx, tenantID)
	if err != nil || currentTenantScopeID != expectedTenantScopeID ||
		!containsMFAScope(lockedScopes, actorScopeID) ||
		!containsMFAScope(lockedScopes, currentTenantScopeID) {
		return ErrUnavailable
	}
	return assertMFAMutation(ctx, tx, operation, lockedScopes)
}

func mfaTenantAuthorityScope(ctx context.Context, query mfaRowQuerier, tenantID uuid.UUID) (uuid.UUID, error) {
	var scopeID uuid.UUID
	err := query.QueryRow(ctx, `SELECT scope.id FROM access_scopes scope
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE scope.kind='tenant' AND scope.tenant_id=$1`, tenantID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrTenantUnavailable
	}
	return scopeID, err
}

func validCanonicalMFAScopes(scopes []uuid.UUID) bool {
	if len(scopes) < 1 || len(scopes) > 64 {
		return false
	}
	for index, scopeID := range scopes {
		if scopeID == uuid.Nil || index > 0 && bytes.Compare(scopes[index-1][:], scopeID[:]) >= 0 {
			return false
		}
	}
	return true
}

func containsMFAScope(scopes []uuid.UUID, required uuid.UUID) bool {
	for _, scopeID := range scopes {
		if scopeID == required {
			return true
		}
	}
	return false
}

func stableMFAError(err error) error {
	if err == nil || errors.Is(err, ErrUnavailable) {
		return err
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		return ErrUnavailable
	}
	return err
}
