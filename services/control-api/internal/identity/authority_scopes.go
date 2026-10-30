package identity

import (
	"bytes"
	"context"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type authorityScopeQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func collectUserAuthorityScopes(
	ctx context.Context,
	querier authorityScopeQuerier,
	userID uuid.UUID,
) ([]uuid.UUID, error) {
	rows, err := querier.Query(ctx, `SELECT scope_id FROM (
		SELECT scope_id FROM memberships WHERE user_id=$1
		UNION
		SELECT scope_id FROM auth_sessions WHERE user_id=$1
	) authority_scopes ORDER BY scope_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scopes := make([]uuid.UUID, 0)
	for rows.Next() {
		var scopeID uuid.UUID
		if err := rows.Scan(&scopeID); err != nil {
			return nil, err
		}
		scopes = append(scopes, scopeID)
	}
	return scopes, rows.Err()
}

func collectSessionFamilyAuthorityScopes(
	ctx context.Context,
	querier authorityScopeQuerier,
	tokenHash []byte,
) (uuid.UUID, []uuid.UUID, error) {
	rows, err := querier.Query(ctx, `SELECT token.family_id,family.scope_id
		FROM auth_sessions token
		JOIN auth_sessions family ON family.family_id=token.family_id
		WHERE token.refresh_token_hash=$1
		GROUP BY token.family_id,family.scope_id
		ORDER BY family.scope_id`, tokenHash)
	if err != nil {
		return uuid.Nil, nil, err
	}
	defer rows.Close()
	var familyID uuid.UUID
	scopes := make([]uuid.UUID, 0)
	for rows.Next() {
		var currentFamilyID, scopeID uuid.UUID
		if err := rows.Scan(&currentFamilyID, &scopeID); err != nil {
			return uuid.Nil, nil, err
		}
		if familyID != uuid.Nil && familyID != currentFamilyID {
			return uuid.Nil, nil, ErrConflict
		}
		familyID = currentFamilyID
		scopes = append(scopes, scopeID)
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, nil, err
	}
	return familyID, scopes, nil
}

func mergeAuthorityScopes(scopes []uuid.UUID, extras ...uuid.UUID) []uuid.UUID {
	unique := make(map[uuid.UUID]struct{}, len(scopes)+len(extras))
	for _, scopeID := range scopes {
		unique[scopeID] = struct{}{}
	}
	for _, scopeID := range extras {
		unique[scopeID] = struct{}{}
	}
	result := make([]uuid.UUID, 0, len(unique))
	for scopeID := range unique {
		result = append(result, scopeID)
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i][:], result[j][:]) < 0
	})
	return result
}

func equalAuthorityScopes(left, right []uuid.UUID) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
