package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// VerifyPlatformPassword checks a platform administrator's password for the
// frozen console of a migration hold (fix-migrollback). It only reads: no
// session, throttle row or login record is written, because a held control
// plane must not diverge from the copy it was migrated to. The admin access
// allow-list is enforced; the caller rate-limits attempts in memory.
func (s *Service) VerifyPlatformPassword(ctx context.Context, username, password, sourceIP string) (Principal, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if len(username) < 3 || len(username) > 128 || len(password) == 0 || len(password) > 1024 {
		return Principal{}, ErrInvalidCredentials
	}
	if err := s.checkAdminAccess(ctx, "platform", sourceIP); err != nil {
		return Principal{}, err
	}
	principal := Principal{Roles: []string{}, Permissions: []string{}}
	var hash, userStatus, membershipStatus string
	err := s.store.pool.QueryRow(ctx, `
		SELECT u.id, u.display_id::text, m.scope_id, scope.kind, u.username, u.display_name, u.password_hash, u.status, m.status,
		       COALESCE(array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '{}'::text[]),
		       COALESCE(array_agg(DISTINCT rp.permission_name) FILTER (WHERE rp.permission_name IS NOT NULL), '{}'::text[])
		FROM users u
		JOIN memberships m ON m.user_id = u.id
		JOIN access_scopes scope ON scope.id = m.scope_id AND scope.kind = 'platform'
		LEFT JOIN role_assignments ra ON ra.scope_id = m.scope_id AND ra.user_id = u.id
		LEFT JOIN roles r ON r.id = ra.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE u.username = $1
		GROUP BY u.id, u.display_id, m.scope_id, scope.kind, u.username, u.display_name, u.password_hash, u.status, m.status
		LIMIT 1`, username,
	).Scan(&principal.UserID, &principal.DisplayID, &principal.ScopeID, &principal.ScopeKind, &principal.Username,
		&principal.DisplayName, &hash, &userStatus, &membershipStatus, &principal.Roles, &principal.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = VerifyPassword(s.dummyHash, password)
		return Principal{}, ErrInvalidCredentials
	}
	if err != nil {
		return Principal{}, fmt.Errorf("read platform administrator: %w", err)
	}
	if !verifyPasswordHash(hash, password).matches {
		return Principal{}, ErrInvalidCredentials
	}
	if userStatus != "active" || membershipStatus != "active" {
		return Principal{}, ErrAccountDisabled
	}
	return principal, nil
}
