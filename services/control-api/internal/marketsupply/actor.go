package marketsupply

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ensureActor returns the platform service account with a live session,
// creating the account on first use. The session's refresh token is random
// and discarded, so it only authorizes this process's own service calls.
func (s *Service) ensureActor(ctx context.Context) (serviceActor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC().Truncate(time.Microsecond)
	if s.actor != nil && now.Add(sessionRenewAt).Before(s.actor.expiresAt) {
		return *s.actor, nil
	}
	var platform uuid.UUID
	if err := s.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return serviceActor{}, ErrNoPlatform
		}
		return serviceActor{}, err
	}
	actor := serviceActor{scopeID: platform, expiresAt: now.Add(sessionTTL)}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationSessionCreate,
			[]uuid.UUID{platform}); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT account.id FROM users account
			JOIN memberships membership ON membership.user_id=account.id AND membership.scope_id=$2
			WHERE account.username=$1`, ServiceUsername, platform).Scan(&actor.userID)
		if errors.Is(err, pgx.ErrNoRows) {
			err = createServiceAccount(ctx, tx, platform, now, &actor.userID)
		}
		if err != nil {
			return err
		}
		if err := syncServicePermissions(ctx, tx, platform); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$3, revocation_reason='market_supply_rotated'
			WHERE user_id=$1 AND scope_id=$2 AND revoked_at IS NULL`, actor.userID, platform, now); err != nil {
			return err
		}
		actor.sessionID = uuid.New()
		refresh := make([]byte, 32)
		if _, err := rand.Read(refresh); err != nil {
			return err
		}
		digest := sha256.Sum256(refresh)
		_, err = tx.Exec(ctx, `INSERT INTO auth_sessions (
				id,family_id,user_id,scope_id,refresh_token_hash,user_agent,created_at,expires_at
			) VALUES ($1,$2,$3,$4,$5,'market-supply',$6,$7)`,
			actor.sessionID, uuid.New(), actor.userID, platform, digest[:], now, actor.expiresAt)
		return err
	})
	if err != nil {
		return serviceActor{}, err
	}
	s.actor = &actor
	return actor, nil
}

// syncServicePermissions makes the service role hold exactly
// servicePermissions, so upgrades can widen or narrow it.
func syncServicePermissions(ctx context.Context, tx pgx.Tx, platform uuid.UUID) error {
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name=$2`,
		platform, serviceRoleName).Scan(&roleID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1 AND NOT (permission_name = ANY($2::text[]))`,
		roleID, servicePermissions); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO role_permissions (role_id,permission_name)
		SELECT $1, name FROM permissions WHERE name = ANY($2::text[]) ON CONFLICT DO NOTHING`,
		roleID, servicePermissions)
	return err
}

func createServiceAccount(ctx context.Context, tx pgx.Tx, platform uuid.UUID, now time.Time, userID *uuid.UUID) error {
	password, err := randomSecret()
	if err != nil {
		return err
	}
	hash, err := identity.HashPassword(password)
	if err != nil {
		return err
	}
	*userID = uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO users (id,username,display_name,password_hash,created_at,updated_at)
		VALUES ($1,$2,'节点市场服务账号',$3,$4,$4)`, *userID, ServiceUsername, hash, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO memberships (scope_id,user_id,created_at) VALUES ($1,$2,$3)`,
		platform, *userID, now); err != nil {
		return err
	}
	roleID := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO roles (id,scope_id,name,description,system_role,created_at)
		VALUES ($1,$2,$3,'Node market supply service account',true,$4)
		ON CONFLICT (scope_id,name) DO NOTHING`, roleID, platform, serviceRoleName, now); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name=$2`,
		platform, serviceRoleName).Scan(&roleID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO role_assignments (scope_id,user_id,role_id,assigned_at)
		VALUES ($1,$2,$3,$4)`, platform, *userID, roleID, now); err != nil {
		return err
	}
	return audit.NewWithClock(nil, func() time.Time { return now }).Append(ctx, tx, audit.Event{
		ScopeID: platform, ActorUserID: userID, Action: "identity.service_account.create",
		ResourceType: "user", ResourceID: userID.String(), RequestID: "market-supply-bootstrap",
		Result: "success", Payload: map[string]any{"username": ServiceUsername, "role": serviceRoleName},
	})
}
