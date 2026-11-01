package systemsettings

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// logscan 10-31（73 19:21 两次 40P01）：authorize 先 access_scopes 再 users 加
// FOR UPDATE，会话鉴权按 session,user_row,membership,scope 加 KEY SHARE/SHARE，
// 两边锁序相反成环。authorize 只读这三行，持有期间会话鉴权必须能拿到共享锁。
func TestAuthorizeDoesNotBlockSessionAuthenticationLocks(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL);
		INSERT INTO users(id,username,display_name,password_hash,status) VALUES($2,'logscan-lock-owner','Lock owner','not-used','active');
		INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active');
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($3,$1,'platform_owner','Integration role',true);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($3,'system_configuration.read') ON CONFLICT DO NOTHING;
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		pgx.QueryExecModeSimpleProtocol, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}

	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if err := authorize(ctx, holder, actor, "system_configuration.read"); err != nil {
		t.Fatalf("authorize: %v", err)
	}

	for _, statement := range []string{
		`SELECT 1 FROM users user_row JOIN memberships membership ON membership.user_id=user_row.id
			JOIN access_scopes scope ON scope.id=membership.scope_id
			WHERE user_row.id=$1 AND scope.id=$2 FOR KEY SHARE OF user_row,membership,scope`,
		`SELECT 1 FROM users account JOIN memberships membership ON membership.user_id=account.id
			JOIN access_scopes scope ON scope.id=membership.scope_id
			WHERE account.id=$1 AND scope.id=$2 FOR SHARE OF account,membership,scope`,
	} {
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='1s'`); err != nil {
				return err
			}
			var one int
			return tx.QueryRow(ctx, statement, userID, scopeID).Scan(&one)
		})
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			t.Fatalf("session lock blocked by authorize (lock order inversion): %s", statement)
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	// authorize still keeps the actor's status from changing until it commits.
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout='500ms'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, userID)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("status update during authorize = %v, want lock timeout", err)
	}
}
