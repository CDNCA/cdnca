package nodednspupprobe

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sessionTestFeatures struct{}

func (sessionTestFeatures) ReadValidFeatures(context.Context, pgx.Tx) (map[string]bool, error) {
	return map[string]bool{dnspupprobe.Feature: true}, nil
}

func execSessionTest(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Fields(query)[0], err)
	}
}

// saving the node probing settings with a session another tab's token refresh
// replaced (still unexpired, unrevoked) succeeds like every other API; revoked, expired and role-less sessions
// are refused.
func TestNodeProbeSettingsAcceptRefreshedSession(t *testing.T) {
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	scope, user, role, old, next := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	oldRefresh, nextRefresh := sha256.Sum256(old[:]), sha256.Sum256(next[:])
	execSessionTest(t, pool, `INSERT INTO access_scopes(id,kind,created_at) VALUES($1,'platform',$2)`, scope, now)
	execSessionTest(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($1,$2,$2,'not-used','active',$3,$3)`, user, "ndp-"+strings.ReplaceAll(user.String(), "-", "")[:20], now)
	execSessionTest(t, pool, `INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$3)`, scope, user, now)
	execSessionTest(t, pool, `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$1,$2,$3,$4,$5,$6)`, old, user, scope, oldRefresh[:], now.Add(-time.Hour), now.Add(30*24*time.Hour))
	// The console's refresh: a new session of the family, the old one used and replaced.
	execSessionTest(t, pool, `INSERT INTO auth_sessions(id,family_id,parent_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$2,$3,$4,$5,$6,$7)`, next, old, user, scope, nextRefresh[:], now.Add(-time.Minute), now.Add(30*24*time.Hour))
	execSessionTest(t, pool, `UPDATE auth_sessions SET used_at=$2, replaced_by_id=$3 WHERE id=$1`, old, now.Add(-time.Minute), next)
	execSessionTest(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES($1,$2,$3,'ndp',true,$4)`,
		role, scope, "ndp_"+strings.ReplaceAll(role.String(), "-", "")[:20], now)
	execSessionTest(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, role, dnspupprobe.PermissionManage)
	execSessionTest(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`, scope, user, role, now)

	store, err := NewStore(pool, sessionTestFeatures{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	settings, _, err := ReadSettings(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	settings.IntervalSeconds = 60
	replaced := Actor{UserID: user, ScopeID: scope, SessionID: old}
	current := Actor{UserID: user, ScopeID: scope, SessionID: next}
	saved, err := store.Update(ctx, replaced, "node-after-refresh", settings)
	if err != nil || saved.IntervalSeconds != 60 {
		t.Fatalf("replaced session save %+v %v", saved, err)
	}
	if again, err := store.Update(ctx, replaced, "node-after-refresh", settings); err != nil || again.Revision != saved.Revision {
		t.Fatalf("replaced session replay %+v %v", again, err)
	}
	if _, err := store.Status(ctx, current); err != nil {
		t.Fatalf("current session read: %v", err)
	}

	execSessionTest(t, pool, `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`, next, now.Add(-time.Second))
	if _, err := store.Update(ctx, current, "node-expired", settings); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expired session save: %v", err)
	}
	execSessionTest(t, pool, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, scope, user)
	if _, err := store.Update(ctx, replaced, "node-no-role", settings); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("session without the role: %v", err)
	}
	execSessionTest(t, pool, `UPDATE auth_sessions SET revoked_at=$2, revocation_reason='logout' WHERE id=$1`, old, now)
	if _, err := store.Update(ctx, replaced, "node-revoked", settings); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked session save: %v", err)
	}
}
