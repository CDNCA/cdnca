package dashboard

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newProfilePool migrates an isolated schema without the shared dashboard
// fixture, so the login-profile projection can be checked on its own.
func newProfilePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dashboard_profile_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestPostgresAdminProfileReturnsLoginRegionAndCity(t *testing.T) {
	pool := newProfilePool(t)
	ctx := context.Background()
	scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'platform',NULL,$4);
		INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
			VALUES($2,'profile-admin','Profile admin','unused','active',$4,$4);
		INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',$4);
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,source_ip,created_at,expires_at)
			VALUES($3,$3,$2,$1,$5,'203.0.113.61',$4,$6)`, pgx.QueryExecModeSimpleProtocol,
		scopeID, userID, sessionID, now, digest("profile-refresh"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	loginAt := now.Add(-time.Minute)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return audit.NewWithClock(pool, func() time.Time { return loginAt }).Append(ctx, tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &userID, Action: "auth.login", ResourceType: "session_family",
			ResourceID: sessionID.String(), RequestID: "profile-geo-login", Result: "success",
			Payload: map[string]any{
				"session_id": sessionID.String(), "geo_code": "CN", "geo_region": "山东省", "geo_city": "潍坊市",
				"geo_resolution": "matched",
			},
		})
	}); err != nil {
		t.Fatal(err)
	}

	var profile AdminProfileStats
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		profile, err = readAdminProfile(ctx, tx, scopeID, userID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if profile.LastLoginAt == nil || !profile.LastLoginAt.Equal(loginAt) || profile.LastLoginIP != "203.0.113.61" ||
		profile.LastLoginGeo != "CN" || profile.LastLoginRegion != "山东省" || profile.LastLoginCity != "潍坊市" {
		t.Fatalf("admin login profile = %#v", profile)
	}
}
