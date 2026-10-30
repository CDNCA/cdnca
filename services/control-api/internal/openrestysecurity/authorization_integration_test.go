package openrestysecurity

import (
	"bytes"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIAMTxAuthorizerAuthorizesPlatformSessionOnlyForItsOwnScope(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(t.Context()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "openresty_platform_auth_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = admin.Exec(t.Context(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = identifier
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		_, _ = admin.Exec(t.Context(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupContext, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanupContext, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 31, 3, 30, 0, 0, time.UTC)
	scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tenantID, tenantScopeID, platformNodeID, tenantNodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	username := "waf_platform_" + strings.ReplaceAll(userID.String(), "-", "")[:16]
	refreshHash := sha256.Sum256([]byte("openresty-platform-session-" + sessionID.String()))
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL);
		INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
		VALUES($2,$3,'OpenResty platform session','integration-test-only',$7,$7);
		INSERT INTO memberships(scope_id,user_id,created_at) VALUES($1,$2,$7);
		INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
		VALUES($4,$1,'platform_owner','OpenResty platform integration role',true,$7);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($4,$8);
		INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$4,$7);
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($5,$6,$2,$1,$9,$7,$10);
		INSERT INTO tenants(id,display_name) VALUES($11,'OpenResty target isolation tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($12,'tenant',$11);
		INSERT INTO nodes(id,display_id,scope_id,name,region,admin_state,created_by_user_id)
		VALUES($13,101,$1,'waf-platform-node','华东','active',$2),
		      ($14,102,$12,'waf-tenant-node','华南','active',$2)`,
		pgx.QueryExecModeSimpleProtocol, scopeID, userID, username, roleID, sessionID, uuid.New(), now.Add(-time.Hour),
		"platform.admin", refreshHash[:], now.Add(time.Hour), tenantID, tenantScopeID, platformNodeID, tenantNodeID); err != nil {
		t.Fatal(err)
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rawSession, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{3}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	locked, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewIAMTxAuthorizer(locked)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopePlatform,
		Permissions: []string{PermissionRead}}.WithCredential(CredentialSession, sessionID, rawSession, nil)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return authorizer.Authorize(t.Context(), tx, actor, scopeID, PermissionRead)
	}); err != nil {
		t.Fatalf("platform self-scope authorization: %v", err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		err := authorizer.Authorize(t.Context(), tx, actor, uuid.New(), PermissionRead)
		if err != ErrNotFound {
			t.Fatalf("platform cross-scope authorization error = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(pool, authorizer, integrationSealer{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := store.SearchTargets(t.Context(), SearchTargetsRequest{Actor: actor, TargetScopeID: scopeID,
		ScopeType: ScopeNode, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if nodes.Total != 1 || len(nodes.Items) != 1 || nodes.Items[0].Value != platformNodeID.String() ||
		nodes.Items[0].Label != "waf-platform-node" {
		t.Fatalf("platform node targets = %+v", nodes)
	}
	regions, err := store.SearchTargets(t.Context(), SearchTargetsRequest{Actor: actor, TargetScopeID: scopeID,
		ScopeType: ScopeRegion, Page: 1, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if regions.Total != 1 || len(regions.Items) != 1 || regions.Items[0].Value != "华东" {
		t.Fatalf("platform region targets = %+v", regions)
	}
	if _, err := store.SearchTargets(t.Context(), SearchTargetsRequest{Actor: actor, TargetScopeID: tenantScopeID,
		ScopeType: ScopeNode, Page: 1, PageSize: 20}); err != ErrNotFound {
		t.Fatalf("cross-scope target search error = %v, want ErrNotFound", err)
	}
}
