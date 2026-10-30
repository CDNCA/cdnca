package openrestysecurity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuleGroupStatePostgreSQLScopeBindingAndWritePermission(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "cc_toggle_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = identifier
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	refreshHash := sha256.Sum256([]byte("cc-toggle-session-" + sessionID.String()))
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
		INSERT INTO users(id,username,display_name,password_hash) VALUES($2,$3,'CC toggle operator','integration-test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($1,$2);
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($4,$1,'cc_toggle_operator','CC toggle test',true);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($4,$5),($4,$6);
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$4);
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($7,$8,$2,$1,$9,$10,$11)`, pgx.QueryExecModeSimpleProtocol,
		scopeID, userID, "cc_toggle_"+strings.ReplaceAll(userID.String(), "-", ""), roleID,
		PermissionRead, PermissionManage, sessionID, uuid.New(), refreshHash[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		tenantID, tenantScopeID := uuid.New(), uuid.New()
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO tenants(id,display_name) VALUES($1,'CC toggle tenant');
			INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
			INSERT INTO memberships(scope_id,user_id) VALUES($2,$3)`, pgx.QueryExecModeSimpleProtocol,
			tenantID, tenantScopeID, userID); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"cc_reference_matchers", "cc_reference_filters"} {
			fields, values := "field,operator,values", "'path','prefix','[\"/\"]'::jsonb"
			if table == "cc_reference_filters" {
				fields, values = "filter_type,parameters", "'req_rate','{}'::jsonb"
			}
			for _, fixture := range []struct {
				name, key string
				system    bool
				deleted   bool
			}{
				{"matching", "cc.js-verify", true, false},
				{"other", "cc.other", true, false},
				{"custom", "cc.js-verify", false, false},
				{"deleted", "cc.js-verify", true, true},
			} {
				var deletedAt *time.Time
				legacyID := "1"
				if fixture.key != "cc.js-verify" {
					legacyID = "2"
				}
				if fixture.deleted {
					deletedAt = &now
				}
				query := `INSERT INTO ` + table + `(id,scope_id,tenant_id,owner_user_id,name,` + fields + `,
					system_rule,system_rule_id,system_rule_key,created_by_user_id,updated_by_user_id,created_at,updated_at,deleted_at)
					VALUES($1,$2,$3,$4,$5,` + values + `,$6,$10,$7,$4,$4,$8,$8,$9)`
				if _, err := pool.Exec(t.Context(), query, uuid.New(), tenantScopeID, tenantID, userID,
					fixture.name, fixture.system, fixture.key, now, deletedAt, legacyID); err != nil {
					t.Fatal(err)
				}
			}
		}
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
	store, err := NewStore(pool, authorizer, integrationSealer{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: ScopePlatform,
		Permissions: []string{PermissionRead, PermissionManage}}.WithCredential(CredentialSession, sessionID, rawSession, nil)
	request := RuleGroupStateRequest{Actor: actor, TargetScopeID: scopeID, SystemRuleID: "cc.js-verify", Enabled: false}

	t.Run("logical key updates both tenant projections without unrelated rows", func(t *testing.T) {
		if err := store.SetRuleGroupEnabled(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"cc_reference_matchers", "cc_reference_filters"} {
			var changed, unrelated int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE name='matching' AND NOT enabled AND revision=2),
				count(*) FILTER (WHERE name<>'matching' AND enabled AND revision=1) FROM `+table).Scan(&changed, &unrelated); err != nil {
				t.Fatal(err)
			}
			if changed != 2 || unrelated != 6 {
				t.Fatalf("%s changed=%d unrelated=%d", table, changed, unrelated)
			}
		}
	})
	t.Run("legacy rule ID restores only matching projections", func(t *testing.T) {
		legacy := request
		legacy.SystemRuleID, legacy.Enabled = "1", true
		if err := store.SetRuleGroupEnabled(t.Context(), legacy); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"cc_reference_matchers", "cc_reference_filters"} {
			var changed, unrelated int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE name='matching' AND enabled AND revision=3),
				count(*) FILTER (WHERE name<>'matching' AND enabled AND revision=1) FROM `+table).Scan(&changed, &unrelated); err != nil {
				t.Fatal(err)
			}
			if changed != 2 || unrelated != 6 {
				t.Fatalf("%s changed=%d unrelated=%d", table, changed, unrelated)
			}
		}
	})
	t.Run("cross scope rejected", func(t *testing.T) {
		crossScope := request
		crossScope.TargetScopeID = uuid.New()
		if err := store.SetRuleGroupEnabled(t.Context(), crossScope); err == nil {
			t.Fatal("cross-scope write succeeded")
		}
	})
	t.Run("tenant cannot modify shared system projections", func(t *testing.T) {
		tenant := request
		tenant.Actor.ScopeKind = ScopeTenant
		tenantID := uuid.New()
		tenant.Actor.tenantID = &tenantID
		if err := store.SetRuleGroupEnabled(t.Context(), tenant); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant write error=%v, want permission denied", err)
		}
	})
	t.Run("read only permission cannot toggle", func(t *testing.T) {
		readOnly := request
		readOnly.Actor.Permissions = []string{PermissionRead}
		if err := store.SetRuleGroupEnabled(t.Context(), readOnly); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("read-only error=%v, want permission denied", err)
		}
	})
	t.Run("database permission revocation defeats cached permissions", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `DELETE FROM role_permissions WHERE role_id=$1 AND permission_name=$2`, roleID, PermissionManage); err != nil {
			t.Fatal(err)
		}
		if err := store.SetRuleGroupEnabled(t.Context(), request); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("revoked write permission error=%v, want permission denied", err)
		}
		for _, table := range []string{"cc_reference_matchers", "cc_reference_filters"} {
			var changed int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM `+table+` WHERE revision>3 OR NOT enabled`).Scan(&changed); err != nil {
				t.Fatal(err)
			}
			if changed != 0 {
				t.Fatalf("%s unauthorized write changed %d rows", table, changed)
			}
		}
	})
}
