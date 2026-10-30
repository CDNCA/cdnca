//go:build integration

package node

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestEnsureLineGroupAddressesKept: an update that drops a secondary IP (or
// primary IP) a current line-group revision still uses for this node is
// refused with ErrAddressInUse.
func TestEnsureLineGroupAddressesKept(t *testing.T) {
	pool := nodeAddressTestPool(t)
	ctx := t.Context()
	scopeID, userID, nodeID, groupID, endpointID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'addr-in-use','addr','unused')`, []any{userID}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4)
			  VALUES($1,$2,'addr node','active',$3,1,'192.0.2.60')`, []any{nodeID, scopeID, userID}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,region,resolved_value,ipv4_resolved_value,
			  current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			  VALUES($1,$2,'addr group','','lg-addr-in-use','v4-addr-in-use',1,$3,$3,now(),now())`, []any{groupID, scopeID, userID}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,region,resolved_value,
			  ipv4_resolved_value,probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,
			  failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			  VALUES($1,$2,1,'addr group','','lg-addr-in-use','v4-addr-in-use',10000,3000,3,3,0,0,1,$3,$4,now())`,
				[]any{groupID, scopeID, make([]byte, 32), userID}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,
			  address_family,port,priority,weight,enabled) VALUES($1,$2,$3,$4,1,'198.51.100.60',4,443,0,1,true)`,
				[]any{endpointID, nodeID, scopeID, groupID}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
			  consecutive_successes,consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			  SELECT $1,$2,1,$3,'unknown',0,0,0,created_at,1,created_at,created_at
			  FROM node_line_group_revisions WHERE line_group_id=$2`, []any{scopeID, groupID, endpointID}},
			{`UPDATE node_line_group_revisions SET sealed_at=created_at WHERE line_group_id=$1`, []any{groupID}},
		} {
			if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(NewStore(pool))
	actor := Actor{UserID: userID, ScopeID: scopeID}
	current, err := service.store.Get(ctx, scopeID, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	update := func(key string, settings NodeManagementSettings) error {
		_, err := service.UpdateNode(ctx, actor, UpdateRequest{ID: nodeID, ExpectedRevision: current.Revision,
			Fields: UpdateFields{ManagementSettings: &settings}, IdempotencyKey: key, RequestID: key})
		return err
	}
	withSecondary := current.ManagementSettings
	withSecondary.SecondaryIPs = []string{"198.51.100.60"}
	if err := update("addr-add", withSecondary); err != nil {
		t.Fatalf("add the secondary IP: %v", err)
	}
	if current, err = service.store.Get(ctx, scopeID, nodeID); err != nil {
		t.Fatal(err)
	}
	dropped := current.ManagementSettings
	dropped.SecondaryIPs = []string{}
	if err := update("addr-drop", dropped); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("dropping an in-use secondary IP: %v, want ErrAddressInUse", err)
	}
}

// nodeAddressTestPool is a fully migrated private schema.
func nodeAddressTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "node_address_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^node_address_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
