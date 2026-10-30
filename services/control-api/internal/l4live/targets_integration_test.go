//go:build integration

package l4live

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	schema := "l4live_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	config, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

// The live list targets the active nodes holding the scope's configuration,
// with the version of L4_LIVE_CONNECTIONS their latest session declared.
// Rows are seeded with triggers off: only the read side is tested.
func TestLoadTargetsReadsScopeNodesAndLatestSessionCapability(t *testing.T) {
	pool := integrationPool(t)
	ctx := t.Context()
	scope, other, user := uuid.New(), uuid.New(), uuid.New()
	upgraded, listOnly, legacy, disabled, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	snapshot := func(version uint32) []byte {
		features := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, ApiVersion: 7}}
		if version != 0 {
			features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS, ApiVersion: version})
		}
		payload, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: "1.0.35", Features: features})
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, err := tx.Exec(ctx, sql, args...); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$3),($2,'tenant',$4)`, scope, other, uuid.New(), uuid.New())
		exec(`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES($1,$2,'live','x',now(),now())`,
			user, "live-"+user.String()[:8])
		for index, node := range []struct {
			id    uuid.UUID
			state string
			scope uuid.UUID
		}{{upgraded, "active", scope}, {listOnly, "active", scope}, {legacy, "active", scope}, {disabled, "disabled", scope}, {foreign, "active", other}} {
			exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
				VALUES($1,$2,$3,$4,$5,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`,
				node.id, node.scope, "live-"+string(rune('a'+index)), node.state, user)
			exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at) VALUES($1,$2,$3,now())`,
				node.id, node.scope, uuid.New())
		}
		session := func(node uuid.UUID, epoch int64, caps []byte) {
			digest := sha256.Sum256(caps)
			exec(`INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,certificate_sha256,
				artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,capabilities_sha256,
				facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,$2,$3,$4,'k',1,0,$5,$4,'\x00',$4,'gw','gw-1',now())`, node, epoch, uuid.New(), digest[:], caps)
		}
		session(upgraded, 1, snapshot(0))
		session(upgraded, 2, snapshot(2)) // upgraded in place: the latest session counts
		session(listOnly, 1, snapshot(1))
		session(legacy, 1, snapshot(0))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(pool, requesterFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	targets, err := service.loadTargets(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uuid.UUID]uint32{}
	for _, item := range targets {
		got[item.id] = item.version
	}
	if len(got) != 3 || got[upgraded] != 2 || got[listOnly] != 1 || got[legacy] != 0 {
		t.Fatalf("targets = %+v", targets)
	}
}
