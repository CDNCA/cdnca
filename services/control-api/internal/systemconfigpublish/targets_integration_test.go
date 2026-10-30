package systemconfigpublish

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSystemConfigurationTargetsIncludeBoundPlatformNodes(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "system_config_targets_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated target schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(databaseURL)
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
		t.Fatal(err)
	}
	userID, platformScope, tenantScope, otherScope := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'target-owner','Target owner','test-only')`, []any{userID}},
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScope}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Target tenant'),($2,'Other tenant')`, []any{tenantScope, otherScope}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1),($2,'tenant',$2)`, []any{tenantScope, otherScope}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$4),($2,$4),($3,$4)`, []any{platformScope, tenantScope, otherScope, userID}},
		{`WITH site AS (
		  INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		  VALUES($1,1,$2,$3,'system-target.example.test',ARRAY['http://192.0.2.1'],ARRAY['192.0.2.1'],$3,$3) RETURNING id
		), pool AS (INSERT INTO site_origin_pools(site_id) SELECT id FROM site RETURNING site_id)
		INSERT INTO site_origins(site_id,position,host,port) SELECT site_id,1,'192.0.2.1',80 FROM pool`, []any{uuid.New(), tenantScope, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	displayID := 0
	addNode := func(ownerScope uuid.UUID, state string, binding *uuid.UUID) uuid.UUID {
		t.Helper()
		id := uuid.New()
		displayID++
		if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,$4,$5,$6)`, id, ownerScope, id.String(), state, userID, displayID); err != nil {
			t.Fatal(err)
		}
		if binding != nil {
			if _, err := pool.Exec(ctx, `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,now())`, id, *binding); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	boundPlatform := addNode(platformScope, "active", &tenantScope)
	addNode(platformScope, "active", nil)
	addNode(platformScope, "active", &otherScope)
	addNode(otherScope, "active", &tenantScope)
	for _, state := range []string{"pending", "draining", "disabled", "retired"} {
		addNode(platformScope, state, &tenantScope)
	}
	load := func(want []uuid.UUID, verifyLock bool) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		targets, err := loadTargets(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		slices.SortFunc(want, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
		if len(targets) != 1 || targets[0].scopeID != tenantScope || !slices.Equal(targets[0].nodeIDs, want) {
			t.Fatalf("system configuration targets=%+v, want tenant %s nodes %v", targets, tenantScope, want)
		}
		if verifyLock {
			err := pgx.BeginFunc(ctx, pool, func(other pgx.Tx) error {
				var id uuid.UUID
				return other.QueryRow(ctx, `SELECT node_id FROM node_config_state WHERE node_id=$1 FOR UPDATE NOWAIT`, boundPlatform).Scan(&id)
			})
			var locked *pgconn.PgError
			if !errors.As(err, &locked) || locked.Code != "55P03" {
				t.Fatalf("platform binding was not held through publication transaction: %v", err)
			}
		}
	}
	load([]uuid.UUID{boundPlatform}, true)
	legacyTenant := addNode(tenantScope, "active", nil)
	load([]uuid.UUID{boundPlatform, legacyTenant}, true)
	if _, err := pool.Exec(ctx, `UPDATE nodes SET admin_state='disabled' WHERE id=$1`, boundPlatform); err != nil {
		t.Fatal(err)
	}
	load([]uuid.UUID{legacyTenant}, false)
	var claimCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_config_state WHERE node_id=$1`, legacyTenant).Scan(&claimCount); err != nil || claimCount != 0 {
		t.Fatalf("discovery claimed an unbound legacy node: count=%d err=%v", claimCount, err)
	}
}

type recordingNodeMonitoringEnqueuer struct {
	nodeIDs   []string
	artifacts []*agentv1.NodeMonitoringArtifact
}

func (enqueuer *recordingNodeMonitoringEnqueuer) EnqueueNodeMonitoringArtifact(
	_ context.Context, _ pgx.Tx, artifact *agentv1.NodeMonitoringArtifact,
) error {
	enqueuer.nodeIDs = append(enqueuer.nodeIDs, artifact.NodeId)
	enqueuer.artifacts = append(enqueuer.artifacts, artifact)
	return nil
}

func TestSystemConfigurationNodeMonitoringTargetsOnlyServingNodes(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "system_config_monitoring_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated monitoring target schema: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(databaseURL)
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
		t.Fatal(err)
	}
	userID, platformScope, configID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'monitor-owner','Monitor owner','test-only')`, []any{userID}},
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{platformScope}},
		{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
			generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'serving-config',$3,'monitor-test','1','releasable','monitor-serving-config',$3,$4,$4)`,
			[]any{configID, platformScope, make([]byte, 32), now}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	displayID := 0
	addNode := func(state string, binding bool, serving bool) uuid.UUID {
		t.Helper()
		id := uuid.New()
		displayID++
		if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,$4,$5,$6)`, id, platformScope, id.String(), state, userID, displayID); err != nil {
			t.Fatal(err)
		}
		if binding {
			var current *uuid.UUID
			if serving {
				current = &configID
			}
			if _, err := pool.Exec(ctx, `INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
				VALUES($1,$2,$3,$4)`, id, platformScope, current, now); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	servingActive := addNode("active", true, true)
	addNode("active", false, false) // freshly enrolled, never configured
	addNode("active", true, false)  // bound but no activation yet
	for _, state := range []string{"pending", "draining", "disabled", "retired"} {
		addNode(state, true, true)
	}
	enqueuer := &recordingNodeMonitoringEnqueuer{}
	service := &Service{pool: pool, nodeMonitoring: enqueuer}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return service.publishNodeMonitoring(ctx, tx, systemconfig.ActivationPublicationRequest{
			Actor:    systemconfig.Actor{UserID: userID, ScopeID: platformScope, ScopeKind: "platform"},
			Revision: 1, SnapshotSHA256: strings.Repeat("ab", 32),
			Configuration: systemconfig.ProjectBootstrapConfiguration(), ActivatedAt: now,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(enqueuer.nodeIDs, []string{servingActive.String()}) {
		t.Fatalf("node monitoring activation targeted %v, want only serving active node %s", enqueuer.nodeIDs, servingActive)
	}
	if enqueuer.artifacts[0].ConfigRevision != 1 {
		t.Fatalf("node without override got revision %d, want platform revision 1", enqueuer.artifacts[0].ConfigRevision)
	}

	// A node override overlays the platform policy and shifts that node's
	// delivered revision by its own override revision.
	overridden := addNode("active", true, true)
	if _, err := pool.Exec(ctx, `INSERT INTO node_monitoring_overrides(node_id,scope_id,protocol,probe_timeout_ms,monitor_port,
		revision,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'http',2500,8080,1,$3,$4,$4)`,
		overridden, platformScope, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_monitoring_overrides SET revision=2,updated_at=$2 WHERE node_id=$1`,
		overridden, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	enqueuer = &recordingNodeMonitoringEnqueuer{}
	service = &Service{pool: pool, nodeMonitoring: enqueuer}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return service.publishNodeMonitoring(ctx, tx, systemconfig.ActivationPublicationRequest{
			Actor:    systemconfig.Actor{UserID: userID, ScopeID: platformScope, ScopeKind: "platform"},
			Revision: 3, SnapshotSHA256: strings.Repeat("ab", 32),
			Configuration: systemconfig.ProjectBootstrapConfiguration(), ActivatedAt: now.Add(time.Hour),
		})
	}); err != nil {
		t.Fatal(err)
	}
	revisions := map[string]uint64{}
	for _, artifact := range enqueuer.artifacts {
		revisions[artifact.NodeId] = artifact.ConfigRevision
		var payload struct {
			Protocol       string  `json:"protocol"`
			ProbeTimeoutMS int     `json:"probe_timeout_ms"`
			MonitorPort    *uint16 `json:"monitor_port"`
		}
		if err := json.Unmarshal(artifact.CanonicalConfigJson, &payload); err != nil {
			t.Fatal(err)
		}
		if artifact.NodeId == overridden.String() &&
			(payload.Protocol != "http" || payload.ProbeTimeoutMS != 2500 || payload.MonitorPort == nil || *payload.MonitorPort != 8080) {
			t.Fatalf("override was not overlaid: %s", artifact.CanonicalConfigJson)
		}
		if artifact.NodeId == servingActive.String() && (payload.Protocol == "http" || payload.MonitorPort != nil) {
			t.Fatalf("override leaked to another node: %s", artifact.CanonicalConfigJson)
		}
	}
	if len(revisions) != 2 || revisions[servingActive.String()] != 3 || revisions[overridden.String()] != 5 {
		t.Fatalf("effective revisions = %v, want platform 3 and override 3+2", revisions)
	}
}
