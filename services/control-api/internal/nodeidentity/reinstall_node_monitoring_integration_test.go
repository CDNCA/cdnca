//go:build integration

package nodeidentity

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringoutbox"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

// After "重装此节点" the node's monitoring stayed
// red. The node monitoring artifact goes out once per (node, effective
// revision) through a work queue the previous host acknowledged, so the new
// host never received one and never probed. A reinstall advances the node's
// override revision (fields unchanged): a new effective revision, published
// once the new host serves. A node enrolled once is not touched.
func TestReinstallRedeliversNodeMonitoring(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	ctx := context.Background()
	activatePlatformMonitoring(t, pool)
	outbox, err := nodemonitoringoutbox.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	// claim publishes (as the outbox worker does) what reconciliation queued
	// and returns the effective revision sent to each node.
	var published uint64
	claim := func() map[uuid.UUID]uint64 {
		t.Helper()
		commands, err := outbox.ClaimCommands(ctx, uuid.New(), 32, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		sent := map[uuid.UUID]uint64{}
		for _, command := range commands {
			artifact := new(agentv1.NodeMonitoringArtifact)
			if err := proto.Unmarshal(command.Payload, artifact); err != nil {
				t.Fatal(err)
			}
			sent[command.NodeID] = artifact.ConfigRevision
			published++
			if err := outbox.MarkPublished(ctx, command, nodemonitoringoutbox.CommandStream, published); err != nil {
				t.Fatal(err)
			}
		}
		return sent
	}
	reinstalled := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	enrolledOnce := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	configs := map[uuid.UUID]uuid.UUID{}
	for index, fixture := range []identityFixture{reinstalled, enrolledOnce} {
		request := validAuthorizeRequest(t, testCSR(t, false))
		request.EnrollmentToken = fixture.token
		request.ArtifactEncryptionPublicKey = bytesOf(32, byte(50+index))
		enrollIdentity(t, service, request)
		configs[fixture.nodeID] = seedTelemetryCurrentConfig(t, pool, fixture, uuid.New(), now.Add(-time.Hour))
	}
	first := claim()
	if len(first) != 2 || first[reinstalled.nodeID] == 0 || first[reinstalled.nodeID] != first[enrolledOnce.nodeID] {
		t.Fatalf("first delivery = %v", first)
	}

	clock.set(now.Add(10 * time.Minute))
	reinstall := reenrollRequest(t, pool, reinstalled, clock)
	reinstall.EnrollmentToken = issueIdentityToken(t, pool, reinstalled, clock.now(), "re_enrollment")
	enrollIdentity(t, service, reinstall)
	// Nothing is sent before the new host serves (no OpenResty listener to probe).
	if sent := claim(); len(sent) != 0 {
		t.Fatalf("delivery before the new host serves = %v", sent)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_config_state SET current_config_version_id=$2,revision=revision+1
		WHERE node_id=$1`, reinstalled.nodeID, configs[reinstalled.nodeID]); err != nil {
		t.Fatal(err)
	}
	again := claim()
	if len(again) != 1 || again[reinstalled.nodeID] != first[reinstalled.nodeID]+1 {
		t.Fatalf("delivery after the new host serves = %v, want only the reinstalled node at revision %d",
			again, first[reinstalled.nodeID]+1)
	}
	// The override keeps inheriting every field; it is attributed to the
	// user who issued the re_enrollment token.
	var inherits bool
	var updatedBy uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT monitor_enabled IS NULL AND protocol IS NULL AND probe_timeout_ms IS NULL
		AND monitor_port IS NULL AND monitor_action IS NULL, updated_by_user_id
		FROM node_monitoring_overrides WHERE node_id=$1`, reinstalled.nodeID).Scan(&inherits, &updatedBy); err != nil ||
		!inherits || updatedBy != reinstalled.userID {
		t.Fatalf("override after reinstall: inherits=%v by=%s, %v", inherits, updatedBy, err)
	}
	var untouched int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM node_monitoring_overrides WHERE node_id=$1`,
		enrolledOnce.nodeID).Scan(&untouched); err != nil || untouched != 0 {
		t.Fatalf("overrides of the node enrolled once = %d, %v", untouched, err)
	}
}

// activatePlatformMonitoring activates the platform's bootstrap system
// configuration (node monitoring included).
func activatePlatformMonitoring(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	actor := systemconfig.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&actor.ScopeID); err != nil {
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, actor.ScopeID); err != nil {
			t.Fatal(err)
		}
	}
	roleID := uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'monitoring-owner','Monitoring owner','test-only')`, []any{actor.UserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actor.ScopeID, actor.UserID}},
		{`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, []any{roleID, actor.ScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.read'),($1,'system_configuration.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{actor.ScopeID, actor.UserID, roleID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	configuration, err := systemconfig.NewServiceWithDependencies(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	draft, err := configuration.CreateDraft(ctx, actor, systemconfig.CreateDraftRequest{
		Configuration: systemconfig.ProjectBootstrapConfiguration(), IdempotencyKey: "monitoring-draft", RequestID: "monitoring-draft",
	})
	if err != nil {
		t.Fatal(err)
	}
	checks := []systemconfig.PreflightCheck{}
	for _, name := range []string{systemconfig.PreflightSchema, systemconfig.PreflightReferences,
		systemconfig.PreflightCapacity, systemconfig.PreflightNginxSafety, systemconfig.PreflightErrorPages} {
		checks = append(checks, systemconfig.PreflightCheck{Name: name, Status: systemconfig.CheckPass})
	}
	if _, err := configuration.RecordPreflight(ctx, actor, systemconfig.RecordPreflightRequest{
		Revision: draft.Revision, ExpectedStatus: systemconfig.StatusDraft, SnapshotSHA256: draft.SnapshotSHA256,
		Checks: checks, IdempotencyKey: "monitoring-preflight", RequestID: "monitoring-preflight",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := configuration.Activate(ctx, actor, systemconfig.ActivateRequest{
		Revision: draft.Revision, IdempotencyKey: "monitoring-activate", RequestID: "monitoring-activate",
	}); err != nil {
		t.Fatal(err)
	}
}
