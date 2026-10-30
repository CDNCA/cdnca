//go:build integration

package nodescheduler

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type failingL2Auditor struct{}

func (failingL2Auditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("forced L2 audit failure")
}

func TestL2TopologyMigration241RoundTrip(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682) and later
	// migrations sit on top of 241; pin the schema head to 241 for this test.
	pool := openNodeSchedulingDatabaseThrough(t, 241)
	ctx := t.Context()
	if err := databasetest.MigrateThrough(ctx, pool, "down", 241); err != nil {
		t.Fatalf("rollback migration 241: %v", err)
	}
	var tables int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class
		WHERE relnamespace=current_schema()::regnamespace
		  AND relname IN ('l2_topology_configs','l2_topology_conditions','l2_topology_nodes','l2_topology_write_requests')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatalf("L2 tables after rollback = %d", tables)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 241); err != nil {
		t.Fatalf("reapply migration 241: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_class
		WHERE relnamespace=current_schema()::regnamespace
		  AND relname IN ('l2_topology_configs','l2_topology_conditions','l2_topology_nodes','l2_topology_write_requests')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 4 {
		t.Fatalf("L2 tables after reapply = %d", tables)
	}
}

func TestL2TopologyCRUDIsolationIdempotencyAndRollback(t *testing.T) {
	fixture := newIntegrationFixture(t)
	ctx := t.Context()
	configRequest := L2ConfigWriteRequest{
		Name: "华东 L2", Region: "华东", Remark: "主配置", Mode: L2ModeCache,
		LoadMethod: L2LoadRoundRobin, IdempotencyKey: "l2-config-create", RequestID: "l2-config-create-request",
	}
	createdConfig, err := fixture.service.PutL2Config(ctx, fixture.actor, configRequest)
	if err != nil || createdConfig.Config.Revision != 1 || createdConfig.Config.TenantScopeID != fixture.actor.ScopeID {
		t.Fatalf("create config = %#v, err = %v", createdConfig, err)
	}
	replayedConfig, err := fixture.service.PutL2Config(ctx, fixture.actor, configRequest)
	if err != nil || !replayedConfig.Replayed || replayedConfig.Config.ID != createdConfig.Config.ID {
		t.Fatalf("replay config = %#v, err = %v", replayedConfig, err)
	}
	changedConfig := configRequest
	changedConfig.Name = "changed"
	if _, err := fixture.service.PutL2Config(ctx, fixture.actor, changedConfig); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("config idempotency conflict = %v", err)
	}

	conditionRequest := L2ConditionWriteRequest{
		Name: "境外访问", Remark: "国家条件", Rules: []L2Rule{{Field: "node_country", Operator: "neq", Value: "CN"}},
		IdempotencyKey: "l2-condition-create", RequestID: "l2-condition-create-request",
	}
	createdCondition, err := fixture.service.PutL2Condition(ctx, fixture.actor, conditionRequest)
	if err != nil || createdCondition.Condition.Revision != 1 {
		t.Fatalf("create condition = %#v, err = %v", createdCondition, err)
	}

	viewer := seedTenantViewer(t, fixture.pool, fixture.actor.ScopeID, "l2-viewer")
	if configs, err := fixture.service.ListL2Configs(ctx, viewer); err != nil || len(configs) != 1 {
		t.Fatalf("viewer list configs = %#v, err = %v", configs, err)
	}
	denied := configRequest
	denied.IdempotencyKey = "l2-viewer-denied"
	denied.RequestID = "l2-viewer-denied-request"
	if _, err := fixture.service.PutL2Config(ctx, viewer, denied); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer write error = %v", err)
	}
	otherActor := seedTenantActor(t, fixture.pool, "l2-other")
	if configs, err := fixture.service.ListL2Configs(ctx, otherActor); err != nil || len(configs) != 0 {
		t.Fatalf("cross-tenant configs = %#v, err = %v", configs, err)
	}

	nodeID := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,display_id,name,ipv4,admin_state,created_by_user_id)
		VALUES($1,$2,1,'华东节点','192.0.2.21','active',$3)`, nodeID, fixture.actor.ScopeID, fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	available, err := fixture.service.ListAvailableL2Nodes(ctx, fixture.actor, createdConfig.Config.ID)
	if err != nil || len(available) != 1 || available[0].NodeID != nodeID {
		t.Fatalf("available nodes = %#v, err = %v", available, err)
	}
	added, err := fixture.service.AddL2Nodes(ctx, fixture.actor, L2NodeAddRequest{
		ConfigID: createdConfig.Config.ID, NodeIDs: []uuid.UUID{nodeID}, ConditionID: &createdCondition.Condition.ID,
		IdempotencyKey: "l2-node-add", RequestID: "l2-node-add-request",
	})
	if err != nil || len(added.Items) != 1 || added.Items[0].ConditionName == nil || *added.Items[0].ConditionName != "境外访问" {
		t.Fatalf("add nodes = %#v, err = %v", added, err)
	}
	if _, err := fixture.service.DeleteL2Config(ctx, fixture.actor, createdConfig.Config.ID, 1,
		"l2-config-referenced-delete", "l2-config-referenced-delete-request"); !errors.Is(err, ErrReferenceConflict) {
		t.Fatalf("referenced config delete = %v", err)
	}
	updatedNode, err := fixture.service.PutL2Node(ctx, fixture.actor, L2NodeWriteRequest{
		MembershipID: added.Items[0].ID, ConditionID: nil, ExpectedRevision: 1, Enabled: false, Weight: 25, Sort: 20,
		IdempotencyKey: "l2-node-update", RequestID: "l2-node-update-request",
	})
	if err != nil || updatedNode.Node.Revision != 2 || updatedNode.Node.Enabled || updatedNode.Node.Weight != 25 {
		t.Fatalf("update node = %#v, err = %v", updatedNode, err)
	}
	if _, err := fixture.service.PutL2Node(ctx, fixture.actor, L2NodeWriteRequest{
		MembershipID: added.Items[0].ID, ExpectedRevision: 1, Enabled: true, Weight: 50, Sort: 30,
		IdempotencyKey: "l2-node-stale", RequestID: "l2-node-stale-request",
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale node update = %v", err)
	}

	rollbackService := NewService(fixture.pool, fixture.clock.Now)
	rollbackService.auditor = failingL2Auditor{}
	rollbackRequest := configRequest
	rollbackRequest.Name = "审计回滚配置"
	rollbackRequest.IdempotencyKey = "l2-audit-rollback"
	rollbackRequest.RequestID = "l2-audit-rollback-request"
	if _, err := rollbackService.PutL2Config(ctx, fixture.actor, rollbackRequest); err == nil || !strings.Contains(err.Error(), "forced L2 audit failure") {
		t.Fatalf("forced audit error = %v", err)
	}
	var rollbackRows int
	if err := fixture.pool.QueryRow(ctx, `SELECT count(*) FROM l2_topology_configs
		WHERE tenant_scope_id=$1 AND name='审计回滚配置'`, fixture.actor.ScopeID).Scan(&rollbackRows); err != nil {
		t.Fatal(err)
	}
	if rollbackRows != 0 {
		t.Fatalf("audit failure left %d config rows", rollbackRows)
	}
}
