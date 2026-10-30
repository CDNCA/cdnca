package main

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSystemConfigurationBuiltInMonitoringEntitlement(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	actor := seedMonitoringConfigurationActor(t, pool)
	now := time.Now().UTC().Truncate(time.Second)
	fixture := installEdgePublishProductionEntitlement(t, pool, now) // sites.manage only; no node feature or quota.
	service, err := systemconfig.NewService(pool)
	if err != nil {
		t.Fatal(err)
	}
	authorizer := denySystemConfigurationExpansion{
		Entitlement: entitlementguard.NewGuard(pool, func() time.Time { return now }, fixture.trust),
	}
	manager, err := systemconfig.NewCategoryManager(service, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	monitoring := systemconfig.EffectiveNodeMonitoring(nil)
	monitoring.ProbeIntervalMS--
	request := systemconfig.SaveCategoryRequest{
		Category: systemconfig.CategoryNodeMonitoring, ExpectedHeadRevision: 0,
		Change:         systemconfig.CategoryChange{NodeMonitoring: &monitoring},
		IdempotencyKey: "builtin-monitoring-save", RequestID: "builtin-monitoring-save",
	}
	result, err := manager.SaveCategory(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("valid controller license must allow built-in monitoring expansion: %v", err)
	}
	if result.HeadRevision != 1 || result.Revision != 1 || result.Status != systemconfig.StatusDraft {
		t.Fatalf("monitoring save = %#v", result)
	}
	reloaded, err := manager.GetActiveCategory(t.Context(), actor, systemconfig.CategoryNodeMonitoring)
	if err != nil || reloaded.HeadRevision != 1 || !reflect.DeepEqual(reloaded.Value, monitoring) {
		t.Fatalf("reload monitoring = %#v, %v", reloaded, err)
	}
	replayed, err := manager.SaveCategory(t.Context(), actor, request)
	if err != nil || !replayed.Replayed || replayed.Revision != 1 {
		t.Fatalf("replay monitoring = %#v, %v", replayed, err)
	}
	tenant := actor
	tenant.ScopeKind = "tenant"
	if err := authorizer.AuthorizeSystemConfigurationExpansion(t.Context(), &systemConfigurationExpansionTestTx{}, systemconfig.ExpansionCheck{
		Actor: tenant, Category: systemconfig.CategoryNodeMonitoring, RequestID: "tenant-monitoring",
	}); !errors.Is(err, systemconfig.ErrEntitlementDenied) {
		t.Fatalf("tenant monitor expansion = %v", err)
	}
	now = now.Add(6 * time.Minute) // Lease and grace expired; signed revocation LKG is still current.
	monitoring.ProbeIntervalMS--
	request.ExpectedHeadRevision, request.IdempotencyKey, request.RequestID = 1, "expired-monitoring-save", "expired-monitoring-save"
	if _, err := manager.SaveCategory(t.Context(), actor, request); !errors.Is(err, systemconfig.ErrEntitlementDenied) {
		t.Fatalf("expired license allowed expansion: %v", err)
	}
	var revisions, writes, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM system_configuration_revisions),
		(SELECT count(*) FROM system_configuration_write_requests WHERE idempotency_key=$1),
		(SELECT count(*) FROM audit_events WHERE request_id=$1)`, request.RequestID).Scan(&revisions, &writes, &audits); err != nil {
		t.Fatal(err)
	}
	if revisions != 1 || writes != 0 || audits != 1 {
		t.Fatalf("denied write left revisions=%d writes=%d audits=%d", revisions, writes, audits)
	}
	var action, outcome, category, reason string
	if err := pool.QueryRow(t.Context(), `SELECT action,result,payload->>'category',payload->>'reason'
		FROM audit_events WHERE request_id=$1`, request.RequestID).Scan(&action, &outcome, &category, &reason); err != nil {
		t.Fatal(err)
	}
	if action != "system_configuration.create_draft" || outcome != "denied" || category != systemconfig.CategoryNodeMonitoring || reason != "entitlement_denied" {
		t.Fatalf("denial audit = %s %s %s %s", action, outcome, category, reason)
	}
	reloaded, err = manager.GetActiveCategory(t.Context(), actor, systemconfig.CategoryNodeMonitoring)
	if err != nil || reloaded.HeadRevision != 1 || reloaded.Value.(systemconfig.NodeMonitoringConfiguration).ProbeIntervalMS != monitoring.ProbeIntervalMS+1 {
		t.Fatalf("denial changed saved configuration: %#v, %v", reloaded, err)
	}
	// Existing monitoring may be reduced or disabled after license expiry.
	monitoring.ProbeIntervalMS = systemconfig.EffectiveNodeMonitoring(nil).ProbeIntervalMS
	disabled := false
	monitoring.MonitorEnabled, monitoring.RecoveryNotificationEnabled = &disabled, false
	request.IdempotencyKey, request.RequestID = "expired-monitoring-contract", "expired-monitoring-contract"
	result, err = manager.SaveCategory(t.Context(), actor, request)
	if err != nil || result.HeadRevision != 2 {
		t.Fatalf("expired license blocked contraction: %#v, %v", result, err)
	}
}

func TestSystemConfigurationMonitoringContractionWithoutLicense(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	actor := seedMonitoringConfigurationActor(t, pool)
	service, err := systemconfig.NewService(pool)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := systemconfig.NewCategoryManager(service, denySystemConfigurationExpansion{})
	if err != nil {
		t.Fatal(err)
	}
	monitoring := systemconfig.EffectiveNodeMonitoring(nil)
	monitoring.ProbeIntervalMS++
	disabled := false
	monitoring.MonitorEnabled, monitoring.RecoveryNotificationEnabled = &disabled, false
	request := systemconfig.SaveCategoryRequest{
		Category: systemconfig.CategoryNodeMonitoring, Change: systemconfig.CategoryChange{NodeMonitoring: &monitoring},
		IdempotencyKey: "unlicensed-monitoring-contract", RequestID: "unlicensed-monitoring-contract",
	}
	if result, err := manager.SaveCategory(t.Context(), actor, request); err != nil || result.HeadRevision != 1 {
		t.Fatalf("nil guard blocked contraction: %#v, %v", result, err)
	}
	monitoring.ProbeIntervalMS--
	request.ExpectedHeadRevision, request.IdempotencyKey, request.RequestID = 1, "unlicensed-monitoring-expand", "unlicensed-monitoring-expand"
	if _, err := manager.SaveCategory(t.Context(), actor, request); !errors.Is(err, systemconfig.ErrEntitlementDenied) {
		t.Fatalf("nil guard allowed expansion: %v", err)
	}
}

func seedMonitoringConfigurationActor(t *testing.T, pool *pgxpool.Pool) systemconfig.Actor {
	t.Helper()
	actor := systemconfig.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	roleID := uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{actor.ScopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'builtin-monitoring-admin','Monitoring admin','unused')`, []any{actor.UserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{actor.ScopeID, actor.UserID}},
		{`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, []any{roleID, actor.ScopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'system_configuration.read'),($1,'system_configuration.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{actor.ScopeID, actor.UserID, roleID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return actor
}
