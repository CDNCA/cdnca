//go:build integration

package systemothersettings

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ui-leftover3 #1：GET 必须返回 rule_intel_contribution（前端按完整键集合校验），
// 不带该字段的保存（旧客户端）要保留已存值，而不是把已关的开关静默改回默认开。
func TestPostgresOtherSettingsRuleIntelContributionRoundTripAndOmittedSaveKeepsStored(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		pool = databasetest.MigratedPool(t, nil)
	}
	actor := seedOtherSettingsActor(t, pool)
	now := time.Date(2026, 10, 23, 1, 2, 3, 0, time.UTC)
	service, err := NewService(pool, audit.NewWithClock(pool, func() time.Time { return now }), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	initial, err := service.Get(t.Context(), actor)
	if err != nil || initial.Value.RuleIntelContribution == nil || !*initial.Value.RuleIntelContribution {
		t.Fatalf("initial document=(%#v,%v), want rule_intel_contribution=true", initial, err)
	}
	off := initial.Value
	off.RuleIntelContribution = boolPointer(false)
	saved, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: 0, Value: off, IdempotencyKey: "other-rule-intel-off", RequestID: "other-rule-intel-off"})
	if err != nil || saved.Revision != 1 {
		t.Fatalf("save off=(%#v,%v)", saved, err)
	}
	legacy := saved.Value
	legacy.RuleIntelContribution = nil
	legacy.SyncBatch = 500
	resaved, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: 1, Value: legacy, IdempotencyKey: "other-rule-intel-legacy", RequestID: "other-rule-intel-legacy"})
	if err != nil || resaved.Value.RuleIntelContribution == nil || *resaved.Value.RuleIntelContribution {
		t.Fatalf("legacy save=(%#v,%v), want stored rule_intel_contribution=false kept", resaved, err)
	}
	enabled, err := RuleIntelContribution(t.Context(), pool)
	if err != nil || enabled {
		t.Fatalf("RuleIntelContribution=(%v,%v), want false", enabled, err)
	}
	loaded, err := service.Get(t.Context(), actor)
	if err != nil || loaded.Value.SyncBatch != 500 || loaded.Value.RuleIntelContribution == nil || *loaded.Value.RuleIntelContribution {
		t.Fatalf("loaded=(%#v,%v)", loaded, err)
	}
}

func seedOtherSettingsActor(t *testing.T, pool *pgxpool.Pool) Actor {
	t.Helper()
	userID, roleID := uuid.New(), uuid.New()
	var scopeID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&scopeID); err == pgx.ErrNoRows {
		scopeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(t.Context(), `
		INSERT INTO users(id,username,display_name,password_hash,status) VALUES($2,'other-settings-owner','Other settings owner','not-used','active');
		INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active');
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($3,$1,'other_settings_owner','Integration role',true);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($3,'system_configuration.read'),($3,'system_configuration.manage');
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		pgx.QueryExecModeSimpleProtocol, scopeID, userID, roleID)
	if err != nil {
		t.Fatal(err)
	}
	return Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
}
