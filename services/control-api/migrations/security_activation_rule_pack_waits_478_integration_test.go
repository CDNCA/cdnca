//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestSecurityActivationRulePackWaits478: after 478
// a wait row is a capability wait (capability + version, no packs) or a rule
// pack wait (packs, no capability), nothing in between; a row written as 477
// wrote it is a capability wait; down refuses while a rule pack wait is
// recorded and succeeds once it is gone.
func TestSecurityActivationRulePackWaits478(t *testing.T) {
	const version = 478
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	scopeID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	pack := strings.Repeat("a", 64)
	insert := func(kind any, capability, required any, packs any) (uuid.UUID, error) {
		id := uuid.New()
		_, err := pool.Exec(ctx, `INSERT INTO security_activation_capability_waits(id,tenant_scope_id,site_id,policy_id,
			policy_kind,policy_version,expected_binding_revision,expected_active_policy_version,target_node_ids,canary_size,
			actor_user_id,actor_scope_id,actor_scope_kind,capability,required_api_version,blocking_node_ids,
			status,created_at,updated_at,wait_kind,rule_pack_sha256)
			VALUES($1,$2,$3,$4,'waf',1,0,0,ARRAY[$5::uuid],1,$6,$2,'platform',$7,$8,ARRAY[$5::uuid],'superseded',now(),now(),
			COALESCE($9::text,'capability'),$10)`,
			id, scopeID, uuid.New(), uuid.New(), uuid.New(), uuid.New(), capability, required, kind, packs)
		return id, err
	}
	if _, err := insert(nil, 1, 4, nil); err != nil {
		t.Fatalf("477-shaped capability wait: %v", err)
	}
	ruleWait, err := insert("rule_pack", nil, nil, []string{pack})
	if err != nil {
		t.Fatalf("rule pack wait: %v", err)
	}
	for name, row := range map[string][]any{
		"capability with packs":       {"capability", 1, 4, []string{pack}},
		"capability without version":  {"capability", 1, nil, nil},
		"rule pack with capability":   {"rule_pack", 1, 4, []string{pack}},
		"rule pack without packs":     {"rule_pack", nil, nil, []string{}},
		"rule pack with a bad digest": {"rule_pack", nil, nil, []string{"nothex"}},
		"unknown kind":                {"other", nil, nil, []string{pack}},
	} {
		if _, err := insert(row[0], row[1], row[2], row[3]); sqlState(err) != "23514" {
			t.Errorf("%s: %v, want 23514", name, err)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4782" {
		t.Fatalf("down with a rule pack wait: %v, want P4782", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM security_activation_capability_waits WHERE id=$1`, ruleWait); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down without rule pack waits: %v", err)
	}
}
