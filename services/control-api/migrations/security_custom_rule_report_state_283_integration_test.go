//go:build integration

package migrations_test

import (
	"testing"
)

func TestSecurityCustomRuleReportStateMigration283(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 282)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, 283); err != nil {
			t.Fatalf("%s 283: %v", step, err)
		}
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_runtime','security_custom_rule_report_state','INSERT')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("runtime grant = %v, %v", granted, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO security_custom_rule_report_state(installation_id,sequence,request_id,observed_at,report,report_digest,updated_at)
		VALUES(gen_random_uuid(),1,'r',now(),'[]',decode(repeat('00',32),'hex'),now())`); err == nil {
		t.Fatal("non-object report accepted")
	}
}
