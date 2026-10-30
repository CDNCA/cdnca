package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 584 (fix-finrefund CFIN-D): refund/void intents are persisted
// before the provider is called (one per approval, at most one in flight per
// order) with append-only per-attempt evidence. The 583 predecessor is pinned
// by checksum.
const (
	migration584PreviousID      = "583_recharge_approval_decision_alias"
	migration584PreviousUpSHA   = "6fa605b83ad700bec6da7d1e9471103584f78b32dc39b47517374e3c2394311a"
	migration584PreviousDownSHA = "54c7bb05b58411f5b68e2f06875b1efe69b8dd33487df586ef10b8a222ac86ae"
	migration584ID              = "584_recharge_payment_compensations"
)

func TestRechargePaymentCompensations584Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration584ID + ".up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 583",
			"(SELECT max(version) FROM schema_migrations) <> 583",
			"WHERE version=583 AND",
			"migration_id='" + migration584PreviousID + "'",
			"checksum_sha256='" + migration584PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration584PreviousDownSHA + "'",
			"ERRCODE='P5840'", "ERRCODE='P5841'", "ERRCODE='P5842'",
			"CREATE TABLE recharge_payment_compensations_v1",
			"approval_request_id uuid NOT NULL UNIQUE",
			"REFERENCES recharge_payment_approval_executions_v1(approval_request_id)",
			"UNIQUE(provider,provider_account_id,provider_request_id)",
			"ON recharge_payment_compensations_v1(order_id) WHERE status IN ('pending','unknown')",
			"CREATE TABLE recharge_payment_compensation_attempts_v1",
			"(OLD.status='unknown' AND NEW.status IN ('pending','succeeded','failed'))",
			"REVOKE ALL ON recharge_payment_compensations_v1,recharge_payment_compensation_attempts_v1 FROM PUBLIC",
			"ALTER TABLE recharge_orders_v1 DROP CONSTRAINT recharge_orders_v1_check2",
			"OR (operation='package_addon_purchase' AND addon_order_id IS NOT NULL",
		}},
		{migration584ID + ".down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 584",
			"migration_id='" + migration584ID + "'",
			"ERRCODE='P5843'", "ERRCODE='P5844'",
			"DROP TABLE recharge_payment_compensation_attempts_v1",
			"DROP TABLE recharge_payment_compensations_v1",
			"ADD CONSTRAINT recharge_orders_v1_check2",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration584PreviousUpSHA, ".down.sql": migration584PreviousDownSHA} {
		raw, err := FS.ReadFile(migration584PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration584PreviousID, suffix, got, want)
		}
	}
}
