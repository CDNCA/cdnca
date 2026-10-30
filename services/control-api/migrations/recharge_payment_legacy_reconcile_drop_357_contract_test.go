package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 357 (recharge collection only over payment
// channels; the 152 reconcile job queue is dropped) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is here.
const (
	migration357Version         = 357
	migration357ID              = "357_recharge_payment_legacy_reconcile_drop"
	migration357PreviousID      = "356_site_cache_shared_across_domains"
	migration357PreviousUpSHA   = "dd69f72578e5a6d56f3e3cf5eced55a2ceb8e99700426077439240db0bf0accc"
	migration357PreviousDownSHA = "4eff66a3efa731a8504eb4781175c71c4b18229eccffd9b4e75fefcf2c991301"
	migration357UpSHA           = "5e8101deee14f96bb09769b33831facd4215a539df5ec169040f761ca2d97cb7"
	migration357DownSHA         = "8dbecc582284d023d24e3aee071497db192c4bfcc8c6ae6f612af9d94b5131c1"
)

func TestRechargePaymentLegacyReconcileDrop357Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration357ID + ".up.sql", migration357UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration357Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration357Version-1),
			"migration_id='" + migration357PreviousID + "'", migration357PreviousUpSHA, migration357PreviousDownSHA,
			"ERRCODE='P3570'", "DROP TABLE recharge_payment_reconcile_receipts_v1;",
			"DROP TABLE recharge_payment_reconcile_jobs_v1;", "DROP FUNCTION guard_recharge_payment_reconcile_job_152();",
		}},
		{migration357ID + ".down.sql", migration357DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration357Version),
			"migration_id='" + migration357ID + "'", "ERRCODE='P3579'",
			"CREATE TABLE recharge_payment_reconcile_jobs_v1", "CREATE TABLE recharge_payment_reconcile_receipts_v1",
			"EXECUTE FUNCTION prevent_recharge_payment_fact_mutation_152()",
			"EXECUTE FUNCTION guard_recharge_payment_reconcile_job_152()", "recharge_payment_reconcile_ready_v1_idx",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		if strings.Contains(string(raw), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
	// The shared append-only trigger function stays: 152's checkouts, events
	// and commands tables still use it.
	up, _ := FS.ReadFile(migration357ID + ".up.sql")
	if strings.Contains(string(up), "DROP FUNCTION prevent_recharge_payment_fact_mutation_152") {
		t.Error("357 must keep prevent_recharge_payment_fact_mutation_152")
	}
}
