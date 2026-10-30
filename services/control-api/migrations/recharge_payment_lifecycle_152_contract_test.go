package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	rechargePayment151UpSHA   = "81a2cdcf12d5ddeb456b219c402043fe0b17b79f379da8436b79e3a7a3627668"
	rechargePayment151DownSHA = "2bad7d25e8c2bbec6a80385a65868efa82e7af2b826c21eead23e6e4ef92b71f"
)

func TestBILL1112RechargePaymentLifecycle152Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("152_recharge_payment_lifecycle.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("152_recharge_payment_lifecycle.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 152 requires the exact verified 151 release head", rechargePayment151UpSHA, rechargePayment151DownSHA,
		"captured_minor", "refunded_minor", "partially_refunded", "reconcile_required",
		"recharge_order_events_revision_152", "recharge_order_events_state_152",
		"CREATE TABLE recharge_payment_checkouts_v1", "CREATE TABLE recharge_payment_commands_v1",
		"CREATE TABLE recharge_payment_provider_events_v1", "event_digest_sha256",
		"UNIQUE(provider,provider_account_id,external_event_id)", "UNIQUE(id,order_id)",
		"CREATE TABLE recharge_payment_reconcile_jobs_v1",
		"CREATE TABLE recharge_payment_reconcile_receipts_v1", "recharge_refund", "recharge_void",
		"billing_transactions_recharge_event_fk_152", "prevent_recharge_payment_fact_mutation_152",
		"billing_transactions_recharge_payment_order_152_idx",
		"FOREIGN KEY(job_id,order_id)", "FOREIGN KEY(provider_event_id,order_id)",
		"guard_recharge_payment_order_head_152", "REVOKE ALL ON recharge_payment_checkouts_v1",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("152 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 152 requires the exact verified 151 release head"), strings.Index(up, "INSERT INTO permissions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("152 predecessor guard must run before the first mutation")
	}
	if addColumns, backfill, addConstraints := strings.Index(up, "ADD COLUMN captured_minor"), strings.Index(up, "UPDATE recharge_orders_v1 SET captured_minor=amount_minor"), strings.Index(up, "ADD CONSTRAINT recharge_orders_state_152"); addColumns < 0 || backfill < addColumns || addConstraints < backfill {
		t.Fatal("152 must add amount columns and backfill legacy paid orders before adding state/amount constraints")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 152 rollback requires the exact verified 152 head", upSHA,
		"migration 152 rollback would discard recharge payment lifecycle facts",
		"source_callback_id IS NULL", "operation IN ('recharge_refund','recharge_void')",
		"DROP TABLE recharge_payment_provider_events_v1", "DROP COLUMN recharge_provider_event_id",
		"CREATE UNIQUE INDEX billing_transactions_recharge_order_v1_idx",
		"version=151 AND migration_id='151_l4_domain_geo_runtime'", rechargePayment151UpSHA, rechargePayment151DownSHA,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("152 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 152 rollback requires the exact verified 152 head"), strings.Index(down, "DROP INDEX"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("152 rollback guard must run before the first mutation")
	}
	for _, forbidden := range []string{"CASCADE", "TRUNCATE", "DROP SCHEMA", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("152 migration contains forbidden marker %q", forbidden)
		}
	}
}
