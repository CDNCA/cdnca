package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestBillingRechargeReconciliation133Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("133_billing_recharge_reconciliation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("133_billing_recharge_reconciliation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 133 requires the exact verified 132 release head",
		"3afde20714a6fab00099c7506173138767a303c2119c6eeeba3826c3f2087719",
		"f6a3dfaad783f62cbfd7c61f1b59f7705c6872aee78be1d37e7bec9897bbc279",
		"CREATE TABLE recharge_orders_v1",
		"CREATE TABLE recharge_order_events_v1",
		"CREATE TABLE recharge_provider_callbacks_v1",
		"CREATE TABLE recharge_settlements_v1",
		"CREATE TABLE recharge_statistics_facts_v1",
		"CREATE TABLE recharge_write_receipts_v1",
		"recharge_orders_user_created_v1_idx",
		"recharge_callbacks_order_identity_v1_idx",
		"recharge_statistics_user_time_v1_idx",
		"recharge_statistics_channel_time_v1_idx",
		"recharge_receipts_session_identity_v1_idx",
		"recharge_receipts_order_v1_idx",
		"recharge_order_id",
		"operation='recharge_payment'",
		"CONSTRAINT recharge_orders_callback_identity_133\n        UNIQUE(id,tenant_scope_id,amount_minor,currency)",
		"FOREIGN KEY(order_id,tenant_scope_id,amount_minor,currency)\n        REFERENCES recharge_orders_v1(id,tenant_scope_id,amount_minor,currency)",
		"FOREIGN KEY(order_id,tenant_scope_id,tenant_id,user_id,amount_minor,currency)",
		"FOREIGN KEY(callback_id,order_id,tenant_scope_id,amount_minor,currency)",
		"FOREIGN KEY(transaction_id,order_id,tenant_scope_id,amount_minor,currency)",
		"auth_sessions_recharge_receipt_identity_133 UNIQUE(id,scope_id,user_id)",
		"prevent_billing_recharge_fact_mutation_133",
		"validate_billing_recharge_reconciliation_133",
		"target_settlement_id := NEW.id",
		"target_settlement_id := NEW.settlement_id",
		"TG_OP='DELETE'",
		"billing.recharges.read",
		"billing.recharges.manage",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("133 up missing %q", required)
		}
	}
	for _, forbidden := range []string{"raw_payload", "raw_signature", "provider_secret", "password", "private_key"} {
		if strings.Contains(strings.ToLower(up), forbidden) {
			t.Errorf("133 up persists forbidden field %q", forbidden)
		}
	}
	if !strings.Contains(down, "rollback would discard billing recharge facts") ||
		!strings.Contains(down, "DROP TABLE recharge_statistics_facts_v1") ||
		!strings.Contains(down, "DROP CONSTRAINT auth_sessions_recharge_receipt_identity_133") ||
		!strings.Contains(down, "DROP COLUMN recharge_order_id") {
		t.Fatal("133 down must be loss guarded and restore the billing transaction shape")
	}
	refusal := strings.Index(down, "migration 133 rollback would discard billing recharge facts")
	dropCallbacks := strings.Index(down, "DROP TABLE recharge_provider_callbacks_v1")
	dropEvents := strings.Index(down, "DROP TABLE recharge_order_events_v1")
	dropOrders := strings.Index(down, "DROP TABLE recharge_orders_v1")
	if refusal < 0 || dropCallbacks < refusal || dropEvents < refusal || dropOrders < refusal ||
		dropCallbacks > dropOrders || dropEvents > dropOrders {
		t.Fatalf("133 down dependency order is unsafe: refusal=%d callbacks=%d events=%d orders=%d",
			refusal, dropCallbacks, dropEvents, dropOrders)
	}
}
