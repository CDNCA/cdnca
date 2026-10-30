package migrations

import (
	"bytes"
	"testing"
)

func TestRechargePaymentApprovalMigrationContract(t *testing.T) {
	up, err := FS.ReadFile("171_recharge_payment_approval.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("171_recharge_payment_approval.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("migration 171 requires the exact verified 170 release head"),
		[]byte("140d1689a8d3ce17e34cc8bc46598711364d9fe129ec36bb3e5f591c71f8f089"),
		[]byte("02db4682dcbcabdf057a714cfd10cd32332e5b8540872d41697cb78483fa2609"),
		[]byte("billing.recharges.approve"),
		[]byte("recharge_payment_approval_requests_v1"),
		[]byte("recharge_payment_approval_decisions_v1"),
		[]byte("recharge_payment_approval_executions_v1"),
		[]byte("recharge_payment_approval_receipts_v1"),
		[]byte("NEW.decided_by_user_id=request.proposed_by_user_id"),
		[]byte("NEW.authorized_at>=request.expires_at"),
		[]byte("approval facts are append-only"),
	} {
		if !bytes.Contains(up, required) {
			t.Fatalf("up migration missing %q", required)
		}
	}
	for _, required := range [][]byte{
		[]byte("migration 171 rollback requires the exact verified 171 head"),
		[]byte("0acba33bda1accbd9a4ae03eaebcb6fbd495be78c8e5fcb84a7fa57abf561ab9"),
		[]byte("migration 171 rollback would discard recharge payment approval facts"),
		[]byte("non-system approval grants to be removed"),
	} {
		if !bytes.Contains(down, required) {
			t.Fatalf("down migration missing %q", required)
		}
	}
}
