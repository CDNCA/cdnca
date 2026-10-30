//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestBillingAdjustmentApproval100StaticContract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("100_billing_adjustment_approval_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("100_billing_adjustment_approval_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"migration 100 requires the exact verified 099 release head",
		"ec616f2b6851956945ef67a4940e09051470b8e30431efee188034592692dc1a",
		"0afc07827ca395c1b9393fc6cf606377f6979140177084be18621e2eb062d1b3",
		"CREATE TABLE billing_adjustment_legacy_authority",
		"CREATE TABLE billing_adjustment_requests",
		"CREATE TABLE billing_adjustment_decisions",
		"ADD COLUMN adjustment_request_id uuid",
		"billing.adjustments.propose",
		"billing.adjustments.approve",
		"mfa_step_up_uses",
		"max_uses=1",
		"approved_by_user_id <> proposed_by_user_id",
		"DEFERRABLE INITIALLY DEFERRED",
		"billing adjustment authority fact lacks exact receipt",
		"approved billing adjustment lacks exact double-entry postings",
		"SECURITY DEFINER",
		"SET search_path = %I, pg_catalog, pg_temp",
		"receipt.response_body=expected_response_body",
		"billing_adjustment_receipts_audit_100",
		"AFTER INSERT ON billing_adjustment_write_receipts",
		"BEFORE TRUNCATE",
		"cdnca_control_app",
		"ERRCODE='P1002'",
	} {
		if !strings.Contains(string(up), fragment) {
			t.Errorf("100 up missing %q", fragment)
		}
	}
	if strings.Contains(string(up), "SET search_path FROM CURRENT") {
		t.Fatal("100 up must not capture an implicit temporary-schema-first search path")
	}
	upDigest := sha256.Sum256(up)
	for _, fragment := range []string{
		"migration 100 rollback requires the exact verified 100 head",
		hex.EncodeToString(upDigest[:]),
		"migration 100 rollback would discard billing approval authority facts",
		"migration 100 rollback would discard custom billing approval grants",
		"billing.adjustments.propose",
		"billing.adjustments.approve",
		"billing_adjustment_transaction_digest_100",
		"ERRCODE='P1001'",
		"DROP COLUMN adjustment_request_id",
	} {
		if !strings.Contains(string(down), fragment) {
			t.Errorf("100 down missing %q", fragment)
		}
	}
	if strings.Contains(string(down), "DELETE FROM schema_migrations") {
		t.Fatal("100 down must not delete its own migration ledger row")
	}
}
