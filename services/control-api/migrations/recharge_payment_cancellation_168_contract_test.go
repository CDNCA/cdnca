package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	rechargeCancellation167UpSHA   = "a4409fe5ab7ced09a42212526a956979a1dabe2d6a036fbb59a8169f0fdaf1e3"
	rechargeCancellation167DownSHA = "23784306af9c4f4dc12439b019961e650891b3db9ac01f2ebb2853e08ed73da4"
)

func TestIAM06RechargePaymentCancellation168Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("168_recharge_payment_cancellation.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("168_recharge_payment_cancellation.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 168 requires the exact verified 167 release head", rechargeCancellation167UpSHA, rechargeCancellation167DownSHA,
		"billing.recharges.cancel", "CREATE TABLE recharge_payment_cancellations_v1", "CREATE TABLE recharge_payment_cancellation_attempts_v1",
		"actor_session_id", "expected_revision", "idempotency_key", "request_id", "request_digest_sha256",
		"provider_request_id", "status IN ('pending','succeeded','failed','unknown')", "attempt_count", "revision",
		"UNIQUE(actor_session_id,idempotency_key)", "UNIQUE(actor_session_id,request_id)",
		"guard_recharge_payment_cancellation_head_168", "prevent_recharge_payment_cancellation_attempt_mutation_168",
		"validate_recharge_payment_cancellation_attempt_168", "provider_request_id)", "NEW.attempt_number<=cancellation.attempt_count",
		"prevent_recharge_payment_cancellation_truncate_168", "pg_advisory_xact_lock", "recharge_payment_cancellations_order_active_168_idx",
		"REVOKE ALL ON recharge_payment_cancellations_v1,recharge_payment_cancellation_attempts_v1 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("168 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 168 requires the exact verified 167 release head"), strings.Index(up, "INSERT INTO permissions"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("168 predecessor guard must run before the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 168 rollback requires the exact verified 168 head", upSHA,
		"migration 168 rollback would discard recharge payment cancellation facts",
		"DROP TABLE recharge_payment_cancellation_attempts_v1", "DROP TABLE recharge_payment_cancellations_v1",
		"version=167 AND migration_id='167_http_policy_edge_source_revision'", rechargeCancellation167UpSHA, rechargeCancellation167DownSHA,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("168 down missing %q", required)
		}
	}
	for _, forbidden := range []string{"CASCADE", "TRUNCATE recharge_payment", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("168 migration contains forbidden marker %q", forbidden)
		}
	}
}
