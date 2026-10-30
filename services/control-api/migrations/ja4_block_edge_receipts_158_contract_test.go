package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestSEC10JA4BlockEdgeReceipts158Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("158_ja4_block_edge_receipts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("158_ja4_block_edge_receipts.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 158 requires a contiguous verified 157 release head",
		"d6f9a03fcdc4cd47fe62fe861c8f57e3f25f11fe9bfa9abbb1db2732f411e104",
		"0f31778af185f8505b528ba938fadb7655bbad43690c3a9790632b531ec6720c",
		"CREATE TABLE ja4_block_edge_receipt_queue_158",
		"workflow_id", "publication_id", "rollout_id", "node_id", "config_sha256", "receipt_sha256",
		"claim_token", "claim_expires_at", "recorded_at", "completed_at", "rejected_at",
		"CREATE FUNCTION enqueue_ja4_block_edge_receipt_158", "AFTER UPDATE OF state ON firewall_command_outbox",
		"policy_kind='waf'", "terminal_state", "active_policy_version", "ack-sha256:",
		"CREATE FUNCTION guard_ja4_block_edge_receipt_158", "BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE",
		"REVOKE ALL ON ja4_block_edge_receipt_queue_158 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("158 up missing %q", required)
		}
	}
	upDigest := sha256.Sum256(upBytes)
	for _, required := range []string{
		"migration 158 rollback requires the exact verified 158 head",
		"version=158 AND migration_id='158_ja4_block_edge_receipts'",
		hex.EncodeToString(upDigest[:]),
		"migration 158 rollback would discard JA4 edge receipt facts",
		"DROP TRIGGER ja4_block_edge_receipt_enqueue_158 ON firewall_command_outbox",
		"DROP TABLE ja4_block_edge_receipt_queue_158",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("158 down missing %q", required)
		}
	}
	for _, forbidden := range []string{"CASCADE", "DROP TABLE IF EXISTS", "DROP FUNCTION IF EXISTS"} {
		if strings.Contains(up, forbidden) || strings.Contains(down, forbidden) {
			t.Errorf("158 migration contains forbidden marker %q", forbidden)
		}
	}
}
