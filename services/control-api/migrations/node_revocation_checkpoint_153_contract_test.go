package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	nodeRevocation152UpSHA256   = "5aa5c735685cb02cce34fca432592f280c8f53a4f8c8c006067e43e997d279e0"
	nodeRevocation152DownSHA256 = "1bf753f13c76111d465396b6ac2b446892325b18ff3b8929ead84985963decce"
)

func TestNODE10RevocationCheckpoint153Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("153_node_revocation_checkpoint.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("153_node_revocation_checkpoint.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"migration 153 requires the exact verified 152 release head",
		"version=152 AND migration_id='152_recharge_payment_lifecycle'",
		nodeRevocation152UpSHA256, nodeRevocation152DownSHA256,
		"CREATE TABLE node_revocation_checkpoint_history",
		"PRIMARY KEY(installation_id,revision)",
		"CHECK(artifact_sha256=sha256(wire_bytes))",
		"CREATE TABLE node_revocation_checkpoint_lkg",
		"REFERENCES node_revocation_checkpoint_history(installation_id,revision,artifact_sha256)",
		"guard_node_revocation_checkpoint_history_insert_153",
		"node revocation checkpoint revision must increase strictly",
		"node revocation checkpoint history is append-only",
		"guard_node_revocation_checkpoint_lkg_153",
		"NEW.revision<=OLD.revision", "NEW.issued_at<OLD.issued_at",
		"BEFORE UPDATE OR DELETE OR TRUNCATE ON node_revocation_checkpoint_history",
		"BEFORE TRUNCATE ON node_revocation_checkpoint_lkg",
		"REVOKE ALL ON node_revocation_checkpoint_history,node_revocation_checkpoint_lkg FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("153 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 153 requires the exact verified 152 release head"), strings.Index(up, "CREATE TABLE node_revocation_checkpoint_history"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("153 predecessor guard must run before the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 153 rollback requires the exact verified 153 head",
		"version=153 AND migration_id='153_node_revocation_checkpoint'", upSHA,
		"migration 153 rollback would discard durable node revocation checkpoints",
		"EXISTS(SELECT 1 FROM node_revocation_checkpoint_history)",
		"EXISTS(SELECT 1 FROM node_revocation_checkpoint_lkg)",
		"DROP TABLE node_revocation_checkpoint_lkg",
		"DROP TABLE node_revocation_checkpoint_history",
		"version=152 AND migration_id='152_recharge_payment_lifecycle'",
		nodeRevocation152UpSHA256, nodeRevocation152DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("153 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 153 rollback requires the exact verified 153 head"), strings.Index(down, "DROP TRIGGER"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("153 rollback guard must run before the first mutation")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("153 migration contains forbidden marker %q", forbidden)
		}
	}
}
