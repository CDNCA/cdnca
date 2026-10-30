package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestIAM11RechargeIdentityEligibility161Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("160_site_tls_protocols.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("160_site_tls_protocols.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("161_recharge_identity_eligibility.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("161_recharge_identity_eligibility.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	predecessorUpSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorUp))
	predecessorDownSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorDown))
	for _, required := range []string{
		"migration 161 requires a contiguous verified 160 release head",
		"version=160 AND migration_id='160_site_tls_protocols'", predecessorUpSHA, predecessorDownSHA,
		"CREATE TABLE recharge_identity_policy_revisions_v1",
		"CREATE TABLE recharge_identity_policy_heads_v1",
		"require_real_name boolean NOT NULL",
		"billing-recharge-policy:v1:", "billing-recharge-identity:v1:",
		"identity_verification_cases_recharge_lock_161",
		"REVOKE ALL ON recharge_identity_policy_revisions_v1 FROM PUBLIC",
		"REVOKE ALL ON recharge_identity_policy_heads_v1 FROM PUBLIC",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("161 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 161 requires a contiguous verified 160 release head"),
		strings.Index(up, "CREATE TABLE recharge_identity_policy_revisions_v1"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("161 predecessor guard must precede the first schema mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 161 rollback requires the exact verified 161 head",
		"version=161 AND migration_id='161_recharge_identity_eligibility'", upSHA,
		"version=160 AND migration_id='160_site_tls_protocols'", predecessorUpSHA, predecessorDownSHA,
		"migration 161 rollback would discard recharge identity policy facts",
		"DROP TABLE recharge_identity_policy_heads_v1",
		"DROP TABLE recharge_identity_policy_revisions_v1",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("161 down missing %q", required)
		}
	}
	if refusal, drop := strings.Index(down, "migration 161 rollback would discard recharge identity policy facts"),
		strings.Index(down, "DROP TABLE recharge_identity_policy_heads_v1"); refusal < 0 || drop < 0 || refusal > drop {
		t.Fatal("161 fact refusal must precede destructive rollback")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("161 migration contains forbidden marker %q", forbidden)
		}
	}
}
