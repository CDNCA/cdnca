package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestSITE15TLSProtocols160Contract(t *testing.T) {
	predecessorUp, err := controlmigrations.FS.ReadFile("159_account_registration.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := controlmigrations.FS.ReadFile("159_account_registration.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upBytes, err := controlmigrations.FS.ReadFile("160_site_tls_protocols.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("160_site_tls_protocols.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	predecessorUpSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorUp))
	predecessorDownSHA := fmt.Sprintf("%x", sha256.Sum256(predecessorDown))
	for _, required := range []string{
		"migration 160 requires a contiguous verified 159 release head",
		"version=159 AND migration_id='159_account_registration'", predecessorUpSHA, predecessorDownSHA,
		"ADD COLUMN tls_protocols text[]", "DEFAULT ARRAY['TLSv1.2','TLSv1.3']::text[]", "NOT NULL",
		"SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("160 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 160 requires a contiguous verified 159 release head"),
		strings.Index(up, "ADD COLUMN tls_protocols text[]"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("160 predecessor guard must precede the first mutation")
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 160 rollback requires the exact verified 160 head",
		"version=160 AND migration_id='160_site_tls_protocols'", upSHA,
		"version=159 AND migration_id='159_account_registration'", predecessorUpSHA, predecessorDownSHA,
		"migration 160 rollback would discard non-canonical TLS remediation facts",
		"DROP COLUMN tls_protocols",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("160 down missing %q", required)
		}
	}
	if refusal, drop := strings.Index(down, "migration 160 rollback would discard non-canonical TLS remediation facts"),
		strings.Index(down, "DROP COLUMN tls_protocols"); refusal < 0 || drop < 0 || refusal > drop {
		t.Fatal("160 remediation-fact refusal must precede destructive rollback")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "DROP SCHEMA", "__UP_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("160 migration contains forbidden marker %q", forbidden)
		}
	}
}
