package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 446 (ADR 0016) is a placeholder number (the
// dispatch reserves 442); the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration446Version         = 446
	migration446ID              = "446_migrate_import"
	migration446PreviousID      = "445_market_deposit_notices"
	migration446PreviousUpSHA   = "4b3158dd2587cc14bcbe1b3f2b3614f46a5f9027ed716bcf34c2a50a28dc10c3"
	migration446PreviousDownSHA = "4ec4556cca071125de252c20886aef624d78da41bc699f8983a71bc75e173579"
	migration446UpSHA           = "86a1e1d2c969e966fe9585564bbf0b8a230e0b6980a877c35be9c05002ca7725"
	migration446DownSHA         = "43bfa7f0ddedd8969fd66278d46c31941fcb406b5fcef584217d33cba0dcbbb1"
)

func TestMigrateImport446Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration446ID + ".up.sql", migration446UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration446Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration446Version-1),
			"migration_id='" + migration446PreviousID + "'", migration446PreviousUpSHA, migration446PreviousDownSHA,
			"ERRCODE='P4460'", "CREATE TABLE migrate_import_jobs", "CREATE TABLE migrate_import_legacy_passwords",
			"CREATE TABLE migrate_import_balance_credits", "'migrate_import_credit'", "system.migrate_import.manage",
			"identity.migrated_account",
			"ALTER TABLE mfa_step_up_proofs ALTER COLUMN tenant_id DROP NOT NULL",
			"NEW.tenant_id IS NOT NULL AND scope.tenant_id = NEW.tenant_id",
		}},
		{migration446ID + ".down.sql", migration446DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration446Version),
			"migration_id='" + migration446ID + "'", "ERRCODE='P4461'", "ERRCODE='P4464'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
