package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (TENANT-PWRESET-UNKNOWN): 487 follows 484_escalate_reseller_policies
// (pinned by checksum); local placeholder, renumbered to 493 on merge with the P487x codes.
const (
	pwresetResultsVersion  = 487
	pwresetResultsID       = "487_tenant_member_password_reset_results"
	pwresetResultsPinned   = "486_shared_node_host_firewall"
	pwresetResultsPinUpSHA = "88269053938a4cc883c4b713bdf93f412e9f8d9eecb60c876f8790c5d32110e7"
	pwresetResultsPinDnSHA = "1b2123bcf4fdbd59ff791f1e5a2aad79f5c497e7fdb221b7b993bbb702995fc2"
	pwresetResultsUpSHA    = "b78bfc9655330cfc9cfbbc96238af8df73871768947d8b151b0db11cb14d37dd"
	pwresetResultsDownSHA  = "b315adc033b593623a1eba8c4d5e94fccd2aaee43aafbea0dcf0f61ea63dd5aa"
)

func TestTenantMemberPasswordResetResults487Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{pwresetResultsID + ".up.sql", pwresetResultsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", pwresetResultsVersion-1),
			"migration_id='" + pwresetResultsPinned + "'",
			"checksum_sha256='" + pwresetResultsPinUpSHA + "'",
			"down_checksum_sha256='" + pwresetResultsPinDnSHA + "'",
			"ERRCODE='P4870'",
			"CREATE TABLE tenant_member_password_reset_results",
			"expires_at <= created_at + interval '10 minutes'",
			"CHECK (retrieved_at IS NULL OR envelope IS NULL)",
		}},
		{pwresetResultsID + ".down.sql", pwresetResultsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", pwresetResultsVersion),
			"migration_id='" + pwresetResultsID + "'",
			"ERRCODE='P4871'",
			"DROP TABLE tenant_member_password_reset_results",
		}},
	} {
		raw, err := controlmigrations.FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		text := string(raw)
		for _, required := range script.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		guard := strings.Index(text, "RAISE EXCEPTION")
		mutation := strings.Index(text, "CREATE TABLE")
		if mutation < 0 {
			mutation = strings.Index(text, "DROP TABLE")
		}
		if guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
	for _, file := range []struct{ name, sha string }{
		{pwresetResultsPinned + ".up.sql", pwresetResultsPinUpSHA},
		{pwresetResultsPinned + ".down.sql", pwresetResultsPinDnSHA},
	} {
		raw, err := controlmigrations.FS.ReadFile(file.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != file.sha {
			t.Errorf("%s pinned %s, file is %s", file.name, file.sha, got)
		}
	}
}
