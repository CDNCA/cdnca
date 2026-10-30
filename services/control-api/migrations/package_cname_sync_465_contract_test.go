package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 465 is a placeholder number: the merge
// renumbers it to 465. Everything that changes with the renumbering is here
// (plus the version in the SQL guards, ERRCODE P4650/P4651 and DO labels).
const (
	migration465Version         = 465
	migration465ID              = "465_package_cname_sync"
	migration465PreviousID      = "464_impersonation_direct_switch"
	migration465PreviousUpSHA   = "b2fd775b5f606d395686a7ecea5f38b5520205710b21507d1f893070dcdeffea"
	migration465PreviousDownSHA = "03cf9db5368de7102fd1dbd57b0f1bce93bf3bd9fd119622559b6e6c200f9411"
	migration465UpSHA           = "769f707d96643c9ac8d7001c4167ab12d73c3f86cdcd84ccafd58554ea72a61e"
	migration465DownSHA         = "2235ca001a1ded0c1d73ca91d3c58d09b306507e2f545576febbd8226ccc6bc8"
)

func TestPackageCNAMESync465Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration465ID + ".up.sql", migration465UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration465Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration465Version-1),
			"migration_id='" + migration465PreviousID + "'", migration465PreviousUpSHA, migration465PreviousDownSHA,
			"ERRCODE='P4650'", "CREATE TABLE package_cname_sync_jobs", "UNIQUE (product_id, product_revision)",
			"CREATE TABLE package_cname_sync_items", "PRIMARY KEY (job_id, subscription_id)",
			"'sold_override', 'future_entitlement', 'inactive'",
		}},
		{migration465ID + ".down.sql", migration465DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration465Version),
			"migration_id='" + migration465ID + "'", "ERRCODE='P4651'",
			"DROP TABLE package_cname_sync_items", "DROP TABLE package_cname_sync_jobs",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
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
