package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 385 (ge-analytics, site traffic limits) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration385Version         = 385
	migration385ID              = "385_site_traffic_limits"
	migration385PreviousID      = "384_admin_inbox_messages"
	migration385PreviousUpSHA   = "5c11871b2ece4b55f9046cb4d43d6793245747bb616aa70f1a2394e1e2187d3c"
	migration385PreviousDownSHA = "9e97da3f8a96458279a51741ae79e98f771971b9ca7e315778476da5f8d96c62"
	migration385UpSHA           = "6f341a154adc549a92d4ad631dcd95549ada31a5f34d522bb4b2c049ac898529"
	migration385DownSHA         = "93329a6b93bf825da3a03317fa0b7a614294f0c65217abec5dad8b55e8e13137"
)

func TestSiteTrafficLimits385Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration385ID + ".up.sql", migration385UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration385Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration385Version-1),
			"migration_id='" + migration385PreviousID + "'", migration385PreviousUpSHA, migration385PreviousDownSHA,
			"ERRCODE='P3850'", "CREATE TABLE site_traffic_limits", "CREATE TABLE site_traffic_limit_write_requests",
			"exceeded_period IN ('daily','monthly','total')",
		}},
		{migration385ID + ".down.sql", migration385DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration385Version),
			"migration_id='" + migration385ID + "'", "ERRCODE='P3851'",
			"DROP TABLE site_traffic_limit_write_requests", "DROP TABLE site_traffic_limits",
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
