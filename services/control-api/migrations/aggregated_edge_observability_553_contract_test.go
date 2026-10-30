package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 553 (fix-aephase1, 占位): the own node group's 24-hour rounds and
// the third-party probe settings (method, headers, thresholds). Its guard
// pins 547's checksums; everything that changes with the number is here.
const (
	migration553Version         = 553
	migration553PreviousVersion = 552
	migration553PreviousID      = "552_usage_report_state"
	migration553PreviousUpSHA   = "8211118bdc7b76025ad0600d4e2f05790c65193510374eb019a54151ceefdc48"
	migration553PreviousDownSHA = "6e73505720198c4ce48ffd2f0fbf49f1c1afa2e9f435a4e2ded72c6e06353987"
	migration553ID              = "553_aggregated_edge_observability"
)

func TestAggregatedEdgeObservability553Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration553ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration553PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration553PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration553PreviousVersion),
			"migration_id='" + migration553PreviousID + "'",
			"checksum_sha256='" + migration553PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration553PreviousDownSHA + "'",
			"ERRCODE='P5530'", "CREATE TABLE aggregated_edge_local_rounds",
			"health_method IN ('GET', 'HEAD')", "jsonb_array_length(health_headers) <= 8",
			"failure_threshold BETWEEN 1 AND 10", "recovery_threshold BETWEEN 1 AND 10",
		}},
		{migration553ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration553Version),
			"migration_id='" + migration553ID + "'", "ERRCODE='P5531'",
			"DROP TABLE aggregated_edge_local_rounds", "DROP COLUMN health_method",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration553PreviousUpSHA, ".down.sql": migration553PreviousDownSHA} {
		raw, err := FS.ReadFile(migration553PreviousID + suffix)
		if err != nil {
			continue
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, 553 guard pins %s", migration553PreviousID, suffix, got, want)
		}
	}
}
