package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 491: audit_events.user_agent for the operation log
// 浏览器UA column. Placeholder 490 renumbered to 491 at merge (after
// 490_aggregated_edge_alert_access_point). Everything that changes is here.
const (
	migration491Version         = 491
	migration491PreviousVersion = 490
	migration491ID              = "491_audit_user_agent"
	migration491PreviousID      = "490_aggregated_edge_alert_access_point"
	migration491PreviousUpSHA   = "309e8d8dcea2473d3be5c88448c7fbb8f3b7f1e7b08750db41142a7e7966b48d"
	migration491PreviousDownSHA = "12ed9a7ef6d47a8214dcbd8d286266a06670d4262ce44ab18b058cac8484a6eb"
	migration491UpSHA           = "910509fe143010d111092d82e708e54f306c6eb8ac16f496005999d1623a5ff2"
	migration491DownSHA         = "86252f1ad503ed9ca383de7ef96d23d97361463daf94bfc1a8de2192271b908c"
)

func TestAuditUserAgent491Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration491ID + ".up.sql", migration491UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration491PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration491PreviousVersion),
			"migration_id='" + migration491PreviousID + "'", migration491PreviousUpSHA, migration491PreviousDownSHA,
			"ERRCODE='P4910'", "ADD COLUMN user_agent text NOT NULL DEFAULT ''",
			"char_length(user_agent) <= 512", "source.user_agent = NEW.user_agent",
			"CREATE TRIGGER audit_event_archive_insert_491",
		}},
		{migration491ID + ".down.sql", migration491DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration491Version),
			"migration_id='" + migration491ID + "'", "ERRCODE='P4911'", "ERRCODE='P4912'",
			"CREATE TRIGGER audit_event_archive_insert_361", "DROP COLUMN user_agent",
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
