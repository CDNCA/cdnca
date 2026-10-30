package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 543 (fix-decide1027b item 6: ticket events for the detail's
// system lines). Its predecessor is 542, pinned by checksum.
const (
	migration543ID      = "543_ticket_events"
	migration543UpSHA   = "a4f0e03aa59fc4da8e7ee88cde19669424d616b0a6ec3e454041045abd1bea30"
	migration543DownSHA = "ad27f2b6f0abcaae94d95b75538c833d33cf76519fb1c409d865eca200586e4c"
)

func TestTicketEvents543Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration543ID + ".up.sql", migration543UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 542", "(SELECT max(version) FROM schema_migrations) <> 542",
			"migration_id='" + migration542ID + "'", migration542UpSHA, migration542DownSHA, "ERRCODE='P5430'",
			"CREATE TABLE ticket_events", "kind IN ('status', 'priority', 'assignee', 'closed', 'reopened')",
			"GRANT SELECT, INSERT ON ticket_events TO cdnca_control_app, cdnca_control_runtime;",
		}},
		{migration543ID + ".down.sql", migration543DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 543", "migration_id='" + migration543ID + "'",
			"ERRCODE='P5431'", "DROP TABLE ticket_events;",
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
	// Append only: no UPDATE or DELETE for the runtime roles.
	raw, _ := FS.ReadFile(migration543ID + ".up.sql")
	if strings.Contains(string(raw), "UPDATE ON ticket_events") || strings.Contains(string(raw), "DELETE ON ticket_events") {
		t.Fatal("ticket_events must stay append-only")
	}
}
