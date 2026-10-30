package announcement

import (
	"os"
	"strings"
	"testing"
)

func TestAnnouncementDownFailsClosedBeforeDroppingFacts(t *testing.T) {
	script, err := os.ReadFile("../../migrations/043_announcements.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	lock := strings.Index(text, "LOCK TABLE announcements")
	guard := strings.Index(text, "migration 043 rollback requires announcement facts to be archived and absent")
	firstDrop := strings.Index(text, "DROP TRIGGER")
	if lock < 0 || guard < 0 || firstDrop < 0 || lock > firstDrop || guard > firstDrop {
		t.Fatal("043 down must lock and check announcement facts before destructive statements")
	}
	for _, table := range []string{
		"announcements", "announcement_versions", "announcement_audience_users", "announcement_audience_groups",
		"announcement_recipient_snapshots", "announcement_inbox_events", "announcement_inbox_states", "announcement_write_requests",
	} {
		if !strings.Contains(text, "EXISTS (SELECT 1 FROM "+table+")") {
			t.Fatalf("043 down does not guard %s", table)
		}
	}
}
