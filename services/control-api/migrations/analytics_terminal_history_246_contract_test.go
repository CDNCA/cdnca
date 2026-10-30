package migrations

import (
	"strings"
	"testing"
)

func TestAnalyticsTerminalHistory246RetainsConfirmationAndIdentityFences(t *testing.T) {
	for _, direction := range []string{"up", "down"} {
		content, err := FS.ReadFile("246_analytics_terminal_history_progress." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		for _, required := range []string{"LOCK TABLE schema_migrations", "receipt.receipt_identity_sha256 IS DISTINCT FROM p_receipt_identity_sha256", "generation.retired_at IS NOT NULL", "p_at<=generation.updated_at", "receipt.state IN ('prepared','broker_ack_observed')"} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s missing fence %q", direction, required)
			}
		}
		if direction == "up" && !strings.Contains(text, "GREATEST(generation.prepared_stream_floor,generation.broker_stream_ack_floor)+1") {
			t.Fatal("preparation does not bind confirmed broker floor")
		}
		if direction == "down" && !strings.Contains(text, "p_stream_sequence<>generation.prepared_stream_floor+1") {
			t.Fatal("rollback did not preserve prior condition")
		}
		for _, forbidden := range []string{"TRUNCATE ", "DELETE FROM ", "DISABLE TRIGGER", " TO PUBLIC"} {
			if strings.Contains(strings.ToUpper(text), forbidden) {
				t.Fatalf("unsafe migration operation: %s", forbidden)
			}
		}
	}
}
