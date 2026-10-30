package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 579 (fix-cacheflow2: producer-reported item cancellation in the
// unified background job) is a placeholder number; the merge renumbers it
// after the head it lands on. Everything that changes with that is here.
const (
	migration579Version         = 579
	migration579PreviousVersion = 578
	migration579PreviousID      = "578_certificate_binding_reservations"
	migration579PreviousUpSHA   = "139667f70fca4f1e4882ceab9e51f38ff351c044d093705d322f103175528600"
	migration579PreviousDownSHA = "72afa08de44c386b4d6de89274cbccaf3113c0e78afa48c40daa23fc2012fc05"
	migration579ID              = "579_background_job_producer_cancellation"
)

func TestBackgroundJobProducerCancellation579Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration579ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration579PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration579PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration579PreviousVersion),
			"migration_id='" + migration579PreviousID + "'",
			"checksum_sha256='" + migration579PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration579PreviousDownSHA + "'",
			"ERRCODE='P5790'",
			"CHECK (state IN ('succeeded','failed','cancelled'))",
			"(state = 'cancelled' AND error_code = 'cancelled' AND source = 'worker')",
			"result_completed_count=result_succeeded_count+result_cancelled_count",
			"IF NEW.state = 'cancelled' AND NEW.sequence = 0 THEN",
			"(failed=0 AND parent.last_error_code IS DISTINCT FROM 'cancelled')",
			"(parent.cancel_requested_at IS NULL AND cancelled=parent.total_count AND command_cancelled=0)",
			"(NEW.state='partial_failed' AND NEW.error_code NOT IN ('item_failed','cancelled'))",
			"NEW.state='cancelled' AND NEW.cancel_requested_at IS NOT NULL THEN",
		}},
		{migration579ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration579Version),
			"migration_id='" + migration579ID + "'", "ERRCODE='P5791'", "ERRCODE='P5792'",
			"CHECK (state IN ('succeeded', 'failed'))",
			"result_cancelled_count=0 AND result_failure_code IS NULL",
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
	// Down restores the exact function bodies 579 replaces.
	down, err := FS.ReadFile(migration579ID + ".down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []struct{ file, header string }{
		{"027_background_jobs.up.sql", "FUNCTION protect_background_job_item()"},
		{"115_dns_retry_after_voluntary_yield.up.sql", "CREATE OR REPLACE FUNCTION validate_background_job_projection("},
		{"115_dns_retry_after_voluntary_yield.up.sql", "CREATE OR REPLACE FUNCTION protect_background_job_attempt()"},
		{"104_background_job_settlement_dlq.up.sql", "CREATE OR REPLACE FUNCTION mark_background_job_command_mutation_094()"},
	} {
		raw, err := FS.ReadFile(source.file)
		if err != nil {
			t.Fatal(err)
		}
		start := strings.Index(string(raw), source.header)
		end := strings.Index(string(raw[start:]), "\n$$;")
		if start < 0 || end < 0 {
			t.Fatalf("%s: %s not found", source.file, source.header)
		}
		body := string(raw[start : start+end])
		if !strings.Contains(string(down), body) {
			t.Errorf("579 down does not restore %s from %s", source.header, source.file)
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration579PreviousUpSHA, ".down.sql": migration579PreviousDownSHA} {
		raw, err := FS.ReadFile(migration579PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration579PreviousID, suffix, got, want)
		}
	}
}
