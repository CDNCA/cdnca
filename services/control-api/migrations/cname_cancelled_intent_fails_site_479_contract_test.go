package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (assigned 479; the guard pins 478 by checksum and
// expects the head 478). Every number the merge renumbering touches is here.
const (
	cancelledIntentVersion       = 479
	cancelledIntentID            = "479_cname_cancelled_intent_fails_site"
	cancelledIntentPinnedID      = "478_security_activation_rule_pack_waits"
	cancelledIntentPinnedUpSHA   = "63e4d195ecef588d164e898a588d742dac7b4c1206434a0b770631dced9b806c"
	cancelledIntentPinnedDownSHA = "a250d31d998642b58580b6a0520c4b02eea72cfb473f3555795006e3e4a19bb1"
	cancelledIntentUpSHA         = "c75ffc514f776a7ec0161b29738bb1a6e15eaa896e5335954ee498d837bf6050"
	cancelledIntentDownSHA       = "3479adb4c3b7feec74a7a88a4ab677e4d3e1abc871993be868b797c2020b9a9b"
)

func TestCNAMECancelledIntentFailsSite479Contract(t *testing.T) {
	previous := cancelledIntentVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{cancelledIntentID + ".up.sql", cancelledIntentUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + cancelledIntentPinnedID + "'",
			"checksum_sha256='" + cancelledIntentPinnedUpSHA + "'",
			"down_checksum_sha256='" + cancelledIntentPinnedDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", cancelledIntentVersion),
			"job.state IN ('queued','running','failed','cancelled')",
			"intent_match.intent_job_state IN ('failed','cancelled') AND NEW.cname_state<>'failed'",
		}},
		{cancelledIntentID + ".down.sql", cancelledIntentDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", cancelledIntentVersion),
			"migration_id='" + cancelledIntentID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", cancelledIntentVersion),
			"job.state IN ('queued','running','failed') ORDER BY",
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
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "CREATE OR REPLACE FUNCTION"); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
