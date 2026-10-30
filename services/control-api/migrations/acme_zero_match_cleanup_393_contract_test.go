package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 393 is a placeholder number: the merge renumbers
// it after the head it lands on. Everything that changes with the renumbering
// is in this block.
const (
	migration393Version         = 393
	migration393ID              = "393_acme_zero_match_cleanup"
	migration393PreviousID      = "392_package_monitor_audit_hash_v2"
	migration393PreviousUpSHA   = "6ca9f2f0f63718778374cffaebfb7cc6e0e3f56e2383139c0e7b9d829d68ec20"
	migration393PreviousDownSHA = "fe1ce7fafa4c2434296783adc449e099bc60dac6486abccd3953a7a8712f60ca"
	migration393UpSHA           = "6e30e3b5f94026497b7847c26dad04b5d64676c0c757c744384348fd197f05d9"
	migration393DownSHA         = "54cb2a15504e7363ee8d179a33a7309b3c8d215ae225bb3cc78ae262ec5d7ae5"
)

func TestACMEZeroMatchCleanup393Contract(t *testing.T) {
	const handleRequired = "NEW.provider_ref IS DISTINCT FROM frozen_provider OR NEW.remote_record_ref IS NULL"
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration393ID + ".up.sql", migration393UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration393Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration393Version-1),
			"migration_id='" + migration393PreviousID + "'", migration393PreviousUpSHA, migration393PreviousDownSHA,
			"ERRCODE='P3930'", "CREATE OR REPLACE FUNCTION validate_acme_challenge_publication_048()",
			"NEW.state IN ('cleanup_claimed', 'cleaned')",
			"AND NEW.provider_ref IS NULL AND NEW.remote_record_ref IS NULL", handleRequired,
			// A published handle stays immutable, so an empty cleanup cannot follow it.
			"DNS-01 remote record handle is immutable after publication",
		}},
		{migration393ID + ".down.sql", migration393DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration393Version),
			"migration_id='" + migration393ID + "'", "ERRCODE='P3931'", "ERRCODE='P3932'",
			"CREATE OR REPLACE FUNCTION validate_acme_challenge_publication_048()", handleRequired,
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
	down, err := FS.ReadFile(migration393ID + ".down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(down), "NEW.state IN ('cleanup_claimed', 'cleaned')") {
		t.Fatal("393 down must restore the 048 handle requirement")
	}
}
