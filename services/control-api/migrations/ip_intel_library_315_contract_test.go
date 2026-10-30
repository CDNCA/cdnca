package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Placeholder number; renumbered on merge with the const block.
const (
	migration315Version         = 315
	migration315ID              = "315_ip_intel_library"
	migration315PreviousID      = "314_ticket_attachment_cleanup"
	migration315PreviousUpSHA   = "e5b4dc29d293a7fbbf64a089f26f443f49e3d703021e32fdc64a48a7aadd7ffa"
	migration315PreviousDownSHA = "62230c4fca3eabef097e6b338508fef63bed34642af0a69109345733b81d1c3d"
	migration315UpSHA           = "5632dfd2da07bdf177f02996c1b319075aa6c781c1a745b3bf4e2814b9b84755"
	migration315DownSHA         = "b2e8ac45c3b828a7ba13f20b18340cfe59cc8b511da8beea43e4efa8357399c8"
)

func TestIPIntelLibrary315Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration315ID + ".up.sql", migration315UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration315Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration315Version-1),
			"migration_id='" + migration315PreviousID + "'", migration315PreviousUpSHA, migration315PreviousDownSHA,
			"ERRCODE='P3150'", "CREATE TABLE ip_intel_library", "CREATE TABLE ip_intel_sync_state",
			"ip intel library revisions only move forward",
		}},
		{migration315ID + ".down.sql", migration315DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration315Version),
			"migration_id='" + migration315ID + "'", "ERRCODE='P3151'", "DROP TABLE ip_intel_library",
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
	for _, name := range []string{migration315PreviousID + ".up.sql", migration315PreviousID + ".down.sql"} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		want := migration315PreviousUpSHA
		if strings.HasSuffix(name, ".down.sql") {
			want = migration315PreviousDownSHA
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Fatalf("%s checksum %s, guard expects %s", name, got, want)
		}
	}
}
