package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 384 (administrator message center) is a placeholder number:
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is in this block.
const (
	migration384Version         = 384
	migration384ID              = "384_admin_inbox_messages"
	migration384PreviousID      = "383_account_suspension_site_holds"
	migration384PreviousUpSHA   = "a2c402da2f2d338b01c61b52c985b17d2f736358275e3f05601c068402145dfd"
	migration384PreviousDownSHA = "986483de8f74de7950de1886f3a636c2950437921abf2e5ed2c880f5341dadc2"
	migration384UpSHA           = "5c11871b2ece4b55f9046cb4d43d6793245747bb616aa70f1a2394e1e2187d3c"
	migration384DownSHA         = "9e97da3f8a96458279a51741ae79e98f771971b9ca7e315778476da5f8d96c62"
)

func TestAdminInboxMessages384Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration384ID + ".up.sql", migration384UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration384Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration384Version-1),
			"migration_id='" + migration384PreviousID + "'", migration384PreviousUpSHA, migration384PreviousDownSHA,
			"ERRCODE='P3840'", "CREATE TABLE admin_inbox_messages",
		}},
		{migration384ID + ".down.sql", migration384DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration384Version),
			"migration_id='" + migration384ID + "'", "ERRCODE='P3841'",
			"DROP TABLE admin_inbox_messages",
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
