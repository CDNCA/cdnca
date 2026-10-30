package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 509: error page assets get a display name. Branch
// placeholder 500 behind s5b; the merge renumbered it to 509 behind 508.
// Everything that changes with the number is here.
const (
	migration509Version         = 509
	migration509PreviousVersion = 508
	migration509ID              = "509_error_page_asset_name"
	migration509PreviousID      = migration508ID
	migration509PreviousUpSHA   = migration508UpSHA
	migration509PreviousDownSHA = migration508DownSHA
	migration509UpSHA           = "3f8d0df112806f7a9be9d3fb1f6453466c3d085ee5e9fa281d384947b2f2d333"
	migration509DownSHA         = "91113797adc319abcf00c5713eb5a02370accd17199fd0fa41066bc48d58a58d"
)

func TestErrorPageAssetName509Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration509ID + ".up.sql", migration509UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration509PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration509PreviousVersion),
			"migration_id='" + migration509PreviousID + "'", migration509PreviousUpSHA, migration509PreviousDownSHA,
			"ERRCODE='P5090'", "ADD COLUMN name text NOT NULL DEFAULT ''", "char_length(name) BETWEEN 1 AND 128",
		}},
		{migration509ID + ".down.sql", migration509DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration509Version),
			"migration_id='" + migration509ID + "'", "ERRCODE='P5091'", "DROP COLUMN name",
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
