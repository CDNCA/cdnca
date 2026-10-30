package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 395 (TCP malformed flag filter and conntrack
// INVALID drop in the ddos_protection category) is a placeholder number
// (reserved 397): the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is in this block.
const (
	migration395Version         = 395
	migration395ID              = "395_ddos_tcp_flags"
	migration395PreviousID      = "394_aggregated_edge_quality"
	migration395PreviousUpSHA   = "31742813bd63915494f29db87db6d17dfd6f99da4474cb9ecb57fb0761da40c3"
	migration395PreviousDownSHA = "0253b97951f615c5b604f5ab57d6ad9e7202f36108497d783e6dc5c9f1375fcb"
	migration395UpSHA           = "a54c3be15b6174c90bd92234baa891f4f80eb2131eba6b64f20d6daddd55ba13"
	migration395DownSHA         = "b48d953879faa9b83bf24642ea7981dc318291ec47a3fda4375ab31ba6d21817"
)

func TestDDoSTCPFlags395Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration395ID + ".up.sql", migration395UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration395Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration395Version-1),
			"migration_id='" + migration395PreviousID + "'", migration395PreviousUpSHA, migration395PreviousDownSHA,
			"ERRCODE='P3950'", "CREATE OR REPLACE FUNCTION system_configuration_v2_ddos_protection_is_valid",
			"ARRAY['empty_connection','tcp_flag_filter','tcp_flag_types','drop_invalid']",
			"ARRAY['null','xmas','syn_fin','syn_rst','fin','all']",
		}},
		{migration395ID + ".down.sql", migration395DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration395Version),
			"migration_id='" + migration395ID + "'", "ERRCODE='P3951'",
			"ARRAY['tcp_flag_filter','tcp_flag_types','drop_invalid']",
			"], ARRAY['empty_connection']) OR",
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
