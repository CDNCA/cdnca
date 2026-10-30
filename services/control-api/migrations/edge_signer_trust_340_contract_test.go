package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 340 (node signer trust) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration340Version         = 340
	migration340ID              = "340_edge_signer_trust"
	migration340PreviousID      = "339_security_rule_catalog_republication"
	migration340PreviousUpSHA   = "9fa371339d29ea5ec41e6337d0291a8037185c6e0b7c39842753bd337626a310"
	migration340PreviousDownSHA = "31acae1731a07cf53a9dd0a3f20bf32ab212d4616bdb972d78996448abe9ff45"
	migration340UpSHA           = "2a5bbd98e64db2e52fa2e9f5683ecd8cbac139ef01e5cbaf3f41524667fea8f5"
	migration340DownSHA         = "4cd5ebdedd4e5ed677b4b1916d179a244597d4ac47605414c82aa0f88a02927f"
)

func TestEdgeSignerTrust340Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration340ID + ".up.sql", migration340UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration340Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration340Version-1),
			"migration_id='" + migration340PreviousID + "'", migration340PreviousUpSHA, migration340PreviousDownSHA,
			"ERRCODE='P3400'", "CREATE TABLE edge_signer_trust_documents", "CREATE TABLE edge_signer_trust_events",
			"CREATE TABLE edge_signer_trust_node_state", "edge_signer_trust_documents_append_only_340",
			"edge_signer_trust_events_no_truncate_340",
		}},
		{migration340ID + ".down.sql", migration340DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration340Version),
			"migration_id='" + migration340ID + "'", "ERRCODE='P3401'", "ERRCODE='P3403'",
			"DROP TABLE edge_signer_trust_documents",
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
