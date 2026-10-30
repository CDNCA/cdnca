package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 312 (NF19 备用IP上线顺序) and the head it requires. The number is a
// placeholder: the coordinator assigns the final number on merge.
const (
	nodeLineEndpointPublished312Version   = 312
	nodeLineEndpointPublished312PriorID   = "311_edge_system_republication"
	nodeLineEndpointPublished312PriorUp   = "c3e3272b23d5b728ac56dc1ddcb0cfbecc06c7167ca802bfc44996bc3a9ea9ef"
	nodeLineEndpointPublished312PriorDown = "b2aa0eac0c6c022e024a843f8c6ed118a925f5e9ad72773afe1e8275cc3affb8"
	nodeLineEndpointPublished312UpSHA     = "9ad72f4099c7eb5a449d77b3c38a332a708f517a6f0c67a186e10954d71b109c"
	nodeLineEndpointPublished312DownSHA   = "5a9447177396e87dd56bd2b1b9103744a11fa198a9421d66e6f116e1b0cbc11d"
)

func TestNodeLineEndpointPublished312Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"312_node_line_endpoint_published.up.sql", nodeLineEndpointPublished312UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 311", "(SELECT max(version) FROM schema_migrations) <> 311",
			nodeLineEndpointPublished312PriorID, nodeLineEndpointPublished312PriorUp, nodeLineEndpointPublished312PriorDown,
			"ERRCODE='P3120'", "CREATE VIEW node_line_endpoint_published", "online_less_than_backup_count",
			"standby_rank <= primaries - online_primaries", "online_total = 0",
			"GRANT SELECT ON node_line_endpoint_published TO cdnca_control_app, cdnca_control_runtime",
		}},
		{"312_node_line_endpoint_published.down.sql", nodeLineEndpointPublished312DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 312", "312_node_line_endpoint_published",
			"ERRCODE='P3121'", "DROP VIEW node_line_endpoint_published",
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
	if nodeLineEndpointPublished312Version != 312 {
		t.Fatal("version")
	}
}
