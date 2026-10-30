package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 501: node_line_endpoint_published counts
// primaries/standbys/online per (carrier, address family).
// renumbered 498→501 (predecessor 500).
const (
	migration501Version         = 501
	migration501PreviousVersion = 500
	migration501ID              = "501_node_line_endpoint_published_per_carrier"
	migration501UpSHA           = "b3d177340a3e14288a119c60fb405cc768b6c0cdd7aaa34ba6c6acb47e9bb671"
	migration501DownSHA         = "f26c8f2b5b8001034e034b18fd71b3d078d7ecbfb23bb4517acadd061fbbe68e"
)

func TestNodeLineEndpointPublishedPerCarrier501Contract(t *testing.T) {
	const perCarrier = "PARTITION BY tenant_scope_id, line_group_id, config_revision, carrier, address_family"
	const perFamily = "PARTITION BY tenant_scope_id, line_group_id, config_revision, address_family"
	view := func(raw string) string {
		return raw[strings.Index(raw, "CREATE OR REPLACE VIEW node_line_endpoint_published"):]
	}
	for _, script := range []struct {
		name, sha       string
		required        []string
		partition, gone string
	}{
		{migration501ID + ".up.sql", migration501UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration501PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration501PreviousVersion),
			"migration_id='" + migration500ID + "'", migration500UpSHA, migration500DownSHA, "ERRCODE='P5010'",
			"SELECT serving.*, endpoint.carrier, endpoint.priority",
		}, perCarrier, perFamily},
		{migration501ID + ".down.sql", migration501DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration501Version),
			"migration_id='" + migration501ID + "'", "ERRCODE='P5011'",
		}, perFamily, perCarrier},
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
		// Both window frames and the standby rank partition are per carrier (up) or per family (down).
		body := view(string(raw))
		if strings.Count(body, script.partition) != 3 || strings.Contains(body, script.gone) {
			t.Errorf("%s partitions: want 3x %q and no %q", script.name, script.partition, script.gone)
		}
	}
	// The down view is exactly 312's.
	original, err := FS.ReadFile("312_node_line_endpoint_published.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, _ := FS.ReadFile(migration501ID + ".down.sql")
	body312 := string(original)[strings.Index(string(original), "CREATE VIEW node_line_endpoint_published"):]
	body312 = body312[:strings.Index(body312, "FROM counted;")]
	if !strings.Contains(string(down), strings.Replace(body312, "CREATE VIEW", "CREATE OR REPLACE VIEW", 1)) {
		t.Error("501 down must restore the 312 view")
	}
}
