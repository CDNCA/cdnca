package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodeServingHolds280Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"280_node_serving_holds.up.sql", "fa2d1e6483ca3be92caf05bb736b2ec0009a95b661fcdaa73ebbb8e2d8381841", []string{
			"279_node_monitoring_overrides",
			"f954c57bdafed2ee7a0381034458ce8171805949d03a74a6db3ccba45cf894ca",
			"618c0b4546625d12d1f85da00f786f168256c174a579bd11b8666d8eb2d3bb70",
			"ERRCODE='P2800'", "CREATE TABLE node_serving_holds", "CREATE TABLE node_serving_events",
			"CREATE VIEW node_line_endpoint_serving", "family_serving = 0", "CREATE TABLE dns_cname_retargets",
			"WHERE state IN ('pending', 'applying')",
		}},
		{"280_node_serving_holds.down.sql", "1f1f1b7c726f7230b68f0d937c7ca561c25d865cb17f03605d6730c023f045f0", []string{
			"(SELECT count(*) FROM schema_migrations) <> 280", "280_node_serving_holds",
			"ERRCODE='P2803'", "DROP VIEW node_line_endpoint_serving",
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
