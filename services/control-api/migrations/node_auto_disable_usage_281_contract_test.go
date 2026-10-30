package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodeAutoDisableUsage281Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"281_node_auto_disable_usage.up.sql", "9d452586cc12a60903266cb0418b752c871471af1b70f34e60b4a45e317717a6", []string{
			"280_node_serving_holds",
			"fa2d1e6483ca3be92caf05bb736b2ec0009a95b661fcdaa73ebbb8e2d8381841",
			"1f1f1b7c726f7230b68f0d937c7ca561c25d865cb17f03605d6730c023f045f0",
			"ERRCODE='P2810'", "CREATE TABLE node_auto_disable_usage", "'traffic_enabled', false",
			"'{auto_disable,traffic_enabled}'", "'traffic_total_gb' = '500'::jsonb",
		}},
		{"281_node_auto_disable_usage.down.sql", "1d7d99dd4066ebae4bcd4fabe030c5ab3d6201f88044b8b195783472a428a1a2", []string{
			"(SELECT count(*) FROM schema_migrations) <> 281", "281_node_auto_disable_usage",
			"'traffic_enabled', true", "DROP TABLE node_auto_disable_usage",
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
