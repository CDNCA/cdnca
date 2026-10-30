package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// 282 follows the integration branch's 280_node_serving_holds and
// 281_node_auto_disable_usage; its guard must pin the exact 281 head.
func TestSecurityRuleCatalogConsumer282Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"282_security_rule_catalog_consumer.up.sql", "6809951208c23bd51918e881e6c355231403a88ccfb2bf9f4f9b5e61faf4c99b", []string{
			"(SELECT count(*) FROM schema_migrations) <> 281", "281_node_auto_disable_usage",
			"9d452586cc12a60903266cb0418b752c871471af1b70f34e60b4a45e317717a6",
			"1d7d99dd4066ebae4bcd4fabe030c5ab3d6201f88044b8b195783472a428a1a2",
			"ERRCODE='P2820'", "ERRCODE='P2821'", "ERRCODE='P2822'",
			"CREATE TABLE security_system_rules", "CREATE TABLE security_system_rule_tenant_states",
		}},
		{"282_security_rule_catalog_consumer.down.sql", "60e6b9c785c603df1df0cd2d95584e1697d15c3a62f16335ac0d9a1016ca00c6", []string{
			"(SELECT count(*) FROM schema_migrations) <> 282", "282_security_rule_catalog_consumer",
			"ERRCODE='P2823'", "DROP TABLE security_system_rules",
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
