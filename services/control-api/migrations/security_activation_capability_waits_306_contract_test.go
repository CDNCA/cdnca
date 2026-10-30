package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 306 (G1-c: security activations waiting for node capability)
// sits on the exact verified 305 head. The numbers live together so the
// coordinator can renumber on merge.
const (
	capabilityWaitsVersion           = "306"
	capabilityWaitsPrevious          = "305_identity_secondary_verification"
	capabilityWaitsPreviousUpSHA     = "cb591779e5c8b35acff239ac4a5dec44caaaff5e005169d0bfab6ac22184009d"
	capabilityWaitsPreviousDownSHA   = "ca8f58f22cf5f18c7b4b3607bb00a70c3d891906a3e0635d1e4d6517925220d3"
	capabilityWaitsUpSHA             = "12ac6e3078913063754f16f2b97d8e9f6a5a3b518011fc363e77569f6ccc4242"
	capabilityWaitsDownSHA           = "bbdfce794d3382d532494f7d71b6a7bc2179cbb30e8227eb844b0b388d753b68"
	capabilityWaitsPreviousHeadCount = "(SELECT count(*) FROM schema_migrations) <> 305"
)

func TestSecurityActivationCapabilityWaits306Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{capabilityWaitsVersion + "_security_activation_capability_waits.up.sql", capabilityWaitsUpSHA, []string{
			capabilityWaitsPreviousHeadCount, capabilityWaitsPrevious, capabilityWaitsPreviousUpSHA, capabilityWaitsPreviousDownSHA,
			"ERRCODE='P3060'",
			"CREATE TABLE security_activation_capability_waits",
			"ON security_activation_capability_waits(tenant_scope_id, site_id, policy_kind) WHERE status = 'waiting'",
			"GRANT SELECT, INSERT, UPDATE ON security_activation_capability_waits TO cdnca_control_app, cdnca_control_runtime",
		}},
		{capabilityWaitsVersion + "_security_activation_capability_waits.down.sql", capabilityWaitsDownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 306", "306_security_activation_capability_waits", "ERRCODE='P3061'",
			"DROP TABLE security_activation_capability_waits;",
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
