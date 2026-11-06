package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 639 (dnspup probe unified purposes, selection,
// line alerts, plugin probe API; predecessor 638_security_policy_batch_idempotency,
// renumbered from the task's 638 placeholder at merge). Everything that changes
// with a renumbering is here.
const (
	migration639Version         = 639
	migration639ID              = "639_probe_dnspup_unified"
	migration639PreviousVersion = 638
	migration639PreviousID      = "638_security_policy_batch_idempotency"
	migration639PreviousUpSHA   = "29eed0e1939f03ced6f1853921b4f5be5e047726e427fe3c0a5f72d4996f148c"
	migration639PreviousDownSHA = "c6b092c39067eb0866d2169ede92f9e56143ac6929628725b0f55650f7a3cf37"
	migration639UpSHA           = "f2473ce04500fc9a4d35f0e40a614e80a676407b847d99517a62b6bf774a6f70"
	migration639DownSHA         = "f1ec74f785be5aa510541f1a2ea9f86d27a41508d056fcf5bf366923a06ce119"
)

func TestProbeDNSPupUnified639Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration639ID + ".up.sql", migration639UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration639PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration639PreviousVersion),
			"migration_id='" + migration639PreviousID + "'", migration639PreviousUpSHA, migration639PreviousDownSHA,
			"ERRCODE='P6390'", "'probes.dnspup.request'", "'node.dnspup.line_unreachable.zh-cn'",
			"CREATE TABLE probe_dnspup_purposes", "CREATE TABLE node_dnspup_probe_overrides",
			"CREATE TABLE probe_dnspup_plugin_requests", "CREATE TABLE node_dnspup_line_alert_states",
			"CREATE TRIGGER roles_tenant_probes_dnspup_request_639",
		}},
		{migration639ID + ".down.sql", migration639DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration639Version),
			"migration_id='" + migration639ID + "'", "ERRCODE='P6391'", "ERRCODE='P6392'",
			"DROP TABLE probe_dnspup_purposes", "DELETE FROM permissions WHERE name = 'probes.dnspup.request'",
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
