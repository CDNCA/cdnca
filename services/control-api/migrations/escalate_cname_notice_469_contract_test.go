package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 469 (owner notice when a split CNAME cannot
// be written automatically) guards the 468_node_native_runtime head
// (task/20261024-merge-nru); renumber at the merge if 469 is taken (the
// guard, the error codes P<version>0/1/2 and the checksums below).
const (
	migration469Version         = 469
	migration469ID              = "469_escalate_cname_notice"
	migration469PreviousID      = "468_node_native_runtime"
	migration469PreviousUpSHA   = "0e6ce3d3dc426695ab7c142fa2581f0e5cce0a2a754e14bfc7a6700a04b96dba"
	migration469PreviousDownSHA = "8a4e6bd6fabe1c56cc277f48d570d733def4555f97f4cff7616235d94625a587"
	migration469UpSHA           = "aa849a7b833d78a97c94665790a403c2240775cce17686d07bdcf56efb3f959f"
	migration469DownSHA         = "83464b6343256e4b45087e0eeeda7f852906e868879bf10ba115e094142fd00a"
)

func TestEscalateCNAMENotice469Contract(t *testing.T) {
	const event, template = "security.escalate.cname_change_required", "security.escalate.cname_change_required.zh-cn"
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration469ID + ".up.sql", migration469UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration469Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration469Version-1),
			"migration_id='" + migration469PreviousID + "'", migration469PreviousUpSHA, migration469PreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", migration469Version),
			"('" + event + "', true, true, true, 1, 1, true, true, false, now())",
			"('" + template + "', 1, 'sms', ''", "('" + template + "', 1, 'email', ",
			"ARRAY['domain','cname','reason']", "{{.domain}}", "{{.cname}}", "{{.reason}}",
		}},
		{migration469ID + ".down.sql", migration469DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration469Version),
			"migration_id='" + migration469ID + "'", fmt.Sprintf("ERRCODE='P%d1'", migration469Version),
			fmt.Sprintf("ERRCODE='P%d2'", migration469Version),
			"DELETE FROM notification_templates WHERE template_id = '" + template + "'",
			"DELETE FROM notification_event_policies WHERE event_type = '" + event + "'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
