package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 421 (node security events in the notification
// center) is a placeholder number (BATCH-PLUGIN 第 18 条 reserves 426; the
// loader needs consecutive versions, so it sits on the integration head + 1).
// Everything that changes with the renumbering is here.
const (
	migration421Version         = 421
	migration421ID              = "421_node_security_event_alerts"
	migration421PreviousID      = "420_aggregated_edge_fixed"
	migration421PreviousUpSHA   = "917bc1485185055f4e8442da990375423819f87e942ba80432507a24e8dd9592"
	migration421PreviousDownSHA = "d6909aa87797a285e8843aaf0165337d06ee8798a37a16ed073265c42e874a26"
	migration421UpSHA           = "a1b78379c70f918fc5efff8c6b6291bfd417444937f10e3339fd2a58bbfb54b5"
	migration421DownSHA         = "51f53b9be781092f73e0d870a1201c0c8ddf78723561b3f3329b7dd2822e2597"
)

func TestNodeSecurityEventAlerts421Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration421ID + ".up.sql", migration421UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration421Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration421Version-1),
			"migration_id='" + migration421PreviousID + "'", migration421PreviousUpSHA, migration421PreviousDownSHA,
			"ERRCODE='P4210'", "'node.security.event'", "'node.security.event.zh-cn'",
		}},
		{migration421ID + ".down.sql", migration421DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration421Version),
			"migration_id='" + migration421ID + "'", "ERRCODE='P4211'", "ERRCODE='P4212'",
			"'node.security.event.zh-cn'",
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
