package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 422 (XDP filter fallback / reattach templates
// of node.security.event) is a placeholder number: it sits on 421 (sec-events,
// itself a placeholder) + 1. Everything that changes with the renumbering is
// here.
const (
	migration422Version         = 422
	migration422ID              = "422_node_security_xdp_alerts"
	migration422PreviousID      = "421_node_security_event_alerts"
	migration422PreviousUpSHA   = "a1b78379c70f918fc5efff8c6b6291bfd417444937f10e3339fd2a58bbfb54b5"
	migration422PreviousDownSHA = "51f53b9be781092f73e0d870a1201c0c8ddf78723561b3f3329b7dd2822e2597"
	migration422UpSHA           = "2464075f330342eb8dc3aeab8371ba0465711bc820678d1d8b7b235bea82c6c5"
	migration422DownSHA         = "a1adaf5012a11bde72bf5290bea9225a73b881635a6e251c82e8b53d624a7e0d"
)

func TestNodeSecurityXDPAlerts422Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration422ID + ".up.sql", migration422UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration422Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration422Version-1),
			"migration_id='" + migration422PreviousID + "'", migration422PreviousUpSHA, migration422PreviousDownSHA,
			"ERRCODE='P4220'", "'node.security.xdp.zh-cn'",
		}},
		{migration422ID + ".down.sql", migration422DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration422Version),
			"migration_id='" + migration422ID + "'", "ERRCODE='P4221'", "ERRCODE='P4222'",
			"'node.security.xdp.zh-cn'",
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
