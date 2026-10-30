package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 496: L4 origin list, IPv6, ACL, admin status
// and batch receipts. Local placeholder 490, renumbered to 496 at merge
// (predecessor 495).
const (
	migration496Version         = 496
	migration496PreviousVersion = 495
	migration496ID              = "496_l4_origin_pool_acl"
	migration496PreviousID      = "495_http_policy_header_vars_conditions"
	migration496PreviousUpSHA   = "d1f710dfcc99d9063cd723ea76cb1c0b158b652393134b363550b3f2dd54bd6d"
	migration496PreviousDownSHA = "e511b05932fb54077d052a23f80e0714bb048efd2ea61c2aca7e2875d5371d4b"
	migration496UpSHA           = "5e4af277f365757f7f882ab8f0597a46ea8f0d05966bddc945de7b004646229d"
	migration496DownSHA         = "4c36faa85650454c3518caebdb36709147e6bfc641248ea7a5f7f2bbf8d7c0aa"
)

func TestL4OriginPoolACL496Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration496ID + ".up.sql", migration496UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration496PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration496PreviousVersion),
			"migration_id='" + migration496PreviousID + "'", migration496PreviousUpSHA, migration496PreviousDownSHA,
			"ERRCODE='P4960'", "ADD COLUMN origins jsonb", "ADD COLUMN listen_ipv6 boolean", "ADD COLUMN acl_default_action text",
			"ADD COLUMN acl_rules jsonb", "ADD COLUMN admin_status text", "l4_publish_intents_runtime_spec_496",
			"validate_l4_runtime_spec_341(", "'stream.batch_create', 'stream.batch_action'",
		}},
		{migration496ID + ".down.sql", migration496DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration496Version),
			"migration_id='" + migration496ID + "'", "ERRCODE='P4961'", "ERRCODE='P4962'",
			"ADD CONSTRAINT l4_publish_intents_runtime_spec_341", "DROP COLUMN origins",
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
