package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 577 (fix-mktsiteconf7, placeholder number): persisted origin auth
// delivery build failures, the subscriber's per-leaf node delivery state and
// the market.supply.node_delivery_failed notification. The merge renumbers it
// after the head it lands on; everything that changes with that is here.
const (
	migration577Version         = 577
	migration577PreviousVersion = 576
	migration577PreviousID      = "576_region_catalog_geo_codes"
	migration577PreviousUpSHA   = "a1bf4f310b89eaeffd95bf6e6b0f29e54719c3107191b8739b140d75a9c6c81b"
	migration577PreviousDownSHA = "d21cf9dd984999c6e4e23c301e62593682703914319ef2bff59028d668fed8d4"
	migration577ID              = "577_market_node_delivery_state"
)

func TestMarketNodeDeliveryState577Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration577ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration577PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration577PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration577PreviousVersion),
			"migration_id='" + migration577PreviousID + "'",
			"checksum_sha256='" + migration577PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration577PreviousDownSHA + "'",
			"ERRCODE='P5770'", "CREATE TABLE origin_auth_delivery_build_failures",
			"node_state IN ('', 'delivering', 'effective', 'failed')", "ADD COLUMN next_node_check_at",
			"(node_state = '' OR state = 'applied')",
			"('market.supply.node_delivery_failed', true",
			"('market.supply.node_delivery_failed.zh-cn', 1, 'sms'", "('market.supply.node_delivery_failed.zh-cn', 1, 'email'",
			"ARRAY['domain','supply','revision','reason']",
		}},
		{migration577ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration577Version),
			"migration_id='" + migration577ID + "'", "ERRCODE='P5771'", "ERRCODE='P5772'",
			"DROP TABLE origin_auth_delivery_build_failures", "DROP COLUMN node_state",
			"DELETE FROM notification_event_policies", "DELETE FROM admin_inbox_messages",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration577PreviousUpSHA, ".down.sql": migration577PreviousDownSHA} {
		raw, err := FS.ReadFile(migration577PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration577PreviousID, suffix, got, want)
		}
	}
}
