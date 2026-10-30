package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 494 (回源设置): the pool's HTTP origin
// port, the site's origin auth switch, origins inheriting the pool's port,
// request Host visitor_port, follow protocol and port. Local
// placeholder 490, renumbered to 494 at merge (predecessor 493). Everything that changes is here.
const (
	migration494Version         = 494
	migration494PreviousVersion = 493
	migration494ID              = "494_site_origin_parity"
	migration494PreviousID      = "493_system_configuration_nginx_override_scope_key"
	migration494PreviousUpSHA   = "fa961053ca5cc3d43427db05819f3c367d4df16578dc72a937c0c43b0ddba1a5"
	migration494PreviousDownSHA = "73b0a06256b2c413c8bea9a3e8eca6cf6162110f2882fa9a6a5fb224d97c7572"
	migration494UpSHA           = "7571f8ae527eaad466254f810a82b35c9479a5ccb167ec9d0278a80a64db7532"
	migration494DownSHA         = "1026828343348849ec5d8fb4a2bc7e86cb8737a93d1aede302016790b93031b0"
)

func TestSiteOriginParity494Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration494ID + ".up.sql", migration494UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration494PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration494PreviousVersion),
			"migration_id='" + migration494PreviousID + "'", migration494PreviousUpSHA, migration494PreviousDownSHA,
			"ERRCODE='P4940'", "ADD COLUMN http_port integer NOT NULL DEFAULT 80",
			"ADD COLUMN origin_auth_enabled boolean NOT NULL DEFAULT true",
			"request_host_mode IN ('visitor', 'visitor_port', 'origin', 'custom')",
			"DROP CONSTRAINT site_origin_pools_tls_379", "ADD COLUMN port_inherited boolean NOT NULL DEFAULT false",
		}},
		{migration494ID + ".down.sql", migration494DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration494Version),
			"migration_id='" + migration494ID + "'", "ERRCODE='P4941'", "ERRCODE='P4942'",
			"ADD CONSTRAINT site_origin_pools_tls_379", "DROP COLUMN port_inherited",
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
