package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 600 (aggregated edge owner scope, ADR 0020 §4.1). Everything that
// changes if a merge renumbers it or replaces the 599 placeholder is here.
const (
	migration600PreviousVersion = 599
	migration600PreviousID      = "599_tenant_dns_hub"
	migration600PreviousUpSHA   = "b77d0ad667929d25e0662953d9cf76e1addbb3ea01d363a60c7859c0fc20a600"
	migration600PreviousDownSHA = "ce3dfbd0dd0cb3f121eb18e8ee54678af8392599dbfcacebe7162835eaf61418"
	migration600ID              = "600_aggregated_edge_owner_scope"
)

func TestAggregatedEdgeOwnerScope600Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration600ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration600PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration600PreviousVersion),
			"migration_id='" + migration600PreviousID + "'",
			"checksum_sha256='" + migration600PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration600PreviousDownSHA + "'",
			"ERRCODE='P6000'", "ERRCODE='P6001'", "ERRCODE='P6002'", "ERRCODE='P6003'",
			"RENAME COLUMN platform_scope_id TO owner_scope_id",
			"('edge.tenant.read', ARRAY['tenant_owner', 'tenant_admin', 'tenant_viewer'])",
			"('edge.tenant.manage', ARRAY['tenant_owner', 'tenant_admin'])",
			"('edge.tenant.accounts.manage', ARRAY['tenant_owner'])",
			"('edge.tenant.accounts.manage', true)",
			"AFTER INSERT ON roles",
			"RENAME TO package_offer_spec_publishable_090_base",
			"limits - 'aggregated_edge' - 'aggregated_edge_accounts'",
		}},
		{migration600ID + ".down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 600", "migration_id='" + migration600ID + "'",
			"ERRCODE='P6004'", "ERRCODE='P6005'", "ERRCODE='P6006'",
			"RENAME COLUMN owner_scope_id TO platform_scope_id",
			"package_offer_spec_publishable_090_base(jsonb, timestamptz) RENAME TO package_offer_spec_publishable_090",
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
	for suffix, want := range map[string]string{".up.sql": migration600PreviousUpSHA, ".down.sql": migration600PreviousDownSHA} {
		raw, err := FS.ReadFile(migration600PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration600PreviousID, suffix, got, want)
		}
	}
}
