package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 398 (tenant member email invitations) is a
// placeholder number on the integration head + 1; everything that changes
// with the renumbering is here.
const (
	migration398Version         = 398
	migration398ID              = "398_tenant_member_invitations"
	migration398PreviousID      = "397_plugin_providers"
	migration398PreviousUpSHA   = "5fa98715622e84f6d65b6ae887fca871e688140d7ea6eb950b6fed1ec5cf2513"
	migration398PreviousDownSHA = "a2c969e2e7e2ec74394597a04b809d59eaa836c7ace95011d891434b915df978"
	migration398UpSHA           = "a380fd93568e70d22bd9fb4f842686225b66d4ed2bd86a72a9b6d16a7e2c882e"
	migration398DownSHA         = "ef525337ac937c5974d51c66e657f2d01223d40a028345c56a19d8cdb8a394dd"
)

func TestTenantMemberInvitations398Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration398ID + ".up.sql", migration398UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration398Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration398Version-1),
			"migration_id='" + migration398PreviousID + "'", migration398PreviousUpSHA, migration398PreviousDownSHA,
			"ERRCODE='P3980'", "CREATE TABLE tenant_member_invitations_398", "'identity.tenant_member_invitation'",
			"('tenant_member_invitation', 1, 'email'",
		}},
		{migration398ID + ".down.sql", migration398DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration398Version),
			"migration_id='" + migration398ID + "'", "ERRCODE='P3982'", "ERRCODE='P3983'",
			"DROP TABLE tenant_member_invitations_398",
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
