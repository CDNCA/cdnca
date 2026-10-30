package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 498: tenant_owner loses billing.order_records.manage
// and gets the read-only billing.order_records.read. Branch placeholder 490
// (guard on 489), renumbered to 498 behind 497 at merge. Everything that changes is here.
const (
	migration498Version         = 498
	migration498PreviousVersion = 497
	migration498ID              = "498_tenant_order_records_read_only"
	migration498PreviousID      = "497_system_configuration_trim_region_overrides"
	migration498PreviousUpSHA   = "1d70f77b38fee7d68a22643bc3511ad9d8d50b008a494e707444d4b8cc659fbc"
	migration498PreviousDownSHA = "8086cfce6e06bc5c1a414e0cf87e16bf107f929760495e5991243da74e1a680f"
	migration498UpSHA           = "f3259e3d415e764573a2997e8be3033fc6ca478adf293112ddf112c6065dd8cc"
	migration498DownSHA         = "c545c1473f21d48e7548e6015259abdc8648298c115a0edb9c771f34c76f74a6"
)

func TestTenantOrderRecordsReadOnly498Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration498ID + ".up.sql", migration498UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration498PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration498PreviousVersion),
			"migration_id='" + migration498PreviousID + "'", migration498PreviousUpSHA, migration498PreviousDownSHA,
			"ERRCODE='P4980'", "ERRCODE='P4981'", "('billing.order_records.read'",
			"grant_row.permission_name='billing.order_records.manage'",
			"DROP TRIGGER roles_account_order_record_permission_207 ON roles",
			"ENABLE TRIGGER role_permissions_system_role_guard",
			"FOREIGN KEY(created_by_user_id) REFERENCES users(id)",
		}},
		{migration498ID + ".down.sql", migration498DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration498Version),
			"migration_id='" + migration498ID + "'", "ERRCODE='P4982'", "ERRCODE='P4983'", "ERRCODE='P4984'",
			"EXECUTE FUNCTION grant_account_order_record_permission_207()",
			"ENABLE TRIGGER role_permissions_system_role_guard",
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
