package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 531: platform members with
// platform.admin or certificates.manage pass acme_runtime_actor_is_active_048
// (body uses $1/$2, fixing 048's column-shadowed cross-tenant pass); 048's six
// (scope_id,user_id)→memberships actor foreign keys become user_id→users;
// 047's snapshot check calls the function instead of its own membership lookup.
const (
	migration531ID      = "531_acme_platform_actor"
	migration531UpSHA   = "72e1974077bb7c323bf42068ecb95de88363a3ca8a425f8d159eefb063e3095a"
	migration531DownSHA = "32d96cca107cf01fff61e32bd0de6a2e60d48d556c0140453825b771eac98f09"
)

func TestACMEPlatformActor531Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration531ID + ".up.sql", migration531UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 530", "migration_id='530_installation_ban_rejected_notice'",
			migration530UpSHA, migration530DownSHA, "ERRCODE='P5310'",
			"CREATE OR REPLACE FUNCTION acme_runtime_actor_is_active_048(scope_id uuid, actor_id uuid)",
			"platform_scope.kind = 'platform'", "IN ('platform.admin', 'certificates.manage')",
			"WHERE scope.id = $1 AND scope.kind = 'tenant'", "assignment.user_id = $2",
			"DROP CONSTRAINT certificate_orders_created_actor_fk_048",
			"CREATE OR REPLACE FUNCTION validate_acme_issuance_operation_snapshot_047()",
			"OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, snapshot_actor_id) THEN",
			"ADD CONSTRAINT acme_renewal_claim_actor_fk_531\n        FOREIGN KEY (actor_user_id) REFERENCES users(id)",
		}},
		{migration531ID + ".down.sql", migration531DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 531", "migration_id='" + migration531ID + "'",
			"ERRCODE='P5311'", "ERRCODE='P5312'", "CREATE OR REPLACE FUNCTION validate_acme_issuance_operation_snapshot_047()",
			"CREATE OR REPLACE FUNCTION acme_runtime_actor_is_active_048(scope_id uuid, actor_id uuid)",
			"WHERE scope.id = $1 AND scope.kind = 'tenant'",
			"ADD CONSTRAINT certificate_orders_created_actor_fk_048\n        FOREIGN KEY (scope_id, created_by_user_id)",
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
		if strings.Contains(string(raw), "platform_scope") != (script.name == migration531ID+".up.sql") {
			t.Errorf("%s platform branch presence is wrong", script.name)
		}
		// 048's shadowed comparison must not come back in either direction.
		body := string(raw)[strings.Index(string(raw), "acme_runtime_actor_is_active_048(scope_id uuid"):]
		if strings.Contains(body, "= scope_id") || strings.Contains(body, "= actor_id") {
			t.Errorf("%s compares against a column-shadowed parameter name", script.name)
		}
	}
}
