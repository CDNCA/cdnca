package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 534 (fix-dec1027): platform administrators create package period
// reset authority bindings and review identity verification cases for any
// tenant under their own identity. The 533 predecessor is pinned.
const (
	migration534ID      = "534_platform_admin_period_reset_identity_review"
	migration534UpSHA   = "ab837e36214ae42554bdea18dfa50379c64d9de308fa83914e51645e3b79e4c0"
	migration534DownSHA = "f68aa663825934ce5f9c2db599a7f586d663fdc4f27b0f01c8d70f85c40b645d"
)

func TestPlatformAdminPeriodResetIdentityReview534Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration534ID + ".up.sql", migration534UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 533", "(SELECT max(version) FROM schema_migrations) <> 533",
			"migration_id='533_cname_without_package'", "checksum_sha256='" + migration533UpSHA + "'",
			"down_checksum_sha256='" + migration533DownSHA + "'", "ERRCODE='P5340'",
			"ADD COLUMN actor_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT",
			"DROP CONSTRAINT package_period_reset_workload_tenant_scope_id_actor_user_i_fkey",
			"control_platform_admin_435(NEW.actor_user_id, NEW.actor_scope_id)",
			"NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id",
			"$3 IN ('identity_verification.read', 'identity_verification.review')",
			"AND control_platform_admin_435($2, NULL)",
			"FOREIGN KEY (reviewer_user_id) REFERENCES users(id) ON DELETE RESTRICT",
			"FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT",
		}},
		{migration534ID + ".down.sql", migration534DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 534", "migration_id='" + migration534ID + "'",
			"ERRCODE='P5341'", "ERRCODE='P5342'", "DROP COLUMN actor_scope_id",
			"FOREIGN KEY (tenant_scope_id, reviewer_user_id) REFERENCES memberships(scope_id, user_id)",
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
