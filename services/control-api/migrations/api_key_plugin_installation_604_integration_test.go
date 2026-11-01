//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

// TestAPIKeyPluginInstallation604 (plugapi-S2): an API
// key binds only an enabled installation of its own tenant with matching
// installation_id / plugin_id, the binding is immutable, and the down
// migration refuses while a bound key exists.
func TestAPIKeyPluginInstallation604(t *testing.T) {
	// Keep equal to the 604 contract's version.
	const version = 604
	pool := migrationPoolAt(t, version)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	otherTenant, otherScope := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'604 tenant'),($2,'604 other')`, tenantID, otherTenant)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`,
		scopeID, tenantID, otherScope, otherTenant)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'apikey-604','API key 604','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	digest := sha256.Sum256([]byte("604"))
	head := func(scope, authorization, installation uuid.UUID, status string) {
		t.Helper()
		mustExec(t, pool, `INSERT INTO plugin_installation_heads(
			tenant_scope_id,authorization_id,installation_id,verification_id,plugin_id,plugin_version,manifest_sha256,
			configuration_schema_sha256,manifest_scopes,approved_scopes,sensitive_scopes,status,revision,
			identity_generation,created_at,updated_at,entrypoint_type
		) VALUES($1,$2,$3,$4,'io.cdnca.cf-optimize','1.0.0',$5,$5,ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::text[],
			$6,1,1,clock_timestamp(),clock_timestamp(),'external_https')`,
			scope, authorization, installation, uuid.New(), digest[:], status)
	}
	enabled, enabledInstallation := uuid.New(), uuid.New()
	disabled, foreign := uuid.New(), uuid.New()
	head(scopeID, enabled, enabledInstallation, "enabled")
	head(scopeID, disabled, uuid.New(), "disabled")
	head(otherScope, foreign, uuid.New(), "enabled")

	insertKey := func(authorization, installation *uuid.UUID, plugin *string) (uuid.UUID, error) {
		id := uuid.New()
		keyID := "cfk_" + uuid.NewString()[:22]
		_, err := pool.Exec(ctx, `INSERT INTO api_keys(
			id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,ip_allowlist,secret_digest,pepper_version,status,
			activated_at,created_by_user_id,created_at,updated_at,
			plugin_installation_authorization_id,plugin_installation_id,plugin_id
		) VALUES($1,$2,$2||'.',$3,$4,$5,'604 key',ARRAY['sites.read'],ARRAY[]::text[],$6,'v1','active',
			now(),$5,now(),now(),$7,$8,$9)`,
			id, keyID, scopeID, tenantID, userID, digest[:], authorization, installation, plugin)
		return id, err
	}
	plugin := "io.cdnca.cf-optimize"
	wrongPlugin := "io.cdnca.other"
	randomInstallation := uuid.New()
	for name, tc := range map[string]struct {
		authorization, installation *uuid.UUID
		plugin                      *string
		state                       string
	}{
		// The BEFORE trigger runs ahead of the shape CHECK and the foreign key.
		"partial binding":       {&enabled, nil, &plugin, "P6042"},
		"disabled installation": {&disabled, &enabledInstallation, &plugin, "P6042"},
		"other tenant":          {&foreign, &enabledInstallation, &plugin, "P6042"},
		"installation mismatch": {&enabled, &randomInstallation, &plugin, "P6042"},
		"plugin mismatch":       {&enabled, &enabledInstallation, &wrongPlugin, "P6042"},
	} {
		if _, err := insertKey(tc.authorization, tc.installation, tc.plugin); sqlState(err) != tc.state {
			t.Errorf("%s: %v, want %s", name, err, tc.state)
		}
	}
	if _, err := insertKey(nil, nil, nil); err != nil {
		t.Fatalf("unbound key: %v", err)
	}
	bound, err := insertKey(&enabled, &enabledInstallation, &plugin)
	if err != nil {
		t.Fatalf("bound key: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE api_keys SET plugin_installation_authorization_id=NULL,
		plugin_installation_id=NULL, plugin_id=NULL, name='renamed', revision=revision+1, updated_at=clock_timestamp()
		WHERE id=$1`, bound); sqlState(err) != "P6041" {
		t.Fatalf("unbind: %v, want P6041", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P6044" {
		t.Fatalf("down with bound key: %v, want P6044", err)
	}
}
