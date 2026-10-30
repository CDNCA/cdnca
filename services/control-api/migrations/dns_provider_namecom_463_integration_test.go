//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestDNSProviderNameCom463: before the migration a name.com provider row is
// refused by the closed provider_type CHECK; after up it is stored (with the
// usual encrypted credential columns) and unknown types stay refused; down
// refuses while a name.com provider exists, and succeeds once it is gone.
// The version is the head of the embedded set (463 placeholder; renumbered
// locally to run on the integration head).
func TestDNSProviderNameCom463(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_dns_provider_namecom.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("name.com migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'namecom 463')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'namecom 463','unused')`, userID, "namecom-463-"+userID.String()[:8])
	insert := func(providerType string) (uuid.UUID, error) {
		id := uuid.New()
		_, err := pool.Exec(ctx, `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,
			status,created_by_user_id,updated_by_user_id) VALUES($1,$2,$3,$4,'namecom-key',$5,'unverified',$6,$6)`,
			id, scopeID, "provider-"+id.String()[:8], providerType, append(make([]byte, 29), 1), userID)
		return id, err
	}
	if _, err := insert("namecom"); sqlState(err) != "23514" {
		t.Fatalf("namecom before %d: %v, want 23514", version, err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	providerID, err := insert("namecom")
	if err != nil {
		t.Fatalf("namecom after %d: %v", version, err)
	}
	var stored string
	if err := pool.QueryRow(ctx, `SELECT provider_type FROM dns_providers WHERE id=$1`, providerID).Scan(&stored); err != nil ||
		stored != "namecom" {
		t.Fatalf("stored provider_type = %q (%v)", stored, err)
	}
	for _, kept := range []string{"dns_la", "plugin", "custom_http"} {
		if _, err := insert(kept); err != nil {
			t.Fatalf("%s after %d: %v", kept, version, err)
		}
	}
	if _, err := insert("name_com"); sqlState(err) != "23514" {
		t.Fatalf("unknown type after %d: %v, want 23514", version, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4632" {
		t.Fatalf("down with a name.com provider: %v, want P4632", err)
	}
	mustExec(t, pool, `DELETE FROM dns_providers WHERE id=$1`, providerID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down without name.com providers: %v", err)
	}
	if _, err := insert("namecom"); sqlState(err) != "23514" {
		t.Fatalf("namecom after down: %v, want 23514", err)
	}
}
