//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestDNSProviderClouDNSNamecheapJDCloud632: before the migration the three
// provider types are refused by the closed provider_type CHECK; after up they
// are stored and unknown types stay refused; down refuses while any of them
// exists, and succeeds once they are gone. The version is read from the
// embedded file name; 631's types (dnspod_com, godaddy, namesilo) stay
// accepted on both sides of 632.
func TestDNSProviderClouDNSNamecheapJDCloud632(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_dns_provider_cloudns_namecheap_jdcloud.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'more dns 632')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'more dns 632','unused')`, userID, "more-dns-632-"+userID.String()[:8])
	insert := func(providerType string) (uuid.UUID, error) {
		id := uuid.New()
		_, err := pool.Exec(ctx, `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,
			status,created_by_user_id,updated_by_user_id) VALUES($1,$2,$3,$4,'more-dns-key',$5,'unverified',$6,$6)`,
			id, scopeID, "provider-"+id.String()[:8], providerType, append(make([]byte, 29), 1), userID)
		return id, err
	}
	added := []string{"cloudns", "namecheap", "jdcloud"}
	for _, providerType := range added {
		if _, err := insert(providerType); sqlState(err) != "23514" {
			t.Fatalf("%s before %d: %v, want 23514", providerType, version, err)
		}
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	ids := make([]uuid.UUID, 0, len(added))
	for _, providerType := range added {
		id, err := insert(providerType)
		if err != nil {
			t.Fatalf("%s after %d: %v", providerType, version, err)
		}
		var stored string
		if err := pool.QueryRow(ctx, `SELECT provider_type FROM dns_providers WHERE id=$1`, id).Scan(&stored); err != nil ||
			stored != providerType {
			t.Fatalf("stored provider_type = %q (%v), want %s", stored, err, providerType)
		}
		ids = append(ids, id)
	}
	for _, kept := range []string{"namecom", "dns_la", "plugin", "custom_http", "dnspod_com", "godaddy", "namesilo"} {
		if _, err := insert(kept); err != nil {
			t.Fatalf("%s after %d: %v", kept, version, err)
		}
	}
	for _, unknown := range []string{"cloud_dns", "jd_cloud", "name_cheap"} {
		if _, err := insert(unknown); sqlState(err) != "23514" {
			t.Fatalf("%s after %d: %v, want 23514", unknown, version, err)
		}
	}
	for index, id := range ids {
		if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P"+strconv.FormatInt(version, 10)+"2" {
			t.Fatalf("down with %s in use: %v", added[index], err)
		}
		mustExec(t, pool, `DELETE FROM dns_providers WHERE id=$1`, id)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down without the providers: %v", err)
	}
	for _, providerType := range added {
		if _, err := insert(providerType); sqlState(err) != "23514" {
			t.Fatalf("%s after down: %v, want 23514", providerType, err)
		}
	}
	if _, err := insert("namesilo"); err != nil {
		t.Fatalf("namesilo after %d down: %v", version, err)
	}
}
