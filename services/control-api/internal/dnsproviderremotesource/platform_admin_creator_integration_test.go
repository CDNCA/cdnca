//go:build integration

package dnsproviderremotesource

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-adminall: a DNS provider created for a tenant by a platform
// administrator (not a tenant member) resolves like a member's; one whose
// creator is neither a member nor a platform admin is still refused.
func TestProviderCreatedByPlatformAdminResolves(t *testing.T) {
	pool := openSourcePG17(t)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	tenant := seedSourceTenant(t, pool, "adminall-dns")
	cipher := mustSourceCipher(t, "adminall-dns-key", 52)
	admin := seedPlatformUser(t, pool, "platform.admin")
	viewer := seedPlatformUser(t, pool, "sites.read")
	lister := &recordingLister{}
	snapshot, err := NewOwnerSnapshot(New(pool, cipher), lister)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		creator uuid.UUID
		zone    string
		allowed bool
	}{
		{"tenant member", tenant.userID, "member.test", true},
		{"platform admin", admin, "admin.test", true},
		{"platform member without platform.admin", viewer, "viewer.test", false},
	} {
		creatorTenant := tenant
		creatorTenant.userID = c.creator
		providerID := insertSourceProvider(t, pool, creatorTenant, "cloudflare", "verified", cipher, `{"api_token":"t"}`)
		keyID, ciphertext, err := cipher.EncryptCredential(dnsacme.CredentialBinding{TenantID: tenant.tenantID,
			ScopeID: tenant.scopeID, ProviderID: providerID}, []byte(`{"api_token":"t"}`))
		if err != nil {
			t.Fatal(err)
		}
		setSourceCredentials(t, pool, providerID, keyID, ciphertext)
		zoneID := insertSourceZone(t, pool, creatorTenant, providerID, c.zone)
		siteID := insertSourceReconcileSite(t, pool, tenant, "www."+c.zone)
		_, err = snapshot.OwnerRecords(t.Context(), tenant.tenantID, siteID, zoneID, "edge."+c.zone)
		if c.allowed && err != nil {
			t.Fatalf("%s: OwnerRecords() = %v, want resolved", c.name, err)
		}
		if !c.allowed && err == nil {
			t.Fatalf("%s: OwnerRecords() resolved, want refused", c.name)
		}
	}
}

func seedPlatformUser(t *testing.T, pool *pgxpool.Pool, permission string) uuid.UUID {
	t.Helper()
	ctx := t.Context()
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
			t.Fatal(err)
		}
	}
	userID, roleID := uuid.New(), uuid.New()
	suffix := strings.ReplaceAll(userID.String(), "-", "")[:12]
	for _, s := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'platform','x')`, []any{userID, "pa" + suffix}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'adminall',true)`, []any{roleID, platformScope, "pa_" + suffix}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, []any{roleID, permission}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{platformScope, userID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{platformScope, userID, roleID}},
	} {
		if _, err := pool.Exec(ctx, s.q, s.args...); err != nil {
			t.Fatal(err)
		}
	}
	return userID
}
