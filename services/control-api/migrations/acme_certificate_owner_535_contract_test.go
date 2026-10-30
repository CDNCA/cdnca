package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 535 (fix-certowner): ACME certificate owner rule and backfill.
// The 534 predecessor is pinned at merge.
const (
	migration535ID      = "535_acme_certificate_owner"
	migration535UpSHA   = "cc8f28bdaf66a5ef2e24f24448980e478e0929a72f4859d59d5b8eee24946cae"
	migration535DownSHA = "9572b9c6e0aae771a66245b4d2ca7bb62b30294d7a050b36647a30eca1cf849b"
)

func TestACMECertificateOwner535Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration535ID + ".up.sql", migration535UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 534", "ERRCODE='P5350'",
			"CREATE FUNCTION resolve_certificate_order_owner_535(p_scope_id uuid, p_order_id uuid)",
			"ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_owner_immutable_276;",
			"ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_owner_immutable_276;",
			"ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_protect;",
			"ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_actor_target_085;",
			"asset.source = 'acme' AND asset.owner_user_id IS NULL AND asset.deleted_at IS NULL",
		}},
		{migration535ID + ".down.sql", migration535DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 535", "migration_id='" + migration535ID + "'",
			"ERRCODE='P5351'", "DROP FUNCTION resolve_certificate_order_owner_535(uuid, uuid);",
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
