package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 613: a soft-deleted site's
// binding no longer references its certificate. certificate_asset_bound_551
// excludes deleted sites and protect_certificate_asset calls it.
const (
	migration613ID      = "613_certificate_binding_deleted_site"
	migration612UpSHA   = "88d0d565e361e4613bf5a53230c3823ff4e2ff3c5fc55a2e33db0f2cea326920"
	migration612DownSHA = "890d4dedf565629e9e0ed512a18f997fa387cd90c0cd85aa31ca186b2bf6c94d"
)

func TestCertificateBindingDeletedSite613Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read(migration612ID+".up.sql")))); got != migration612UpSHA {
		t.Fatalf("612 up checksum drift: %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read(migration612ID+".down.sql")))); got != migration612DownSHA {
		t.Fatalf("612 down checksum drift: %s", got)
	}
	up, down := read(migration613ID+".up.sql"), read(migration613ID+".down.sql")
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 612", "migration_id='612_certificate_unpublish_noop'",
		"checksum_sha256='" + migration612UpSHA + "'", "down_checksum_sha256='" + migration612DownSHA + "'",
		"ERRCODE='P6130'", "CREATE OR REPLACE FUNCTION certificate_asset_bound_551",
		"site.deleted_at IS NOT NULL", "CREATE OR REPLACE FUNCTION protect_certificate_asset()",
		"NEW.deleted_at IS NOT NULL AND certificate_asset_bound_551(OLD.tenant_scope_id, OLD.id)",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("613 up missing %q", required)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 613", "migration_id='" + migration613ID + "'", "ERRCODE='P6131'",
		"CREATE OR REPLACE FUNCTION certificate_asset_bound_551", "CREATE OR REPLACE FUNCTION protect_certificate_asset()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("613 down missing %q", required)
		}
	}
	if strings.Contains(down, "deleted_at IS NOT NULL\n          )") {
		t.Error("613 down must restore the 551 rule without the deleted-site exclusion")
	}
}
