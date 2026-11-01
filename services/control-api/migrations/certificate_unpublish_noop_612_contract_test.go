package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 612: an unpublication of a certificate
// that never reached a node completes succeeded without a rollout
// (noop_reason never_published). The 611 predecessor is pinned by checksum;
// down restores 120's result shape and refuses while no-op facts exist.
const (
	migration612ID      = "612_certificate_unpublish_noop"
	migration611UpSHA   = "a92b1455fa9bc83ebe61b2a4ea88a146f71572e5a8e7e2c5c6cb71a1d04c72b7"
	migration611DownSHA = "a694197b3e44a487313de8444bd4047e85efca3c6835bc1188e67fc9b548e56d"
)

func TestCertificateUnpublishNoop612Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read(migration611ID+".up.sql")))); got != migration611UpSHA {
		t.Fatalf("611 up checksum drift: %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(read(migration611ID+".down.sql")))); got != migration611DownSHA {
		t.Fatalf("611 down checksum drift: %s", got)
	}
	up, down := read(migration612ID+".up.sql"), read(migration612ID+".down.sql")
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 611", "(SELECT max(version) FROM schema_migrations) <> 611",
		"migration_id='611_operator_user_foreign_keys'", "checksum_sha256='" + migration611UpSHA + "'",
		"down_checksum_sha256='" + migration611DownSHA + "'", "ERRCODE='P6120'", "ERRCODE='P6123'",
		"noop_reason IS NULL OR noop_reason='never_published'",
		"DROP CONSTRAINT certificate_publication_result_shape_120_check",
		"ADD CONSTRAINT certificate_publication_result_shape_612_check",
		"intent.operation='unpublish'",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("612 up missing %q", required)
		}
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 612", "migration_id='" + migration612ID + "'",
		"ERRCODE='P6121'", "ERRCODE='P6122'", "WHERE noop_reason IS NOT NULL",
		"DROP CONSTRAINT certificate_publication_result_shape_612_check",
		"ADD CONSTRAINT certificate_publication_result_shape_120_check", "DROP COLUMN noop_reason",
		"DROP FUNCTION validate_certificate_publication_noop_612()",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("612 down missing %q", required)
		}
	}
}
