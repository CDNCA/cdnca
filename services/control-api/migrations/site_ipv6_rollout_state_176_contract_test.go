package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSITE03176IPv6RolloutStateContract(t *testing.T) {
	up, err := FS.ReadFile("176_site_ipv6_rollout_state.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("176_site_ipv6_rollout_state.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorUp, err := FS.ReadFile("175_identity_verification_issuer_authority.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	predecessorDown, err := FS.ReadFile("175_identity_verification_issuer_authority.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("migration 176 requires the exact verified 175 release head"),
		[]byte("55dd21f5024894066f3bc20ff100229027e0051e3f33fadf64503c28b9305448"),
		[]byte("7158ccd1514407955e479b71ca3c59015294bfae705e5250c0c00d5d8d541799"),
		[]byte("site_ipv6_rollout_targets"), []byte("ipv6_enabled"), []byte("ipv6_runtime_state"),
		[]byte("ipv6_runtime_source_revision"), []byte("address_family"), []byte("append-only"),
	} {
		if !bytes.Contains(up, required) {
			t.Errorf("176 up migration missing %q", required)
		}
	}
	if guard, mutation := bytes.Index(up, []byte("migration 176 requires the exact verified 175 release head")),
		bytes.Index(up, []byte("ALTER TABLE config_versions")); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("176 predecessor guard must precede schema mutation")
	}
	upSHA := sha256.Sum256(up)
	for _, required := range [][]byte{
		[]byte("migration 176 rollback requires the exact verified 176 head"),
		[]byte(hex.EncodeToString(upSHA[:])),
		[]byte("migration 176 rollback would discard non-default IPv6 desired or runtime facts"),
		[]byte("DROP TABLE site_ipv6_rollout_targets"),
		[]byte("DROP COLUMN ipv6_runtime_source_revision"),
	} {
		if !bytes.Contains(down, required) {
			t.Errorf("176 down migration missing %q", required)
		}
	}
	if bytes.Contains(up, []byte("__UP_SHA256__")) || bytes.Contains(down, []byte("__UP_SHA256__")) ||
		bytes.Contains(up, []byte("DELETE FROM schema_migrations")) || bytes.Contains(down, []byte("DELETE FROM schema_migrations")) {
		t.Fatal("176 migration contains an unresolved hash or ledger deletion")
	}
	if !bytes.Contains(predecessorUp, []byte("migration 175")) || len(predecessorDown) == 0 {
		t.Fatal("175 predecessor files are unavailable")
	}
}
