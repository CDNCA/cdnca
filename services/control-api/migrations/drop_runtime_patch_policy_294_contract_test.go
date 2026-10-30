package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestDropRuntimePatchPolicy294Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"294_drop_runtime_patch_policy.up.sql", "437c67e61f9d74a93e7f4c1523c685d029cd4882fa49e8dc965b5d842afda106", []string{
			"(SELECT count(*) FROM schema_migrations) <> 293", "293_l4_tls_passthrough",
			"e9cf0e5df8011f95991400d9f777b577b9c02916880cf2f46fb214926e7cdfd4", "156_runtime_patch_policy",
			"34cc982875f728e86af11479e9f49a5326a1fff85fe2d6b91efe4c0b84448788", "ERRCODE='P2940'",
			"DROP TABLE runtime_patch_policy_heads_156", "DROP TABLE runtime_patch_policy_receipts_156",
			"DROP TABLE runtime_patch_policy_candidates_156", "DROP FUNCTION commit_runtime_patch_policy_156(",
		}},
		{"294_drop_runtime_patch_policy.down.sql", "f87374d506b5f14723289d5b48d081bae8dfd6182504fa717f6e8c3b63482bf0", []string{
			"(SELECT count(*) FROM schema_migrations) <> 294", "294_drop_runtime_patch_policy", "ERRCODE='P2941'",
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
	// The down rebuilds 156 verbatim, minus its release-head guard.
	original, err := FS.ReadFile("156_runtime_patch_policy.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("294_drop_runtime_patch_policy.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(original), "END;\n$migration_156$;\n")
	if !ok || !strings.HasSuffix(string(down), "\n\n"+strings.TrimLeft(body, "\n")) {
		t.Fatal("294 down does not rebuild the 156 structures verbatim")
	}
}
