package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 403 (smart auto defense control-plane store)
// is a placeholder number (integration head 400 + 1; 408 on merge, BATCH
// 第 16 条). Everything that changes with the renumbering is here.
const (
	migration403Version         = 403
	migration403ID              = "403_autodefense_store"
	migration403PreviousVersion = 402
	migration403PreviousID      = "402_plugin_payment_providers"
	migration403PreviousUpSHA   = "c0f5589b6ee9ecb90569081d861f8450546078555079ad75dd91a4d5bb175689"
	migration403PreviousDownSHA = "bef0eae462a2fbc0a8f3141fe1da268a9072d8f019a5d7a9d67825276e78df12"
	migration403UpSHA           = "6cb9d7920a2c62b80d46757bf7405048634dff6aecd73a29f4c6b9f083267ff4"
	migration403DownSHA         = "2cd498c92848d8b174315148fd867686e27da3b01f6512c1e8285bb0166d26ed"
)

func TestAutoDefenseStore403Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration403ID + ".up.sql", migration403UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration403PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration403PreviousVersion),
			"migration_id='" + migration403PreviousID + "'", migration403PreviousUpSHA, migration403PreviousDownSHA,
			"ERRCODE='P4030'", "CREATE TABLE autodefense_sites", "CREATE TABLE autodefense_mitigations",
			"CREATE TABLE autodefense_report_receipts", "REFERENCES sites(scope_id, id) ON DELETE CASCADE",
		}},
		{migration403ID + ".down.sql", migration403DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration403Version),
			"migration_id='" + migration403ID + "'", "ERRCODE='P4031'", "ERRCODE='P4032'", "DROP TABLE autodefense_sites",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
	// Node autonomy: the control plane keeps no baseline.
	raw, _ := FS.ReadFile(migration403ID + ".up.sql")
	for _, forbidden := range []string{"CREATE TABLE autodefense_baseline", "baseline_snapshot", "CREATE TABLE autodefense_samples"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("up keeps control-plane learning data %q", forbidden)
		}
	}
}
