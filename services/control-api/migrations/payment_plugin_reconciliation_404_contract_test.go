package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 404 (daily payment plugin reconciliation and
// payment alerts in the notification center) is a placeholder number
// (BATCH-PLUGIN 第 16 条, reserved 410): the merge renumbers it. Everything
// that changes with the renumbering is here.
const (
	migration404Version         = 404
	migration404ID              = "404_payment_plugin_reconciliation"
	migration404PreviousVersion = 403
	migration404PreviousID      = "403_autodefense_store"
	migration404PreviousUpSHA   = "6cb9d7920a2c62b80d46757bf7405048634dff6aecd73a29f4c6b9f083267ff4"
	migration404PreviousDownSHA = "2cd498c92848d8b174315148fd867686e27da3b01f6512c1e8285bb0166d26ed"
	migration404UpSHA           = "83d1db6e59f5da39d7bb99692fb1b144a7566d1b61c351c9024d07e5617d075c"
	migration404DownSHA         = "d3a99945f04d709752864554794211e6ab7e6527154c12d4caf503713391e2f2"
)

func TestPaymentPluginReconciliation404Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration404ID + ".up.sql", migration404UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration404PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration404PreviousVersion),
			"migration_id='" + migration404PreviousID + "'", migration404PreviousUpSHA, migration404PreviousDownSHA,
			"ERRCODE='P4040'", "CREATE TABLE payment_reconcile_runs", "CREATE TABLE payment_reconcile_mismatches",
			"'payment.reconcile.mismatch.zh-cn'", "'payment.plugin.alert.zh-cn'",
		}},
		{migration404ID + ".down.sql", migration404DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration404Version),
			"migration_id='" + migration404ID + "'", "ERRCODE='P4041'", "ERRCODE='P4042'",
			"DROP TABLE payment_reconcile_runs",
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
}
