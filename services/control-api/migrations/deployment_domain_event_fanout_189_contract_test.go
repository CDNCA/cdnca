package migrations_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentDomainEventFanout189Contract(t *testing.T) {
	up := readFanout189Migration(t, "189_deployment_domain_event_fanout.up.sql")
	down := readFanout189Migration(t, "189_deployment_domain_event_fanout.down.sql")
	predecessorUp := readFanout189Migration(t, "188_plugin_webhook_installation_binding.up.sql")
	predecessorDown := readFanout189Migration(t, "188_plugin_webhook_installation_binding.down.sql")
	if got := sha256HexFanout189(predecessorUp); got != "d3dd872b493087fb38318949831c0997ad22615177447a6fed8cf5384d3323d2" {
		t.Fatalf("188 up changed: %s", got)
	}
	if got := sha256HexFanout189(predecessorDown); got != "8ef29275c68d9f2416397bdb5d3e028dbd0b900e515e1eb13813ff8245144ecd" {
		t.Fatalf("188 down changed: %s", got)
	}
	for _, marker := range []string{
		"migration 189 requires the exact verified 188 and 187 release heads",
		"deployment_domain_event_fanout_receipts",
		"PRIMARY KEY (source_id, subscription_id)",
		"status IN ('pending','published','failed')",
		"installation_authorization_id",
		"deployment fanout receipt terminal state is immutable",
		"deployment fanout receipt identity is immutable",
		"P1891",
		"P1892",
	} {
		if !strings.Contains(up, marker) {
			t.Errorf("189 up missing %q", marker)
		}
	}
	for _, marker := range []string{
		"migration 189 rollback requires the exact verified release heads",
		"rollback would discard deployment fanout receipts",
		"DROP TABLE deployment_domain_event_fanout_receipts",
		"P1894",
	} {
		if !strings.Contains(down, marker) {
			t.Errorf("189 down missing %q", marker)
		}
	}
	if strings.Contains(strings.ToUpper(down), "CASCADE") {
		t.Fatal("189 down must not use CASCADE")
	}
}

func readFanout189Migration(t *testing.T, name string) string {
	t.Helper()
	for _, root := range []string{".", "services/control-api/migrations"} {
		if body, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			return string(body)
		}
	}
	t.Fatalf("migration file %s not found", name)
	return ""
}

func sha256HexFanout189(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
