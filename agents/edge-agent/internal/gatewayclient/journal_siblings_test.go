package gatewayclient

import (
	"os"
	"path/filepath"
	"testing"
)

// The daemon keeps other state in the journal root next to the deployment records:
// gateway-endpoints.json (learned GatewayHello endpoints, endpoint_failover.go) is written
// on first contact. A fresh node had exactly that file and every session failed with
// "unexpected gateway journal file" before the first deployment (85/78, 10-22).
func TestDurableStoreIgnoresDaemonStateFilesInJournalRoot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newDurableStore(root, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "gateway-endpoints.json"), []byte(`{"version":"x","endpoints":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	records, err := store.records()
	if err != nil {
		t.Fatalf("records with gateway-endpoints.json in the journal root: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %d, want 0", len(records))
	}
	if err := store.scanDeploymentRecordsLocked(func(*durableRecord) error { return nil }); err != nil {
		t.Fatalf("scan with gateway-endpoints.json in the journal root: %v", err)
	}
}
