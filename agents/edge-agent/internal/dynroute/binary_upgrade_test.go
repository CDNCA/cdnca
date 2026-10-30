package dynroute

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// No live master (no pid file, or a pid that is gone): nothing to upgrade
// and the new binary is used by the next start. The real signal sequence is
// covered by scripts/native-runtime-upgrade-acceptance.sh.
func TestUpgradeMasterWithoutLiveMasterIsNoop(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "nginx.pid")
	serves := func(context.Context, int) error {
		t.Fatal("serves called without a master")
		return nil
	}
	if err := UpgradeMaster(context.Background(), pidFile, serves); err != nil {
		t.Fatalf("missing pid file: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte("999999999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpgradeMaster(context.Background(), pidFile, serves); err != nil {
		t.Fatalf("stale pid: %v", err)
	}
}
