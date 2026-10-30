//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

// TestGECache396: up, down, up; the snapshot check takes the control plane's
// cache settings (proxy_cache_min_free_bytes, no proxy_cache_dir) only after
// up; the new columns exist with their defaults and bounds.
func TestGECache396(t *testing.T) {
	const version = 396
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	_, snapshot, _, err := systemconfig.CanonicalSnapshot(systemconfig.ProjectBootstrapConfiguration())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapshot), `"proxy_cache_min_free_bytes": `) || strings.Contains(string(snapshot), "proxy_cache_dir") {
		t.Fatalf("control plane snapshot cache settings: %s", snapshot)
	}
	valid := func(candidate []byte) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_snapshot_is_valid($1)`, candidate).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !valid(snapshot) {
		t.Fatalf("control plane snapshot refused: %s", snapshot)
	}
	unaligned := []byte(strings.Replace(string(snapshot), `"proxy_cache_min_free_bytes": 5368709120`,
		`"proxy_cache_min_free_bytes": 5368709121`, 1))
	if string(unaligned) == string(snapshot) || valid(unaligned) {
		t.Fatal("a min_free that is not whole MiB was accepted")
	}
	var extensionsDefault string
	if err := pool.QueryRow(ctx, `SELECT column_default FROM information_schema.columns
		WHERE table_name='cache_policy_revisions' AND column_name='extensions'`).Scan(&extensionsDefault); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(extensionsDefault, "'{}'") {
		t.Fatalf("defaults extensions=%s", extensionsDefault)
	}
	var rejectsUnknown bool
	if err := pool.QueryRow(ctx, `SELECT NOT ('{"x":1}'::jsonb - ARRAY['stale_if_error','background_update',
		'min_object_bytes','max_object_bytes','slice_bytes'] = '{}'::jsonb)`).Scan(&rejectsUnknown); err != nil || !rejectsUnknown {
		t.Fatalf("extension key check: %v %v", rejectsUnknown, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatal(err)
	}
	if valid(snapshot) {
		t.Fatal("395 accepts proxy_cache_min_free_bytes")
	}
}
