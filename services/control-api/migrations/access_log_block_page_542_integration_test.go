//go:build integration

package migrations_test

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

// TestAccessLogBlockPage542: the catalog accepts block_page in catalog order
// (after x_real_ip, before ja4); down is refused while a revision records
// block_page and restores 540's catalog.
func TestAccessLogBlockPage542(t *testing.T) {
	const version = 542
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	check := func(value string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_v2_access_log_fields_is_valid($1::jsonb)`, value).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if check(`{"fields": ["block_page"]}`) {
		t.Fatal("541 accepts block_page")
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	for _, valid := range []string{`{"fields": ["block_page"]}`, `{"fields": ["x_real_ip", "block_page", "ja4"]}`, `{"fields": []}`} {
		if !check(valid) {
			t.Errorf("%s refused", valid)
		}
	}
	if check(`{"fields": ["ja4", "block_page"]}`) {
		t.Error("out of order accepted")
	}

	configuration := systemconfig.ProjectBootstrapConfiguration()
	configuration.AccessLogFields = &edgeconfig.AccessLogFields{Fields: edgeconfig.DefaultAccessLogFields}
	_, snapshot, _, err := systemconfig.CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := pool.QueryRow(ctx, `SELECT system_configuration_snapshot_is_valid($1)`, snapshot).Scan(&ok); err != nil || !ok {
		t.Fatalf("default selection snapshot refused (%v): %s", err, snapshot)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatal(err)
	}
	if check(`{"fields": ["block_page"]}`) {
		t.Fatal("541 accepts block_page after down")
	}
}
