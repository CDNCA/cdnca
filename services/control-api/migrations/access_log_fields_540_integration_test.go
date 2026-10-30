//go:build integration

package migrations_test

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

// TestAccessLogFields540: the snapshot check accepts the access_log_fields
// category in the form the control plane writes (today's whole snapshot) and
// refuses malformed ones; down is refused while a revision carries it.
func TestAccessLogFields540(t *testing.T) {
	const version = 540
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	check := func(value string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_v2_access_log_fields_is_valid($1::jsonb)`, value).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for _, valid := range []string{`{"fields": []}`, `{"fields": ["client_family", "referer", "ja4"]}`} {
		if !check(valid) {
			t.Errorf("%s refused", valid)
		}
	}
	for name, value := range map[string]string{
		"basic field":  `{"fields": ["host"]}`,
		"out of order": `{"fields": ["ja4", "referer"]}`,
		"duplicate":    `{"fields": ["referer", "referer"]}`,
		"non-string":   `{"fields": [1]}`,
		"not an array": `{"fields": "referer"}`,
		"missing":      `{}`,
		"extra key":    `{"fields": [], "x": 1}`,
	} {
		if check(value) {
			t.Errorf("%s accepted", name)
		}
	}

	configuration := systemconfig.ProjectBootstrapConfiguration()
	configuration.AccessLogFields = &edgeconfig.AccessLogFields{Fields: []string{"upstream_addr", "referer", "user_agent"}}
	_, snapshot, _, err := systemconfig.CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	snapshotValid := func() bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_snapshot_is_valid($1)`, snapshot).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !snapshotValid() {
		t.Fatalf("control plane snapshot refused: %s", snapshot)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatal(err)
	}
	if snapshotValid() {
		t.Fatal("539 accepts the access_log_fields category")
	}
}
