//go:build integration

package migrations_test

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

// TestDDoSTCPFlags395: the category check accepts the TCP flag filter and
// drop_invalid in the form the control plane writes and refuses malformed
// ones; a 377 value (no new keys) stays valid; down is refused while a
// revision carries a new key; up, down, up.
func TestDDoSTCPFlags395(t *testing.T) {
	const version = 395
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	const base = `{"cc_kernel_ban": "off", "allow_networks": [], "rate_ban_seconds": 0, "max_connections_per_ip": 0, ` +
		`"max_connections_per_port": 0, "new_connections_per_minute": 0, "new_connections_per_second": 0}`
	check := func(patch string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_v2_ddos_protection_is_valid($1::jsonb || $2::jsonb)`,
			base, patch).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	for name, patch := range map[string]string{
		"377 value":      `{}`,
		"defaults":       `{"tcp_flag_filter": true, "tcp_flag_types": ["null", "xmas", "syn_fin", "syn_rst"], "drop_invalid": true}`,
		"every type":     `{"tcp_flag_filter": true, "tcp_flag_types": ["null", "xmas", "syn_fin", "syn_rst", "fin", "all"]}`,
		"types kept off": `{"tcp_flag_types": ["fin"]}`,
		"invalid only":   `{"drop_invalid": true}`,
	} {
		if !check(patch) {
			t.Errorf("%s refused", name)
		}
	}
	for name, patch := range map[string]string{
		"switch no types": `{"tcp_flag_filter": true}`,
		"false switch":    `{"tcp_flag_filter": false, "tcp_flag_types": ["null"]}`,
		"false invalid":   `{"drop_invalid": false}`,
		"string switch":   `{"drop_invalid": "true"}`,
		"empty types":     `{"tcp_flag_types": []}`,
		"unknown type":    `{"tcp_flag_types": ["ack"]}`,
		"duplicate type":  `{"tcp_flag_types": ["null", "null"]}`,
		"out of order":    `{"tcp_flag_types": ["xmas", "null"]}`,
		"non-string type": `{"tcp_flag_types": [1]}`,
	} {
		if check(patch) {
			t.Errorf("%s accepted", name)
		}
	}

	configuration := systemconfig.ProjectBootstrapConfiguration()
	value := edgeconfig.DefaultDDoSProtection()
	value.TCPFlagTypes = []string{"all", "fin", "null"}
	configuration.DDoSProtection = &value
	_, snapshot, _, err := systemconfig.CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	// The control plane writes 396's cache settings (ge-cache); at 395 the
	// nginx http block still has proxy_cache_dir and no min_free.
	if err := pool.QueryRow(ctx, `SELECT system_configuration_render_canonical_snapshot(jsonb_set(
		convert_from($1,'UTF8')::jsonb #- '{configuration,nginx,http,proxy_cache_min_free_bytes}',
		'{configuration,nginx,http,proxy_cache_dir}', '"/var/lib/cdnca/cache"'))`, snapshot).Scan(&snapshot); err != nil {
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
		t.Fatal("394 accepts the TCP flag filter")
	}
}
