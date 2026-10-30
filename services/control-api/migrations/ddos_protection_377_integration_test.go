//go:build integration

package migrations_test

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
)

// TestDDoSProtection377: the snapshot check accepts the ddos_protection
// category in the form the control plane writes and refuses malformed ones;
// down is refused while a revision carries the category; up, down, up.
func TestDDoSProtection377(t *testing.T) {
	const version = 377
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	const valid = `{"cc_kernel_ban": "off", "allow_networks": ["192.0.2.0/24", "2001:db8::5/128"], "rate_ban_seconds": 600, ` +
		`"empty_connection": {"threshold": 20, "ban_seconds": 1800, "idle_seconds": 10, "window_seconds": 60}, ` +
		`"max_connections_per_ip": 300, "max_connections_per_port": 0, "new_connections_per_minute": 0, "new_connections_per_second": 80}`
	check := func(patch string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT system_configuration_v2_ddos_protection_is_valid($1::jsonb || $2::jsonb)`,
			valid, patch).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !check(`{}`) {
		t.Fatal("canonical ddos_protection refused")
	}
	for name, patch := range map[string]string{
		"host bits":       `{"allow_networks": ["192.0.2.1/24"]}`,
		"non-string cidr": `{"allow_networks": [1]}`,
		"unknown mode":    `{"cc_kernel_ban": "global"}`,
		"ban no rate":     `{"new_connections_per_second": 0}`,
		"negative":        `{"max_connections_per_ip": -1}`,
		"fraction":        `{"max_connections_per_ip": 1.5}`,
		"short idle":      `{"empty_connection": {"threshold": 20, "ban_seconds": 1800, "idle_seconds": 1, "window_seconds": 60}}`,
		"empty extra key": `{"empty_connection": {"threshold": 20, "ban_seconds": 1800, "idle_seconds": 10, "window_seconds": 60, "x": 1}}`,
		"extra key":       `{"extra": 1}`,
	} {
		if check(patch) {
			t.Errorf("%s accepted", name)
		}
	}

	// The whole snapshot the control plane writes verifies; after down the
	// category is unknown again.
	configuration := systemconfig.ProjectBootstrapConfiguration()
	configuration.DDoSProtection = &edgeconfig.DDoSProtection{MaxConnectionsPerIP: 300, NewConnectionsPerSecond: 80,
		RateBanSeconds: 600, AllowNetworks: []string{"2001:db8::5", "192.0.2.0/24"}, CCKernelBan: edgeconfig.CCKernelBanSitePorts,
		EmptyConnection: &edgeconfig.DDoSEmptyConnection{IdleSeconds: 10, Threshold: 20, WindowSeconds: 60, BanSeconds: 1800}}
	_, snapshot, _, err := systemconfig.CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	// The control plane writes 387's cache settings (ge-cache); at 377 the
	// nginx http block still has proxy_cache_dir and no min_free.
	if err := pool.QueryRow(ctx, `SELECT convert_to(jsonb_set(
		convert_from($1,'UTF8')::jsonb #- '{configuration,nginx,http,proxy_cache_min_free_bytes}',
		'{configuration,nginx,http,proxy_cache_dir}', '"/var/lib/cdnca/cache"')::text,'UTF8')`, snapshot).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	snapshotValid := func() bool {
		t.Helper()
		var ok bool
		// Today's control plane writes the post-391 shape; 391 dropped four
		// defaults.website.other switches that 377's check still requires, so
		// they are added back and the document re-rendered canonically.
		if err := pool.QueryRow(ctx, `SELECT system_configuration_snapshot_is_valid(
			system_configuration_render_canonical_snapshot(jsonb_set($1::jsonb, '{configuration,defaults,website,other}',
				($1::jsonb #> '{configuration,defaults,website,other}') || '{"crawler_policy": "default",
				"realtime_send_enabled": false, "block_transparent_proxy": false, "realtime_response_enabled": false}'::jsonb)))`,
			string(snapshot)).Scan(&ok); err != nil {
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
		t.Fatal("376 accepts the ddos_protection category")
	}
}
