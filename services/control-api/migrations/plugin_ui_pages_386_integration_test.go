//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestPluginUIPages386: market data pack sources accept plugin_ui, a plugin
// page row must be an https origin with a matching declaration, two active
// rows cannot share an origin; down refuses while a plugin_ui source exists.
func TestPluginUIPages386(t *testing.T) {
	const version = 386
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	page := func(pluginID, origin, status string) error {
		_, err := pool.Exec(ctx, `INSERT INTO plugin_ui_pages(plugin_id,version,origin,api_base_url,declaration,declaration_sha256,
			status,tenant_scope_id,authorization_id,materialized_at,updated_at)
			VALUES($1,'1.0.0',$2,'',jsonb_build_object('plugin_id',$1::text,'origin',$2::text),repeat('a',64),$3,$4,$5,now(),now())`,
			pluginID, origin, status, uuid.New(), uuid.New())
		return err
	}
	for _, bad := range [][2]string{{"io.x.a", "http://ui.x.example"}, {"io.x.b", "https://ui.x.example:8443"},
		{"io.x.c", "https://10.0.0.1"}, {"io.x.d", "https://ui.x.example/path"}} {
		if err := page(bad[0], bad[1], "active"); sqlState(err) != "23514" {
			t.Fatalf("page %s %s: %v, want 23514", bad[0], bad[1], err)
		}
	}
	if err := page("io.x.one", "https://ui.x.example", "active"); err != nil {
		t.Fatal(err)
	}
	if err := page("io.x.two", "https://ui.x.example", "active"); sqlState(err) != "23505" {
		t.Fatalf("second active page on one origin: %v, want 23505", err)
	}
	if err := page("io.x.three", "https://ui.x.example", "withdrawn"); err != nil {
		t.Fatalf("withdrawn page sharing an origin: %v", err)
	}
	mustExec(t, pool, `INSERT INTO market_data_pack_sources(artifact_id,kind,plugin_id,version,revision,sha256,local_name,status,
		materialized_at,updated_at) VALUES('plugin_ui/io.x.one','plugin_ui','io.x.one','1.0.0',1,repeat('b',64),'io.x.one','active',now(),now())`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3862" {
		t.Fatalf("down with a plugin_ui source: %v, want P3862", err)
	}
}
