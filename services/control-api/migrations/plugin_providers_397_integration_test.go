//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// embeddedHeadVersion is the version of the plugin providers migration as
// embedded (the placeholder may be renumbered locally).
func embeddedHeadVersion(t *testing.T) int64 {
	t.Helper()
	matches, err := fs.Glob(controlmigrations.FS, "*_plugin_providers.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("plugin providers migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// TestPluginProviders397: a provider row needs an https DNS-host base URL
// and a matching declaration; enabling requires a passed contract for the
// current declaration bytes; down refuses while a provider source or a
// plugin DNS provider exists. The version is the head of the embedded set
// (397 placeholder, 394 under /tmp/pa22_swap.sh).
func TestPluginProviders397(t *testing.T) {
	version := embeddedHeadVersion(t)
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	insert := func(pluginID, baseURL string) error {
		_, err := pool.Exec(ctx, `INSERT INTO plugin_providers(plugin_id,version,base_url,kinds,declaration,declaration_sha256,
			status,tenant_scope_id,authorization_id,contract_status,materialized_at,updated_at)
			VALUES($1,'1.0.0',$2,'{dns}',jsonb_build_object('plugin_id',$1::text,'base_url',$2::text),repeat('a',64),'active',$3,$4,
			'pending',now(),now())`, pluginID, baseURL, uuid.New(), uuid.New())
		return err
	}
	for _, bad := range []string{"http://dns.x.example", "https://dns.x.example:8443", "https://10.0.0.1", "https://dns.x.example/?a"} {
		if err := insert("io.x.bad", bad); sqlState(err) != "23514" {
			t.Fatalf("base_url %s: %v, want 23514", bad, err)
		}
	}
	if err := insert("io.x.dns", "https://dns.x.example/api"); err != nil {
		t.Fatal(err)
	}
	enable := `UPDATE plugin_providers SET enabled=true,enabled_by_user_id=$1,enabled_at=now() WHERE plugin_id='io.x.dns'`
	if _, err := pool.Exec(ctx, enable, uuid.New()); sqlState(err) != "P3971" {
		t.Fatalf("enable before contract: %v, want P3971", err)
	}
	mustExec(t, pool, `UPDATE plugin_providers SET contract_status='failed',contract_version='v1',contract_declaration_sha256=repeat('a',64),
		contract_report='{}',contract_checked_at=now() WHERE plugin_id='io.x.dns'`)
	if _, err := pool.Exec(ctx, enable, uuid.New()); sqlState(err) != "P3971" {
		t.Fatalf("enable after failed contract: %v, want P3971", err)
	}
	mustExec(t, pool, `UPDATE plugin_providers SET contract_status='passed',contract_declaration_sha256=repeat('b',64) WHERE plugin_id='io.x.dns'`)
	if _, err := pool.Exec(ctx, enable, uuid.New()); sqlState(err) != "P3971" {
		t.Fatalf("enable with a contract of other bytes: %v, want P3971", err)
	}
	mustExec(t, pool, `UPDATE plugin_providers SET contract_declaration_sha256=repeat('a',64) WHERE plugin_id='io.x.dns'`)
	if _, err := pool.Exec(ctx, enable, uuid.New()); err != nil {
		t.Fatalf("enable after passed contract: %v", err)
	}
	mustExec(t, pool, `INSERT INTO market_data_pack_sources(artifact_id,kind,plugin_id,version,revision,sha256,local_name,status,
		materialized_at,updated_at) VALUES('plugin_provider/io.x.dns','plugin_provider','io.x.dns','1.0.0',1,repeat('b',64),'io.x.dns',
		'active',now(),now())`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P3973" {
		t.Fatalf("down with a provider source: %v, want P3973", err)
	}
}
