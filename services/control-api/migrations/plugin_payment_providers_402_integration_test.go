//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
)

// TestPluginPaymentProviders402: a payment provider is enabled only with
// the high-risk confirmation in the same write, a fresh proof each time;
// disabling or new declaration bytes drop the confirmation (an upgrade
// also turns it off); a plugin payment channel names its plugin and
// merchant; down refuses while payment plugins exist.
func TestPluginPaymentProviders402(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_plugin_payment_providers.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("plugin payment providers migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	mustExec(t, pool, `INSERT INTO plugin_providers(plugin_id,version,base_url,kinds,declaration,declaration_sha256,
		status,tenant_scope_id,authorization_id,contract_status,contract_version,contract_declaration_sha256,contract_report,
		contract_checked_at,materialized_at,updated_at)
		VALUES('io.x.pay','1.0.0','https://pay.x.example','{payment}',jsonb_build_object('plugin_id','io.x.pay','base_url',
		'https://pay.x.example'),repeat('a',64),'active',$1,$2,'passed','v1',repeat('a',64),'{}',now(),now(),now())`,
		uuid.New(), uuid.New())
	admin := uuid.New()
	plain := `UPDATE plugin_providers SET enabled=true,enabled_by_user_id=$1,enabled_at=now() WHERE plugin_id='io.x.pay'`
	if _, err := pool.Exec(ctx, plain, admin); sqlState(err) != "P4021" {
		t.Fatalf("enable payment without confirmation: %v, want P4021", err)
	}
	other := `UPDATE plugin_providers SET enabled=true,enabled_by_user_id=$1,enabled_at=now(),payment_confirmed_by_user_id=$2,
		payment_confirmed_at=now(),payment_step_up_proof_id=$3 WHERE plugin_id='io.x.pay'`
	if _, err := pool.Exec(ctx, other, admin, uuid.New(), uuid.New()); sqlState(err) != "P4021" {
		t.Fatalf("enable payment confirmed by someone else: %v, want P4021", err)
	}
	proof := uuid.New()
	if _, err := pool.Exec(ctx, other, admin, admin, proof); err != nil {
		t.Fatalf("enable payment with confirmation: %v", err)
	}
	mustExec(t, pool, `UPDATE plugin_providers SET enabled=false WHERE plugin_id='io.x.pay'`)
	var cleared bool
	if err := pool.QueryRow(ctx, `SELECT payment_confirmed_at IS NULL AND payment_step_up_proof_id IS NULL FROM plugin_providers
		WHERE plugin_id='io.x.pay'`).Scan(&cleared); err != nil || !cleared {
		t.Fatalf("disable keeps the confirmation: %v %v", cleared, err)
	}
	if _, err := pool.Exec(ctx, other, admin, admin, proof); err != nil {
		t.Fatalf("re-enable with a new confirmation write: %v", err)
	}
	// New declaration bytes turn a payment provider off.
	mustExec(t, pool, `UPDATE plugin_providers SET declaration_sha256=repeat('b',64),contract_status='pending' WHERE plugin_id='io.x.pay'`)
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM plugin_providers WHERE plugin_id='io.x.pay'`).Scan(&enabled); err != nil || enabled {
		t.Fatalf("upgrade kept payment provider enabled: %v %v", enabled, err)
	}
	// A DNS provider is unaffected.
	mustExec(t, pool, `INSERT INTO plugin_providers(plugin_id,version,base_url,kinds,declaration,declaration_sha256,
		status,tenant_scope_id,authorization_id,contract_status,contract_version,contract_declaration_sha256,contract_report,
		contract_checked_at,materialized_at,updated_at)
		VALUES('io.x.dns','1.0.0','https://dns.x.example','{dns}',jsonb_build_object('plugin_id','io.x.dns','base_url',
		'https://dns.x.example'),repeat('a',64),'active',$1,$2,'passed','v1',repeat('a',64),'{}',now(),now(),now())`,
		uuid.New(), uuid.New())
	mustExec(t, pool, `UPDATE plugin_providers SET enabled=true,enabled_by_user_id=$1,enabled_at=now() WHERE plugin_id='io.x.dns'`, admin)

	channel := func(config string) error {
		_, err := pool.Exec(ctx, `INSERT INTO payment_channels(id,provider,method,display_name,config,created_by,updated_by,
			created_at,updated_at) VALUES($1,'plugin','alipay','插件收款',$2::jsonb,$3,$3,now(),now())`, uuid.New(), config, admin)
		return err
	}
	for _, bad := range []string{`{}`, `{"plugin_id":"io.x.pay"}`, `{"plugin_id":"BAD","merchant_id":"m1"}`} {
		if err := channel(bad); sqlState(err) != "23514" {
			t.Fatalf("plugin channel config %s: %v, want 23514", bad, err)
		}
	}
	if err := channel(`{"plugin_id":"io.x.pay","merchant_id":"m-1"}`); err != nil {
		t.Fatalf("plugin channel: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4023" {
		t.Fatalf("down with payment plugins: %v, want P4023", err)
	}
	mustExec(t, pool, `DELETE FROM payment_channels WHERE provider='plugin'`)
	mustExec(t, pool, `DELETE FROM plugin_providers WHERE plugin_id='io.x.pay'`)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
}
