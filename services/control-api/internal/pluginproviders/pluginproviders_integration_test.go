//go:build integration

package pluginproviders_test

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/entitlement/pluginprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders/pluginproviderstest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newPool(t *testing.T) (*pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (scripts/control-api-integration-sharded.sh)")
	}
	platform, admin := uuid.New(), uuid.New()
	for _, statement := range []string{
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES('` + platform.String() + `','platform',NULL)`,
		`INSERT INTO users(id,username,display_name,password_hash) VALUES('` + admin.String() + `','provider-admin','管理员','unused')`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	return pool, platform, admin
}

func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Acceptance (PA-22): a conforming DNS / SMS / ICP plugin passes the
// installation contract against its sandbox and can then be enabled; before
// that, enabling is refused (and audited); only an enabled, passed provider
// yields a client.
func TestContractThenEnable(t *testing.T) {
	pool, platform, admin := newPool(t)
	plugin := pluginproviderstest.Start(t, pool, "com.example.allinone", "dns", "sms", "icp")
	plugin.Materialize(t, pool)
	ctx := t.Context()
	actor := pluginproviders.Actor{UserID: admin, ScopeID: platform, RequestID: "req-enable-1", SourceIP: "198.51.100.7"}

	if _, err := plugin.Service.Store.SetEnabled(ctx, actor, "com.example.allinone", true); !errors.Is(err, pluginproviders.ErrContractNeeded) {
		t.Fatalf("enable before contract = %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action='plugin.provider.enable' AND result='failure'
		AND resource_id='com.example.allinone'`); n != 1 {
		t.Fatalf("refused enable audit = %d", n)
	}
	if _, err := plugin.Service.Client(ctx, "com.example.allinone", "dns"); !errors.Is(err, pluginproviders.ErrNotUsable) {
		t.Fatalf("client before contract = %v", err)
	}

	if ran := plugin.Service.RunPending(ctx); ran != 1 {
		t.Fatalf("pending contracts run = %d", ran)
	}
	provider, err := plugin.Service.Store.Get(ctx, "com.example.allinone")
	if err != nil || provider.ContractStatus != pluginproviders.ContractPassed || provider.ContractReport == nil ||
		!provider.ContractReport.Passed || provider.Usable {
		t.Fatalf("after contract %+v %v", provider, err)
	}
	kinds := map[string]bool{}
	for _, result := range provider.ContractReport.Cases {
		kinds[result.Kind] = true
	}
	if !kinds["dns"] || !kinds["sms"] || !kinds["icp"] {
		t.Fatalf("contract cases by kind %v", kinds)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action='plugin.provider.contract' AND result='success'
		AND actor_kind='system'`); n != 1 {
		t.Fatalf("contract audit = %d", n)
	}
	if len(plugin.Fake.Records(pluginprovider.SandboxZone)) != 0 || len(plugin.Fake.Sent) != 1 || !plugin.Fake.Sent[0].Sandbox {
		t.Fatalf("contract touched non-sandbox state: records %v sent %+v", plugin.Fake.Records(pluginprovider.SandboxZone), plugin.Fake.Sent)
	}

	provider, err = plugin.Service.Store.SetEnabled(ctx, actor, "com.example.allinone", true)
	if err != nil || !provider.Enabled || !provider.Usable {
		t.Fatalf("enable after contract %+v %v", provider, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action='plugin.provider.enable' AND result='success'
		AND actor_user_id=$1 AND source_ip='198.51.100.7' AND jsonb_array_length(changes) > 0`, admin); n != 1 {
		t.Fatalf("enable audit = %d", n)
	}
	if _, err := plugin.Service.Client(ctx, "com.example.allinone", "icp"); err != nil {
		t.Fatalf("client after enable: %v", err)
	}
	// An upgrade (new declaration bytes) makes it unusable until it passed again.
	if _, err := pool.Exec(ctx, `UPDATE plugin_providers SET declaration_sha256=repeat('c',64),contract_status='pending'
		WHERE plugin_id='com.example.allinone'`); err != nil {
		t.Fatal(err)
	}
	if _, err := plugin.Service.Client(ctx, "com.example.allinone", "icp"); !errors.Is(err, pluginproviders.ErrNotUsable) {
		t.Fatalf("client after upgrade before contract = %v", err)
	}
}

// Acceptance (PA-22): a plugin that fails the contract cannot be enabled; a
// malicious plugin (accepts forged requests, signs with the wrong key) fails
// it with the reason recorded.
func TestFailedContractBlocksEnable(t *testing.T) {
	for name, misbehave := range map[string]pluginprovider.Misbehavior{
		"accepts forged requests": {AcceptBadSignature: true},
		"wrong response key":      {WrongResponseKey: true},
		"ignores delete":          {IgnoreDelete: true},
	} {
		t.Run(name, func(t *testing.T) {
			pool, platform, admin := newPool(t)
			plugin := pluginproviderstest.Start(t, pool, "com.example.evil", "dns")
			plugin.Fake.Misbehave = misbehave
			plugin.Materialize(t, pool)
			ctx := t.Context()
			actor := pluginproviders.Actor{UserID: admin, ScopeID: platform, RequestID: "req-run"}
			provider, err := plugin.Service.RunContract(ctx, actor, "com.example.evil")
			if err != nil || provider.ContractStatus != pluginproviders.ContractFailed || provider.ContractReport.Passed {
				t.Fatalf("contract %+v %v", provider, err)
			}
			if _, err := plugin.Service.Store.SetEnabled(ctx, actor, "com.example.evil", true); !errors.Is(err, pluginproviders.ErrContractNeeded) {
				t.Fatalf("enable after failed contract = %v", err)
			}
			// The database refuses it too, whatever the caller.
			if _, err := pool.Exec(ctx, `UPDATE plugin_providers SET enabled=true,enabled_by_user_id=$1,enabled_at=now()
				WHERE plugin_id='com.example.evil'`, admin); err == nil {
				t.Fatal("database accepted enabling a failed provider")
			}
			if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action='plugin.provider.contract' AND result='failure'
				AND reason_code='contract_failed'`); n != 1 {
				t.Fatalf("failed contract audit = %d", n)
			}
		})
	}
}
