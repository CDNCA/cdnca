//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDomainEventProducers369Migration rolls 369 up/down/up and checks the
// certificate and node producers in SQL. The usage (package monitor and
// cycle enforcement), CC incident and node presence producers are exercised
// through their real write paths in packagemonitor, ccautoswitch and
// nodepresence integration tests.
func TestDomainEventProducers369Migration(t *testing.T) {
	const version = 369
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var active int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM plugin_webhook_event_contracts_122
		WHERE status='active' AND event_type <> 'io.cdnca.webhook.v1.test'`).Scan(&active); err != nil || active != 6 {
		t.Fatalf("active domain contracts = %d, %v", active, err)
	}

	tenant := seedSiteGroup082Identity(t, pool, "domain-event-369")
	orderID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO certificate_orders(id,scope_id,domains,challenge_type,auto_renew,
		created_by_user_id,updated_by_user_id) VALUES($1,$2,ARRAY['events-369.example.test'],'http-01',true,$3,$3)`,
		orderID, tenant.scopeID, tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE certificate_orders SET status='validating',revision=revision+1,
		updated_at=now() WHERE id=$1`, orderID); err != nil {
		t.Fatal(err)
	}
	assertDomainEvents369(t, pool, "certificate_order/"+orderID.String(),
		`coalesce(payload->>'previous_status','-')||'>'||(payload->>'status')||'@'||(payload->>'revision')`,
		"->pending@1,pending>validating@2")

	// A platform node carried by the tenant (node_config_state) and the
	// tenant's own (seller) node each produce one fact for that tenant.
	platform := uuid.New()
	nodeID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
		INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($2,$1,'node-369','active',$3,1);
		INSERT INTO node_config_state(node_id,configuration_scope_id,revision,updated_at) VALUES($2,$4,1,now());
		UPDATE nodes SET admin_state='draining',revision=revision+1,updated_at=now() WHERE id=$2`,
		pgx.QueryExecModeSimpleProtocol, platform, nodeID, tenant.userID, tenant.scopeID); err != nil {
		t.Fatal(err)
	}
	assertDomainEvents369(t, pool, "node/"+nodeID.String(),
		`(payload->>'kind')||':'||(payload->>'previous_status')||'>'||(payload->>'status')||'/'||tenant_scope_id::text`,
		"admin:active>draining/"+tenant.scopeID.String())
	var platformFacts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM domain_event_outbox_368 WHERE tenant_scope_id=$1`,
		platform).Scan(&platformFacts); err != nil || platformFacts != 0 {
		t.Fatalf("platform scope facts = %d, %v", platformFacts, err)
	}

	assertDomainEvent368Code(t, migrateVersionIsolated(t.Context(), pool, "down", version), "P3699")

	// 370 (site filter) rolls up/down/up on top; its filter and delivery
	// guards are exercised end to end in pluginwebhookcontrol.
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version+1); err != nil {
			t.Fatalf("%s %d: %v", step, version+1, err)
		}
	}
}

func assertDomainEvents369(t *testing.T, pool *pgxpool.Pool, subject, expression, want string) {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT `+expression+` FROM domain_event_outbox_368
		WHERE subject=$1 ORDER BY subject_sequence`, subject)
	if err != nil {
		t.Fatal(err)
	}
	values, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || strings.Join(values, ",") != want {
		t.Fatalf("%s facts = %v (%v), want %s", subject, values, err, want)
	}
}
