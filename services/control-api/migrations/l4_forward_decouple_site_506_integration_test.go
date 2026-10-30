//go:build integration

package migrations_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestL4ForwardDecoupleSite506PG17RoundTrip（l4-s6，待出包前全量跑，本任务未跑）:
// a 505 head with one site-bound stream and its latest intent (site_id on the
// top level and in geo) → up 506: l4_forwards / l4_publish_intents lose
// site_id, the old intent is kept verbatim, a new latest intent without
// site_id is appended at the same resource revision, and the NOT VALID check
// does not reject the old row → down 506 is refused (P5063) while a stream
// exists; with no stream the round trip down/up succeeds.
func TestL4ForwardDecoupleSite506PG17RoundTrip(t *testing.T) {
	const version = 506
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "decouple-506", now)
	siteID, streamID := uuid.New(), uuid.New()
	seedSite335(ctx, t, pool, scope, user, siteID, 49901)
	// Seed the stream bound to the site and its v11 intent with triggers off.
	// CHECK 约束在 replica 下照样生效，意图必须是合法 496 形状（见 intentSpec506）。
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`SET LOCAL session_replication_role='replica'`, nil},
		// replica 下 214 的 display_id 赋值触发器不跑，INSERT 里直接给显示 ID。
		{strings.Replace(strings.Replace(l4Insert214(false), "id,scope_id,", "id,display_id,scope_id,", 1),
			"VALUES($1,", "VALUES($1,1,", 1), []any{streamID, scope, subscription, user, "Bound 506", 19499, now}},
		{`UPDATE l4_forwards SET site_id=$2 WHERE id=$1`, []any{streamID, siteID}},
		{`INSERT INTO l4_publish_intents(id,scope_id,stream_id,site_id,version,operation,desired_state,resource_revision,
			configuration_source_revision,runtime_spec,created_by_user_id,created_at)
			VALUES($1,$2,$3::uuid,$4::uuid,1,'create','enabled',1,1,
			$7::jsonb,$5,$6)`,
			[]any{uuid.New(), scope, streamID, siteID, user, now, intentSpec506(scope, siteID, streamID)}},
		// 生产写意图前总会 upsert 计数器（internal/l4forward/store.go），506 据此分配追加意图的版本号。
		{`INSERT INTO l4_scope_publish_counters(scope_id,current_version) VALUES($1,1)`, []any{scope}},
		{`SET LOCAL session_replication_role='origin'`, nil},
	} {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed %.60s: %v", statement.query, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var forwardSite, intentSite bool
	if err := pool.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='l4_forwards' AND column_name='site_id'),
		EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='l4_publish_intents' AND column_name='site_id')`).Scan(
		&forwardSite, &intentSite); err != nil || forwardSite || intentSite {
		t.Fatalf("site_id columns after 506: forwards=%t intents=%t err=%v", forwardSite, intentSite, err)
	}
	var intents int
	var oldSpecSite, latestHasSite, latestGeoHasSite bool
	var latestRevision int64
	if err := pool.QueryRow(ctx, `SELECT count(*),
		bool_or(version=1 AND runtime_spec->>'site_id' IS NOT NULL),
		(array_agg(runtime_spec ? 'site_id' ORDER BY version DESC))[1],
		(array_agg((runtime_spec->'geo') ? 'site_id' ORDER BY version DESC))[1],
		(array_agg(resource_revision ORDER BY version DESC))[1]
		FROM l4_publish_intents WHERE stream_id=$1`, streamID).Scan(
		&intents, &oldSpecSite, &latestHasSite, &latestGeoHasSite, &latestRevision); err != nil {
		t.Fatal(err)
	}
	if intents != 2 || !oldSpecSite || latestHasSite || latestGeoHasSite || latestRevision != 1 {
		t.Fatalf("intents after 506: count=%d old-has-site=%t latest-site=%t latest-geo-site=%t revision=%d",
			intents, oldSpecSite, latestHasSite, latestGeoHasSite, latestRevision)
	}
	// The NOT VALID check leaves the old intent alone; it is not revalidated.
	var validated bool
	if err := pool.QueryRow(ctx, `SELECT convalidated FROM pg_constraint
		WHERE conname='l4_publish_intents_runtime_spec_506'`).Scan(&validated); err != nil || validated {
		t.Fatalf("runtime spec check validated=%t err=%v, want NOT VALID", validated, err)
	}
	// stream-cname's stream intents now hang on the stream + scope (505 FK replaced).
	var streamFK bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint
		WHERE conname='cname_stream_intents_stream_506_fk' AND conrelid='cname_stream_intents'::regclass)`).Scan(&streamFK); err != nil || !streamFK {
		t.Fatalf("cname_stream_intents FK after 506 = %t %v", streamFK, err)
	}

	var pgErr *pgconn.PgError
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P5063" {
		t.Fatalf("down %d with a stream = %v, want P5063", version, err)
	}

	// Without streams the migration rolls back and reapplies.
	if _, err := pool.Exec(ctx, `SET session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DELETE FROM l4_publish_intents WHERE stream_id='` + streamID.String() + `'`,
		`DELETE FROM l4_forward_listeners WHERE stream_id='` + streamID.String() + `'`,
		`DELETE FROM l4_forwards WHERE id='` + streamID.String() + `'`,
	} {
		if _, err := pool.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if _, err := pool.Exec(ctx, `SET session_replication_role='origin'`); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d without streams: %v", step, version, err)
		}
	}
}

// intentSpec506 是与 l4Insert214 转发一致的完整 v11 意图：151 的顶层/geo 键集合必须完全相等
// （151_l4_domain_geo_runtime.up.sql validate_l4_runtime_spec_151），496 起的可选键都不带。
func intentSpec506(scope, siteID, streamID uuid.UUID) string {
	return `{"schema_version":"cdnca.edge.l4/v2","tenant_id":"` + scope.String() + `","site_id":"` + siteID.String() +
		`","stream_id":"` + streamID.String() + `","revision":1,
		"listener":{"protocol":"tcp","address":"*","port":19499},
		"endpoint":{"address":"192.0.2.10","port":9000},
		"dns":{"positive_min_ttl_seconds":0,"positive_max_ttl_seconds":0,"negative_ttl_seconds":0,"stale_if_error_seconds":0,"allow_private_addresses":false},
		"geo":{"tenant_id":"` + scope.String() + `","site_id":"` + siteID.String() + `","stream_id":"` + streamID.String() +
		`","revision":1,"enabled":false,"unknown_region_action":"allow","trusted_proxy_cidrs":[],"blocked_regions":[],"region_cidrs":[]},
		"connect_timeout_ms":3000,"response_timeout_ms":30000,"max_connections_per_client":100,"drain_timeout_ms":30000,
		"proxy_protocol_inbound":false,"proxy_protocol_outbound":false}`
}
