//go:build integration

package wafsubscription

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type stubFetcher struct {
	body []byte
	err  error
	urls []string
}

func (f *stubFetcher) fetch(_ context.Context, url string) ([]byte, error) {
	f.urls = append(f.urls, url)
	return f.body, f.err
}

func feedWith(version, value string) []byte {
	return []byte(`{"version":"` + version + `","generated_at":"2026-10-17T00:00:00Z","rules":[{"id":"r1","name":"规则一","enable":1,
	  "action":"protect","matcher_groups":[{"matcher":[{"field":"args","op":"contain","value":"` + value + `"}]}]}]}`)
}

// PA-25: a fetch keeps the last good snapshot; a subscribing tenant gets a
// downloaded, not enabled user layer pack; a snapshot whose rules changed
// adds a pack version, which a published site mounts only after it is
// published again ("待发布"); every step is audited.
func TestSubscriptionSyncAddsSubscriberPackVersions(t *testing.T) {
	pool := subscriptionPool(t)
	ctx := t.Context()
	now := time.Date(2026, time.October, 17, 8, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	platform := insertScopeUser(t, pool, "platform", "sub-admin")
	tenant := insertScopeUser(t, pool, "tenant", "sub-tenant")
	service := NewService(pool, clock, nil)
	packs := rulepackcontrol.NewService(pool, clock)
	stub := &stubFetcher{body: feedWith("v1", "evil")}
	service.fetcher = stub
	operator := Operator{UserID: platform.userID, ScopeID: platform.scopeID, ScopeKind: "platform", RequestID: "req-1",
		SourceIP: "198.51.100.7"}
	tenantActor := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant", RequestID: "req-t",
		SourceIP: "203.0.113.9"}
	packActor := rulepackcontrol.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}

	if _, err := service.Create(ctx, tenantActor, Input{Name: "x", SourceURL: "https://rules.example.com/a.json"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant create: %v", err)
	}
	for _, url := range []string{"http://rules.example.com/a.json", "https://10.0.0.1/a.json", "https://localhost/a.json"} {
		if _, err := service.Create(ctx, operator, Input{Name: "x", SourceURL: url}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("create %s: %v", url, err)
		}
	}
	item, err := service.Create(ctx, operator, Input{Name: "已知漏洞防护", SourceURL: "https://rules.example.com/a.json?token=t0", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Subscribe(ctx, tenantActor, item.ID); !errors.Is(err, ErrNotReady) {
		t.Fatalf("subscribe before the first fetch: %v", err)
	}

	// Periodic fetch: due at creation; no subscriber yet, no pack.
	if claimed, err := service.RunDue(ctx); err != nil || claimed != 1 {
		t.Fatalf("RunDue = %d, %v", claimed, err)
	}
	item, _ = service.Get(ctx, item.ID)
	if item.Revision != 1 || item.FeedVersion != "v1" || item.RuleCount != 1 || item.LastError != "" ||
		item.LastSuccessAt == nil || !item.NextFetchAt.Equal(now.Add(360*time.Minute)) || item.Rules[0].WAF == nil {
		t.Fatalf("after first fetch = %+v", item)
	}
	if claimed, _ := service.RunDue(ctx); claimed != 0 {
		t.Fatal("not-due library fetched again")
	}
	if _, err := service.Subscribe(ctx, Actor{UserID: platform.userID, ScopeID: platform.scopeID, ScopeKind: "platform"}, item.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("platform subscribe: %v", err)
	}

	// The tenant subscribes: pack 1.0.0, current, downloaded, not enabled.
	subscribed, err := service.Subscribe(ctx, tenantActor, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	packID := PackID(tenant.scopeID, item.ID)
	if !subscribed.Subscribed || subscribed.Pack == nil || subscribed.Pack.PackID != packID || subscribed.Pack.CurrentVersion != "1.0.0" {
		t.Fatalf("subscribed = %+v", subscribed)
	}
	if again, err := service.Subscribe(ctx, tenantActor, item.ID); err != nil || again.Pack.CurrentVersion != "1.0.0" {
		t.Fatalf("subscribe twice = %+v, %v", again, err)
	}
	tenantView := func() rulepackcontrol.Pack {
		view, err := packs.View(ctx, packActor, rulepackcontrol.LevelInput{Level: rulepack.LevelTenant, ObjectID: &tenant.scopeID})
		if err != nil || len(view.Packs) != 1 {
			t.Fatalf("tenant view = %+v, %v", view, err)
		}
		return view.Packs[0]
	}
	if pack := tenantView(); pack.Layer != "user" || pack.Effect == nil || pack.Effect.Enabled || pack.UpdatePolicy != "auto" ||
		len(pack.Versions) != 1 || pack.Versions[0].Source != "subscription" || len(pack.Exports) != 1 {
		t.Fatalf("pack = %+v", pack)
	}

	// The tenant enables it and publishes a site with 1.0.0.
	site := insertSite(t, pool, tenant)
	if _, _, err := packs.PutOverride(ctx, packActor, rulepackcontrol.OverrideInput{Level: rulepack.LevelTenant,
		LevelObjectID: &tenant.scopeID, PackID: packID, State: rulepack.StateEnabled}); err != nil {
		t.Fatal(err)
	}
	if published, err := packs.PublishSite(ctx, packActor, site); err != nil || published.Published == nil ||
		published.Published.Security.Mounts[0].Version != "1.0.0" {
		t.Fatalf("publish = %+v, %v", published, err)
	}

	// A broken document keeps the last good snapshot and records the error.
	stub.body = []byte(`{"version":"v2","rules":[{"id":"r1","name":"n","enable":1,"action":"protect","action_config":{"status":"302"},
	  "matcher_groups":[{"matcher":[{"field":"args","op":"contain","value":"x"}]}]}]}`)
	if item, err = service.Sync(ctx, operator, item.ID); err != nil {
		t.Fatal(err)
	}
	if item.Revision != 1 || item.FeedVersion != "v1" || !strings.Contains(item.LastError, "403") ||
		item.Rules[0].WAF.Match.Inspect[0].Values[0] != "evil" {
		t.Fatalf("after failed fetch = %+v", item)
	}
	stub.body, stub.err = nil, errors.New("connection refused")
	if item, _ = service.Sync(ctx, operator, item.ID); item.Revision != 1 || !strings.Contains(item.LastError, "refused") {
		t.Fatalf("after network failure = %+v", item)
	}

	// Same rules under a new version string: no new revision or pack version.
	stub.body, stub.err = feedWith("v1.1", "evil"), nil
	if item, _ = service.Sync(ctx, operator, item.ID); item.Revision != 1 || item.FeedVersion != "v1.1" || item.LastError != "" {
		t.Fatalf("unchanged rules = %+v", item)
	}
	if pack := tenantView(); len(pack.Versions) != 1 {
		t.Fatalf("unchanged rules added a version: %+v", pack.Versions)
	}

	// Changed rules: revision 2, pack 2.0.0 becomes current; the published
	// site keeps 1.0.0 and is pending until it is published again.
	stub.body = feedWith("v2", "worse")
	if item, _ = service.Sync(ctx, operator, item.ID); item.Revision != 2 || item.LastError != "" {
		t.Fatalf("changed rules = %+v", item)
	}
	if pack := tenantView(); pack.CurrentVersion != "2.0.0" || len(pack.Versions) != 2 {
		t.Fatalf("pack after change = %+v", pack)
	}
	mounts, err := packs.Site(ctx, packActor, site)
	if err != nil || mounts.UpToDate || mounts.Published.Security.Mounts[0].Version != "1.0.0" {
		t.Fatalf("site after change = %+v, %v", mounts, err)
	}
	if item.Subscribers != 1 || item.PendingSites != 1 {
		t.Fatalf("subscription counts = %+v", item)
	}
	subscriberPacks, err := service.SubscriberPacks(ctx, tenantActor, nil)
	if err != nil || len(subscriberPacks) != 1 || len(subscriberPacks[0].PendingSites) != 1 ||
		subscriberPacks[0].PendingSites[0].SiteID != site || subscriberPacks[0].PendingSites[0].PublishedVersion != "1.0.0" {
		t.Fatalf("pending = %+v, %v", subscriberPacks, err)
	}
	other := insertScopeUser(t, pool, "tenant", "sub-other")
	if others, err := service.SubscriberPacks(ctx, Actor{UserID: other.userID, ScopeID: other.scopeID, ScopeKind: "tenant"}, nil); err != nil || len(others) != 0 {
		t.Fatalf("other tenant sees %+v, %v", others, err)
	}
	if _, err := packs.PublishSite(ctx, packActor, site); err != nil {
		t.Fatal(err)
	}
	if item, _ = service.Get(ctx, item.ID); item.PendingSites != 0 {
		t.Fatalf("published site still pending: %+v", item)
	}

	// A rename (same rules) changes the pack text: 2.1.0.
	if _, err := service.Update(ctx, operator, item.ID, Input{Name: "已知漏洞防护（新）", SourceURL: "https://rules.example.com/a.json?token=t1",
		IntervalMinutes: 360, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if item, _ = service.Sync(ctx, operator, item.ID); item.Revision != 2 {
		t.Fatalf("after rename = %+v", item)
	}
	if pack := tenantView(); pack.CurrentVersion != "2.1.0" || pack.Name != "已知漏洞防护（新）" {
		t.Fatalf("pack after rename = %+v", pack)
	}

	// update_policy manual: a new version is downloaded, not made current.
	manual := "manual"
	if _, err := packs.UpdatePack(ctx, packActor, packID, rulepackcontrol.PackUpdate{UpdatePolicy: &manual}); err != nil {
		t.Fatal(err)
	}
	stub.body = feedWith("v3", "worst")
	if item, _ = service.Sync(ctx, operator, item.ID); item.Revision != 3 {
		t.Fatalf("third revision = %+v", item)
	}
	if pack := tenantView(); pack.CurrentVersion != "2.1.0" || len(pack.Versions) != 4 {
		t.Fatalf("manual pack = %+v", pack)
	}

	// Audit: create/update with the URL query redacted, subscribe, the
	// pack versions, and a sync per manual run (failures with a reason).
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='rule.pack.version.create' AND scope_id=$1
		AND payload->>'source'='subscription' AND payload->>'subscription_id'=$2`, tenant.scopeID, item.ID.String()).Scan(&count); err != nil || count != 4 {
		t.Fatalf("pack version events = %d (%v)", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='rule.subscription.sync' AND scope_id=$1
		AND payload->>'ip'='198.51.100.7' AND payload->>'trigger'='manual'`, platform.scopeID).Scan(&count); err != nil || count != 6 {
		t.Fatalf("manual sync events = %d (%v)", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='rule.subscription.sync' AND result='failure'
		AND payload->>'reason' IN ('invalid_document','fetch_failed')`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("failed sync events = %d (%v)", count, err)
	}
	var changes string
	if err := pool.QueryRow(ctx, `SELECT (SELECT item->'after'->>'added' FROM jsonb_array_elements(changes) item
			WHERE item->>'field'='pack_versions') FROM audit_events
		WHERE action='rule.subscription.sync' AND changes @> '[{"field":"revision","after":2}]'`).Scan(&changes); err != nil ||
		!strings.Contains(changes, packID+"@2.0.0") {
		t.Fatalf("sync changes = %s (%v)", changes, err)
	}
	var updatePayload, updateChanges string
	if err := pool.QueryRow(ctx, `SELECT payload::text, changes::text FROM audit_events WHERE action='rule.subscription.update'`).
		Scan(&updatePayload, &updateChanges); err != nil || strings.Contains(updatePayload+updateChanges, "token=") ||
		!strings.Contains(updateChanges, `"field": "source_url.query_changed"`) {
		t.Fatalf("update payload = %s changes = %s (%v)", updatePayload, updateChanges, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='rule.subscription.subscribe' AND scope_id=$1
		AND payload->>'ip'='203.0.113.9'`, tenant.scopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("subscribe events = %d (%v)", count, err)
	}

	// Scheduled failures with the same error are audited once.
	stub.body, stub.err = nil, errors.New("timeout")
	for range 2 {
		mustExec(t, pool, `UPDATE waf_rule_subscriptions SET next_fetch_at=$2 WHERE id=$1`, item.ID, now)
		if _, err := service.RunDue(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='rule.subscription.sync' AND
		payload->>'trigger'='scheduled' AND result='failure'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("scheduled failure events = %d (%v)", count, err)
	}

	// Unsubscribing stops new versions and keeps the pack.
	if err := service.Unsubscribe(ctx, tenantActor, item.ID); err != nil {
		t.Fatal(err)
	}
	stub.body, stub.err = feedWith("v4", "other"), nil
	if item, _ = service.Sync(ctx, operator, item.ID); item.Revision != 4 || item.Subscribers != 0 {
		t.Fatalf("after unsubscribe = %+v", item)
	}
	if pack := tenantView(); len(pack.Versions) != 4 {
		t.Fatalf("unsubscribed pack changed: %+v", pack.Versions)
	}
	// Subscribing again brings the kept pack up to date.
	if again, err := service.Subscribe(ctx, tenantActor, item.ID); err != nil || again.Pack.LatestVersion != "4.0.0" {
		t.Fatalf("resubscribe = %+v, %v", again, err)
	}

	// Deleted libraries stop fetching; subscribers still see them.
	if err := service.Delete(ctx, operator, item.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Sync(ctx, operator, item.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sync deleted: %v", err)
	}
	listed, _ := service.List(ctx, false)
	all, _ := service.List(ctx, true)
	if len(listed) != 0 || len(all) != 1 || !all[0].Deleted {
		t.Fatalf("list = %d / %d", len(listed), len(all))
	}
	if mine, err := service.TenantList(ctx, tenantActor, nil); err != nil || len(mine) != 1 || !mine[0].Deleted || !mine[0].Subscribed {
		t.Fatalf("tenant list after delete = %+v, %v", mine, err)
	}
	if theirs, err := service.TenantList(ctx, Actor{UserID: other.userID, ScopeID: other.scopeID, ScopeKind: "tenant"}, nil); err != nil || len(theirs) != 0 {
		t.Fatalf("other tenant list after delete = %+v, %v", theirs, err)
	}
}

func insertSite(t *testing.T, pool *pgxpool.Pool, owner scopeUser) uuid.UUID {
	id := uuid.New()
	// A site needs its origin pool in the same transaction (deferred check).
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id) VALUES($1,$2,$3,'sub.example.test',ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,1)`,
				[]any{id, owner.scopeID, owner.userID}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{id}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{id}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type scopeUser struct{ scopeID, userID uuid.UUID }

func insertScopeUser(t *testing.T, pool *pgxpool.Pool, kind, username string) scopeUser {
	t.Helper()
	ctx := context.Background()
	result := scopeUser{scopeID: uuid.New(), userID: uuid.New()}
	if kind == "tenant" {
		tenantID := uuid.New()
		mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, username)
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, result.scopeID, tenantID)
	} else {
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, result.scopeID)
	}
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'test-only')`, result.userID, username)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, result.scopeID, result.userID)
	_ = ctx
	return result
}

func mustExec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func subscriptionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "waf_subscription_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}
