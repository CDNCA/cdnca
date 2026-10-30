//go:build integration

package site

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-readiness（PG，写好不跑，出包前统一回归）：列表/详情带 access_readiness 且只读库；
// 后台检查入表、按站点限频与退避；“立即检查”同站 1 分钟一次、换代后旧租约不能覆盖；租户看不到他人站点。
func TestSiteAccessReadinessPostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	created, err := f.createSite(f.a, f.a, "ready.example.test")
	if err != nil {
		t.Fatal(err)
	}
	id := created.Site.ID

	// Fresh site: no line group or online node (fixture has none), DNS never checked.
	detail, err := f.sites.Get(ctx, f.a.siteActor(), id)
	if err != nil || detail.AccessReadiness == nil {
		t.Fatalf("detail readiness=%v err=%v", detail.AccessReadiness, err)
	}
	// fix-readiness2：no package bound → package fails first (blocked), then line_group.
	if detail.AccessReadiness.State != AccessBlocked || len(detail.AccessReadiness.Checks) != 6 ||
		detail.AccessReadiness.Checks[0].Code != AccessCheckPackage || detail.AccessReadiness.Checks[0].OK ||
		detail.AccessReadiness.Checks[0].Detail != PackageUnavailableNoPackage ||
		detail.AccessReadiness.Checks[1].Code != AccessCheckLineGroup || detail.AccessReadiness.Checks[1].OK {
		t.Fatalf("fresh site readiness = %+v", detail.AccessReadiness)
	}
	list, err := f.sites.List(ctx, f.a.siteActor(), ListFilter{Page: 1, Limit: 20})
	if err != nil || len(list.Items) != 1 || list.Items[0].AccessReadiness == nil ||
		list.Items[0].AccessReadiness.State != detail.AccessReadiness.State {
		t.Fatalf("list readiness = %+v err=%v", list.Items, err)
	}
	// Reads never enroll or resolve: no check row yet.
	var rows int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM site_dns_resolution_checks`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("reads wrote check rows: %d %v", rows, err)
	}

	// Background round: enrolls the site and stores a failed check (no CNAME yet), backing off 10 minutes.
	store := f.sites.store
	resolver := fakeResolver{cname: map[string]string{}, ips: map[string][]string{}}
	worker := NewDNSCheckWorker(store, resolver, nil)
	if checked, err := worker.RunOnce(ctx); err != nil || checked != 1 {
		t.Fatalf("first round checked=%d err=%v", checked, err)
	}
	var failures int
	var next time.Time
	if err := f.pool.QueryRow(ctx, `SELECT consecutive_failures, next_check_at FROM site_dns_resolution_checks WHERE site_id=$1`,
		id).Scan(&failures, &next); err != nil || failures != 1 || !next.Equal(f.now.Add(10*time.Minute)) {
		t.Fatalf("after first failure failures=%d next=%v err=%v", failures, next, err)
	}
	// Not due yet: nothing claimed.
	if checked, err := worker.RunOnce(ctx); err != nil || checked != 0 {
		t.Fatalf("early round checked=%d err=%v", checked, err)
	}
	f.now = f.now.Add(10 * time.Minute)
	if checked, err := worker.RunOnce(ctx); err != nil || checked != 1 {
		t.Fatalf("due round checked=%d err=%v", checked, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT consecutive_failures, next_check_at FROM site_dns_resolution_checks WHERE site_id=$1`,
		id).Scan(&failures, &next); err != nil || failures != 2 || !next.Equal(f.now.Add(20*time.Minute)) {
		t.Fatalf("after second failure failures=%d next=%v err=%v", failures, next, err)
	}

	// Give the site a CNAME the resolver points at: 立即检查 passes dns_resolved.
	// A site-mode CNAME carries the whole 113 authority (sites_cname_authority_113_check); its
	// allocation task is not what this checks, so it is seeded with triggers and FKs off.
	if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE sites SET cname='r1.cdn.example.net', cname_mode='site', cname_domain='cdn.example.net',
			cname_hostname2='r1', cname_state='done', cname_task_id=gen_random_uuid(), cname_current_revision=1 WHERE id=$1`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	resolver.cname["ready.example.test"] = "r1.cdn.example.net."
	readiness, err := store.CheckAccessNow(ctx, f.a.siteActor(), id, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if dns := readiness.Checks[3]; dns.Code != AccessCheckDNS || !dns.OK || dns.CheckedAt == nil || !dns.CheckedAt.Equal(f.now) {
		t.Fatalf("manual check dns = %+v", dns)
	}
	if err := f.pool.QueryRow(ctx, `SELECT consecutive_failures, next_check_at FROM site_dns_resolution_checks WHERE site_id=$1`,
		id).Scan(&failures, &next); err != nil || failures != 0 || !next.Equal(f.now.Add(10*time.Minute)) {
		t.Fatalf("after pass failures=%d next=%v err=%v", failures, next, err)
	}
	// Again within the minute: throttled with the seconds left.
	f.now = f.now.Add(20 * time.Second)
	var throttled *AccessCheckThrottledError
	if _, err := store.CheckAccessNow(ctx, f.a.siteActor(), id, resolver); !errors.As(err, &throttled) || throttled.Wait != 40*time.Second {
		t.Fatalf("second manual check err=%v", err)
	}
	f.now = f.now.Add(40 * time.Second)
	if _, err := store.CheckAccessNow(ctx, f.a.siteActor(), id, resolver); err != nil {
		t.Fatalf("manual check after a minute: %v", err)
	}

	// A background claim leased before a manual check cannot store its older answer.
	f.now = f.now.Add(11 * time.Minute)
	claims, err := store.ClaimDNSChecks(ctx, 10, 5*time.Minute)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claims=%d err=%v", len(claims), err)
	}
	f.now = f.now.Add(time.Minute)
	if _, err := store.CheckAccessNow(ctx, f.a.siteActor(), id, resolver); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteDNSCheck(ctx, claims[0], dnsOutcome{Detail: DNSNotFound}); err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := f.pool.QueryRow(ctx, `SELECT ok FROM site_dns_resolution_checks WHERE site_id=$1`, id).Scan(&ok); err != nil || !ok {
		t.Fatalf("stale claim overwrote manual result ok=%v err=%v", ok, err)
	}

	// A changed CNAME makes the stored result stale: read as not checked.
	f.exec(`UPDATE sites SET cname='r2.cdn.example.net' WHERE id=$1`, id)
	detail, err = f.sites.Get(ctx, f.a.siteActor(), id)
	if err != nil || detail.AccessReadiness.Checks[3].OK || detail.AccessReadiness.Checks[3].Detail != "not_checked" {
		t.Fatalf("stale CNAME dns = %+v err=%v", detail.AccessReadiness.Checks[3], err)
	}

	// Another tenant cannot check (or learn of) the site.
	if _, err := store.CheckAccessNow(ctx, f.b.siteActor(), id, resolver); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant check err=%v", err)
	}
	if _, err := store.CheckAccessNow(ctx, f.a.siteActor(), uuid.New(), resolver); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown site err=%v", err)
	}
}

// fix-readiness2（PG，写好不跑）：①线路组在线节点只算已对外发布的端点（未发布的备用节点在线也不算）；
// ②解析目标只含已发布端点 IP；③最近一次发布不含本站 = 未发布，含本站才看节点回执。
func TestSiteAccessReadinessPublishedFactsPostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	created, err := f.createSite(f.a, f.a, "published.example.test")
	if err != nil {
		t.Fatal(err)
	}
	siteID, scope, user := created.Site.ID, f.a.scopeID, f.a.userID
	group, primary, standby := uuid.New(), uuid.New(), uuid.New()
	replica := func(statements ...func(tx pgx.Tx) error) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			for _, statement := range statements {
				if err := statement(tx); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sql := func(query string, args ...any) func(tx pgx.Tx) error {
		return func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }
	}
	online := func(node uuid.UUID) func(tx pgx.Tx) error {
		return sql(`INSERT INTO node_presence(node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,
			occurred_at,projected_at,last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,confirmed_event_id,
			confirmed_request_id,confirmed_payload_digest,online_since,openresty_state,firewall_state,
			filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,updated_at)
			VALUES($1,'online',1,1,$2,$3,$4,$5,$5,$5,1,1,$2,$3,$4,$5,'running','running',100,50,0,$5)`, node, uuid.New(), uuid.New(), make([]byte, 32), f.now)
	}
	// The site's own line group: primary .51 (priority 0) and standby .52 (priority 1).
	replica(
		sql(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES
			($1,$3,'primary','active',$4,901,'192.0.2.51'),($2,$3,'standby','active',$4,902,'192.0.2.52')`, primary, standby, scope, user),
		sql(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
			updated_at,display_id,resolved_value,ipv4_resolved_value) VALUES($1,$2,'readiness',1,$3,$3,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
			group, scope, user),
		sql(`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,probe_interval_ms,
			probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,
			created_by_user_id,created_at,sealed_at) VALUES($1,$2,1,'readiness','lg-'||replace($1::uuid::text,'-',''),
			'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,2,$3,$4,now(),now())`, group, scope, make([]byte, 32), user),
		sql(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled) VALUES
			(gen_random_uuid(),$1,$3,$4,1,'192.0.2.51',4,80,'hk','bgp',0,1,true),
			(gen_random_uuid(),$2,$3,$4,1,'192.0.2.52',4,80,'hk','bgp',1,1,true)`, primary, standby, scope, group),
		sql(`UPDATE sites SET node_group_id=$2 WHERE id=$1`, siteID, group),
		online(standby),
	)
	facts := func() *accessFacts {
		t.Helper()
		loaded, err := loadAccessFacts(ctx, f.pool, []uuid.UUID{siteID}, f.now.Add(-time.Minute))
		if err != nil || loaded[siteID] == nil {
			t.Fatalf("load facts=%v err=%v", loaded, err)
		}
		return loaded[siteID]
	}
	// ① Only the unpublished standby is online: the primary is published (it is not held), so no usable line.
	if got := facts(); !got.LineGroupFound || got.OnlineNodes != 0 {
		t.Fatalf("standby-only online nodes=%d found=%v, want 0", got.OnlineNodes, got.LineGroupFound)
	}
	replica(online(primary))
	if got := facts(); got.OnlineNodes != 1 {
		t.Fatalf("primary online nodes=%d, want 1 (the standby stays unpublished)", got.OnlineNodes)
	}
	// ② The DNS target holds only the published primary address, not the standby.
	var target dnsTarget
	if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		var found bool
		target, found, err = f.sites.store.loadDNSTarget(ctx, tx, siteID)
		if !found && err == nil {
			t.Fatal("site has no DNS target")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(target.Expected) != 1 || target.Expected[0] != "192.0.2.51" {
		t.Fatalf("expected addresses=%v, want only the published primary", target.Expected)
	}

	// ③ A publication of the scope that does not carry the site: not published, whatever its rollout did.
	sourceRevision := 0
	publish := func(carries bool, state string) {
		t.Helper()
		version, rollout, digest := uuid.New(), uuid.New(), make([]byte, 32)
		sourceRevision++ // one publication per (scope, source revision)
		statements := []func(tx pgx.Tx) error{
			sql(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,'\x01',$3,'readiness','1','releasable',$4,$3,$5,$5)`, version, scope, digest, "ready-"+version.String(), f.now),
			sql(`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
				correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
				expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
				VALUES(gen_random_uuid(),$1,$8,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,1,$6,$8,'explicit',$3,1,$7,$1)`,
				scope, "ready-"+rollout.String(), digest, version, rollout, f.now, user, sourceRevision),
			sql(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
				command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES(gen_random_uuid(),$1,$2,1,$3,'apply',$4,gen_random_uuid(),'\x01',$5,$6::timestamptz+interval '1 hour',$6,$6,$7)`,
				rollout, primary, version, state, digest, f.now, scope),
		}
		if carries {
			statements = append(statements, sql(`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id)
				VALUES($1,$2)`, version, siteID))
		}
		replica(statements...)
		f.now = f.now.Add(time.Second)
	}
	publish(false, "healthy")
	if got := facts(); got.PublishState != publishExcluded {
		t.Fatalf("publication without the site: state=%q, want %q", got.PublishState, publishExcluded)
	}
	publish(true, "healthy")
	if got := facts(); got.PublishState != "succeeded" {
		t.Fatalf("publication carrying the site: state=%q, want succeeded", got.PublishState)
	}
	// A later publication that drops the site makes it not published again.
	publish(false, "healthy")
	readiness := buildAccessReadiness(*facts(), f.now)
	if published := readiness.Checks[5]; published.Code != AccessCheckPublished || published.OK || published.Detail != "site_not_in_publication" {
		t.Fatalf("dropped site published check = %+v", published)
	}
}
