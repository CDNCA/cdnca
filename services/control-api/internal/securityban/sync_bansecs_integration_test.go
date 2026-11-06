//go:build integration

package securityban_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Automatic bans of a CC auto switch rule, of a rule pack's mounted CC rule and of the
// auto defense overlay's WAF auto block are listed for the node's ban duration, not DefaultBanSeconds.
func TestSecurityBanSyncUsesEachSourcesBanSeconds(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Millisecond)
	site := seedTenant(t, pool, "sbd3-"+uuid.NewString()[:6])

	switched := uuid.New()
	ccPolicy := securitypolicy.Policy{ID: uuid.New(), ScopeID: site.scope, Kind: securitypolicy.KindCC, Enabled: true,
		Rules: []securitypolicy.Rule{}, Revision: 1,
		CCSettings: &securitypolicy.CCSettings{AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom,
			QPSTotal: 100, RecoverSeconds: 300, Rules: []securitypolicy.Rule{{ID: switched, Action: securitypolicy.ActionRateLimit,
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{ResponseAction: "temporary_ban",
					BanSeconds: 60}}}}}}}
	block := uuid.New()
	wafPolicy := securitypolicy.Policy{ID: uuid.New(), ScopeID: site.scope, Kind: securitypolicy.KindWAF, Enabled: true,
		Rules: []securitypolicy.Rule{{ID: block, Action: "block"}}, Revision: 1}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		for _, policy := range []securitypolicy.Policy{ccPolicy, wafPolicy} {
			document, _ := json.Marshal(policy)
			if _, err := tx.Exec(ctx, `INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
				VALUES($1,1,$2,$3,now())`, policy.ID, document, site.owner); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,
				active_policy_version,last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at)
				VALUES($1,$2,$3,$4,$5,1,1,$6,1,now(),now())`, uuid.New(), site.scope, site.site, policy.ID, policy.Kind, uuid.New()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A user rule pack with one CC temporary ban rule (900 s), published on the site.
	packID := "user/" + site.scope.String() + "/d3"
	pack, err := rulepack.Compile([]byte(`{"schema":"cdnca.rule-pack/v1","pack_id":"` + packID + `","version":"1.0.0",` +
		`"layer":"user","engine":"cc_v2","engine_min_version":2,"name":"d3","description":"","params_schema":{},` +
		`"exports":[],"defaults":{},"rules":[{"id":"r1","name":"r1","cc":{"rule_id":"","priority":0,"flow":"stop","match":{},` +
		`"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":10,"window_seconds":10},` +
		`"action":{"kind":"temporary_ban","ban_seconds":900}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: pack, Priority: 500,
		Source: rulepack.Source{EnabledAt: rulepack.LevelRef{Level: rulepack.LevelSite}}}}, rulepack.Target{})
	if resolution.Security == nil {
		t.Fatalf("resolve: %+v", resolution.Conflicts)
	}
	security, _ := json.Marshal(resolution.Security)
	exec(t, pool, `INSERT INTO rule_packs(pack_id,layer,owner_scope_id,current_version,update_policy,created_by_user_id,
		updated_by_user_id,created_at,updated_at) VALUES($1,'user',$2,NULL,'manual',$3,$3,now(),now())`, packID, site.scope, site.owner)
	exec(t, pool, `INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,
		source,state,downloaded_at,created_by_user_id,created_at) VALUES($1,'1.0.0','cc_v2',2,'d3',$2,$3,$4,'tenant','downloaded',now(),$5,now())`,
		packID, pack.SHA256, len(pack.Canonical), pack.Canonical, site.owner)
	exec(t, pool, `INSERT INTO site_security_mounts(site_id,revision,security,resolved_sha256,published_by_user_id,published_at)
		VALUES($1,1,$2,$3,$4,now())`, site.site, security, resolution.Security.ResolvedSHA256, site.owner)

	ingested := now.Add(-time.Minute)
	occurred := now.Add(-10 * time.Second)
	event := func(id, kind, client, rule string) analyticslog.TemporaryBanEvent {
		ingested = ingested.Add(time.Millisecond)
		return analyticslog.TemporaryBanEvent{EventID: id, TenantID: site.tenant.String(), SiteID: site.site.String(), EventType: kind,
			ClientIP: client, RuleID: rule, OccurredAt: occurred, IngestedAt: ingested}
	}
	source := &events{items: []analyticslog.TemporaryBanEvent{
		event("d3-switch", "cc", "198.51.100.31", switched.String()),
		event("d3-pack", "cc", "198.51.100.32", rulepack.NodeRuleID(packID, "r1")),
		event("d3-overlay", "waf", "198.51.100.33", block.String()),
		event("d3-unknown", "cc", "198.51.100.34", uuid.NewString()),
	}}
	syncer, err := securityban.NewSyncer(pool, source, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if result, err := syncer.RunOnce(ctx); err != nil || result.Added != 4 {
		t.Fatalf("sync = %+v, %v", result, err)
	}
	want := map[string]time.Duration{"198.51.100.31": time.Minute, "198.51.100.32": 900 * time.Second,
		"198.51.100.33": securityban.OverlayAutoBlockSeconds * time.Second, "198.51.100.34": securityban.DefaultBanSeconds * time.Second}
	rows, err := pool.Query(ctx, `SELECT host(client_ip),extract(epoch FROM banned_until-banned_at)::bigint FROM security_ban_entries WHERE site_id=$1`, site.site)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]time.Duration{}
	for rows.Next() {
		var client string
		var seconds int64
		if err := rows.Scan(&client, &seconds); err != nil {
			t.Fatal(err)
		}
		got[client] = time.Duration(seconds) * time.Second
	}
	for client, duration := range want {
		if got[client] != duration {
			t.Errorf("%s banned for %s, want %s", client, got[client], duration)
		}
	}
}
