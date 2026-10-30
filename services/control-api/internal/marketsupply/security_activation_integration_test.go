package marketsupply

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/securityactivation"
	"github.com/cdnca/cdnca/services/control-api/internal/securityiplist"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordingActivations stands in for securityactivation.Store: it records
// Start and reports a candidate for every started version, so the test can
// watch when the leaf starts an activation and what it reports.
type recordingActivations struct {
	mu      sync.Mutex
	kinds   map[uuid.UUID]string // policy ID -> kind, filled once the policies exist
	starts  []securityactivation.StartInput
	status  map[string]securityactivation.CandidateStatus
	active  map[string]int64
	started chan struct{}
}

func (r *recordingActivations) Start(_ context.Context, actor securitypolicy.Actor,
	input securityactivation.StartInput,
) (securityactivation.StartResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if actor.ScopeID != input.TenantScopeID || actor.ScopeKind != "tenant" {
		return securityactivation.StartResult{}, securityactivation.ErrPermissionDenied
	}
	r.starts = append(r.starts, input)
	r.status[input.SiteID.String()+input.PolicyID.String()] = securityactivation.StatusCanary
	select {
	case r.started <- struct{}{}:
	default:
	}
	return securityactivation.StartResult{}, nil
}

func (r *recordingActivations) Status(_ context.Context, _ securitypolicy.Actor, siteID uuid.UUID,
	kind string,
) (securityactivation.StatusResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result securityactivation.StatusResult
	for _, input := range r.starts {
		if input.SiteID != siteID || r.kinds[input.PolicyID] != kind {
			continue
		}
		key := siteID.String() + input.PolicyID.String()
		result.Binding = &securityactivation.Binding{PolicyID: input.PolicyID, ActivePolicyVersion: r.active[key]}
		result.LatestCandidate = &securityactivation.Candidate{Status: r.status[key],
			LastClaimedPolicyVersion: input.PolicyVersion}
	}
	return result, nil
}

// TestLeafSecurityActivatesOnceNodesCarryTheSite commits a site with an
// access list and a rate limit, then lets the seller's node run the tenant's
// configuration: the commit only writes the policies, and the node becoming
// current starts both activations through the notification, on the delivery
// nodes with a canary of one, exactly once.
func TestLeafSecurityActivatesOnceNodesCarryTheSite(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, func() time.Time { return now })
	activations := &recordingActivations{kinds: map[uuid.UUID]string{}, status: map[string]securityactivation.CandidateStatus{},
		active: map[string]int64{}, started: make(chan struct{}, 4)}
	svc.WithSecurity(securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)), activations)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 1},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}
	leafSite := insertTenantSite(t, tenant, "sec-"+uuid.NewString()[:8]+".example.cn")

	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.cn"}, HTTPPorts: []int{80},
		Origins:   []siteconf.Origin{{Host: "203.0.113.20", Port: 80}},
		Access:    json.RawMessage(`{"default":"block","rules":[{"cidr":"198.51.100.0/24","action":"allow"}]}`),
		RateLimit: json.RawMessage(`{"rules":[{"window_seconds":60,"max_requests":600}]}`)}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if blockers := svc.blockers(ctx, g, tenant, nil, uuid.Nil, cfg); len(blockers) != 1 || blockers[0].Code != "leaf_cname_unconfigured" {
		t.Fatalf("wired security still blocked: %+v", blockers)
	}
	request := siteconf.CommitRequest{SiteID: uuid.New(), Revision: 1, Config: cfg}
	for range 2 { // a retried commit writes nothing new
		if err := svc.applySecurity(ctx, tenant, leafSite, request); err != nil {
			t.Fatalf("apply security: %v", err)
		}
	}
	for _, kind := range []string{securitypolicy.KindACL, securitypolicy.KindCC} {
		var id uuid.UUID
		var revision int64
		if err := pool.QueryRow(ctx, `SELECT id, revision FROM security_policies WHERE scope_id=$1 AND name=$2 AND kind=$3`,
			tenant.scopeID, leafPolicyName(kind, leafSite), kind).Scan(&id, &revision); err != nil || revision != 1 {
			t.Fatalf("%s policy revision=%d err=%v", kind, revision, err)
		}
		activations.mu.Lock()
		activations.kinds[id] = kind
		activations.mu.Unlock()
	}
	// Committed, but no node runs the tenant's configuration yet.
	if started, err := svc.ReconcileSecurity(ctx, nil); err != nil || started != 0 {
		t.Fatalf("reconcile before delivery: started=%d err=%v", started, err)
	}
	states, err := svc.securityStatus(ctx, tenant, leafSite)
	if err != nil || len(states) != 2 || states[0].State != securityWaitingNodes || states[1].State != securityWaitingNodes {
		t.Fatalf("status before delivery %+v %v", states, err)
	}

	// The reconciler's tick is a minute, so only the notification can wake it in time.
	loop, stop := context.WithCancel(ctx)
	defer stop()
	go func() { _ = svc.RunSecurityReconciler(loop, edgestatus.NodeConfigCurrentChannel, t.Logf) }()
	time.Sleep(time.Second) // let the listener subscribe
	var node uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT node_id FROM node_line_endpoints WHERE line_group_id=$1`, poolID).Scan(&node); err != nil {
		t.Fatal(err)
	}
	version := uuid.New()
	digest := sha256.Sum256([]byte(version.String()))
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,'\x01',$3,'test','1','releasable',$4,$3,now(),now())`,
				[]any{version, tenant.scopeID, digest[:], "sec-" + version.String()[:8]}},
			{`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
				VALUES($1,$2,$3,now())`, []any{node, tenant.scopeID, version}},
			// What edgestatus sends when a deployment of the scope turns healthy.
			{`SELECT pg_notify($1,$2)`, []any{edgestatus.NodeConfigCurrentChannel, tenant.scopeID.String()}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return fmt.Errorf("%.60s: %w", statement.query, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(20 * time.Second)
	for count := 0; count < 2; {
		select {
		case <-activations.started:
			count++
		case <-deadline:
			t.Fatalf("activations started after the node became current: %d", count)
		}
	}
	stop()
	activations.mu.Lock()
	starts := append([]securityactivation.StartInput(nil), activations.starts...)
	activations.mu.Unlock()
	for _, input := range starts {
		if input.TenantScopeID != tenant.scopeID || input.SiteID != leafSite || input.PolicyVersion != 1 ||
			input.CanarySize != 1 || len(input.TargetNodeIDs) != 1 || input.TargetNodeIDs[0] != node ||
			!input.ExpiresAt.After(now) {
			t.Fatalf("start %+v", input)
		}
	}
	// A started activation is not started again.
	if started, err := svc.ReconcileSecurity(ctx, nil); err != nil || started != 0 {
		t.Fatalf("reconcile while activating: started=%d err=%v", started, err)
	}
	states, err = svc.securityStatus(ctx, tenant, leafSite)
	if err != nil || len(states) != 2 || states[0].State != securityActivating {
		t.Fatalf("status while activating %+v %v", states, err)
	}
	activations.mu.Lock()
	for key := range activations.status {
		activations.active[key] = 1
	}
	activations.mu.Unlock()
	if states, _ = svc.securityStatus(ctx, tenant, leafSite); states[0].State != securityActive || states[1].State != securityActive {
		t.Fatalf("status once promoted %+v", states)
	}
}

// A policy whose nodes never carry the site is reported failed after the
// wait; the reason says which part is missing.
func TestLeafPolicyStateTimesOut(t *testing.T) {
	now := time.Now().UTC()
	waiting := leafPolicy{kind: securitypolicy.KindACL, version: 2, updatedAt: now.Add(-10 * time.Minute),
		deliveryNodes: []uuid.UUID{uuid.New()}}
	if got := waiting.state(securityactivation.StatusResult{}, now); got.State != securityWaitingNodes {
		t.Fatalf("within the wait: %+v", got)
	}
	stale := waiting
	stale.updatedAt = now.Add(-securityActivationWait - time.Minute)
	if got := stale.state(securityactivation.StatusResult{}, now); got.State != securityFailed || got.Reason != "nodes_not_current" {
		t.Fatalf("after the wait: %+v", got)
	}
	stale.deliveryNodes = nil
	if got := stale.state(securityactivation.StatusResult{}, now); got.Reason != "no_delivery_nodes" {
		t.Fatalf("no delivery nodes: %+v", got)
	}
	failed := securityactivation.StatusResult{LatestCandidate: &securityactivation.Candidate{
		Status: securityactivation.StatusFailed, LastClaimedPolicyVersion: 2}}
	if got := waiting.state(failed, now); got.State != securityFailed || got.Reason != "activation_failed" {
		t.Fatalf("failed candidate: %+v", got)
	}
	if partial := (leafPolicy{deliveryNodes: []uuid.UUID{uuid.New(), uuid.New()}}); partial.targets() != nil {
		t.Fatal("started before every delivery node carried the site")
	}
}

// fix-mktsiteconf2 ②: a waf block becomes the leaf site's WAF policy (one
// revision, a retried commit adds none) and the reconciler manages it as it
// does the ACL and CC policies.
func TestLeafWAFPolicyFromSiteconf(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, func() time.Time { return now })
	activations := &recordingActivations{kinds: map[uuid.UUID]string{}, status: map[string]securityactivation.CandidateStatus{},
		active: map[string]int64{}, started: make(chan struct{}, 4)}
	svc.WithSecurity(securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)), activations)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 1},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}
	leafSite := insertTenantSite(t, tenant, "waf-"+uuid.NewString()[:8]+".example.cn")
	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.cn"}, HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: "203.0.113.20", Port: 80}},
		WAF: json.RawMessage(`{"default_action":"allow","waf_settings":{"mode":"observe"},"rules":[{"name":"sqli","priority":1,` +
			`"enabled":true,"action":"block","flow":"stop","action_config":{},"conditions":[{"field":"query","operator":"contains","values":["union select"]}]}]}`)}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if blockers := svc.blockers(ctx, g, tenant, nil, uuid.Nil, cfg); len(blockers) != 1 || blockers[0].Code != "leaf_cname_unconfigured" {
		t.Fatalf("waf blocked: %+v", blockers)
	}
	request := siteconf.CommitRequest{SiteID: uuid.New(), Revision: 1, Config: cfg}
	for range 2 {
		if err := svc.applySecurity(ctx, tenant, leafSite, request); err != nil {
			t.Fatalf("apply security: %v", err)
		}
	}
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT revision FROM security_policies WHERE scope_id=$1 AND name=$2 AND kind='waf'`,
		tenant.scopeID, leafPolicyName(securitypolicy.KindWAF, leafSite)).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("waf policy revision=%d err=%v", revision, err)
	}
	if policies, err := svc.loadLeafPolicies(ctx, &tenant.scopeID, &leafSite); err != nil || len(policies) != 1 || policies[0].kind != "waf" {
		t.Fatalf("leaf policies %+v %v", policies, err)
	}
}

// fix-mktsiteconf3 ①: a cc block (challenge, leaky bucket, auto switch,
// trusted crawler) becomes the leaf site's CC policy; re-applying the same
// block, whose stored switch rules carry derived IDs, writes nothing.
func TestLeafCCPolicyFromSiteconf(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, func() time.Time { return now })
	activations := &recordingActivations{kinds: map[uuid.UUID]string{}, status: map[string]securityactivation.CandidateStatus{},
		active: map[string]int64{}, started: make(chan struct{}, 4)}
	svc.WithSecurity(securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)), activations)
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 1},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}
	leafSite := insertTenantSite(t, tenant, "cc-"+uuid.NewString()[:8]+".example.cn")
	block := siteCC{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{challengeRule(), bucketRule()},
		CCSettings: &securitypolicy.CCSettings{
			BanSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: 1200},
			AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom, QPSTotal: 500, RecoverSeconds: 300,
				RuleGroups: []string{}, Rules: []securitypolicy.Rule{bucketRule()}},
			TrustedCrawlers: []securitypolicy.CCTrustedCrawler{{Name: "googlebot", UserAgentTokens: []string{"Googlebot"},
				RDNSSuffixes: []string{"googlebot.com"}}}}}
	cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.cn"}, HTTPPorts: []int{80},
		Origins: []siteconf.Origin{{Host: "203.0.113.20", Port: 80}}}
	cfg.CC, _ = json.Marshal(block)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if blockers := svc.blockers(ctx, g, tenant, nil, uuid.Nil, cfg); len(blockers) != 1 || blockers[0].Code != "leaf_cname_unconfigured" {
		t.Fatalf("cc blocked: %+v", blockers)
	}
	request := siteconf.CommitRequest{SiteID: uuid.New(), Revision: 1, Config: cfg}
	for range 2 {
		if err := svc.applySecurity(ctx, tenant, leafSite, request); err != nil {
			t.Fatalf("apply security: %v", err)
		}
	}
	var revision int64
	var settings []byte
	if err := pool.QueryRow(ctx, `SELECT revision, cc_settings FROM security_policies WHERE scope_id=$1 AND name=$2 AND kind='cc'`,
		tenant.scopeID, leafPolicyName(securitypolicy.KindCC, leafSite)).Scan(&revision, &settings); err != nil || revision != 1 {
		t.Fatalf("cc policy revision=%d err=%v", revision, err)
	}
	var stored securitypolicy.CCSettings
	if err := json.Unmarshal(settings, &stored); err != nil || stored.AutoSwitch == nil || !stored.AutoSwitch.Active() ||
		stored.BanSeconds == nil || stored.BanSeconds.Seconds != 1200 || len(stored.TrustedCrawlers) != 1 {
		t.Fatalf("stored settings %s %v", settings, err)
	}
	if policies, err := svc.loadLeafPolicies(ctx, &tenant.scopeID, &leafSite); err != nil || len(policies) != 1 || policies[0].kind != "cc" {
		t.Fatalf("leaf policies %+v %v", policies, err)
	}
}

// fix-mktsiteconf3 ⑥: a WAF rule naming a carried IP list runs against the
// leaf tenant's own copy of the list; a changed list updates that copy.
func TestLeafWAFIPListFromSiteconf(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	now := time.Now().UTC()
	svc := newTestService(t, pool, func() time.Time { return now })
	activations := &recordingActivations{kinds: map[uuid.UUID]string{}, status: map[string]securityactivation.CandidateStatus{},
		active: map[string]int64{}, started: make(chan struct{}, 4)}
	svc.WithSecurity(securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, time.Now)), activations)
	svc.WithWAFExtras(sitecrs.NewStore(pool, time.Now), securityiplist.NewStore(pool, time.Now))
	actor, err := svc.ensureActor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	poolID := insertLineGroup(t, pool, platform, actor.userID)
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(),
		SubscriptionPath: []uuid.UUID{uuid.New()}, NodePoolRef: poolID.String(),
		Limits:         spec.LimitSet{{Metric: spec.MetricDomains, Cap: 2, Action: spec.ActionRejectNew}},
		LoadThresholds: spec.DefaultLoadFloor, Tags: spec.Tags{CCProtection: spec.CCNone, Tenancy: spec.TenancyShared},
		Allocation: spec.Allocation{HTTPPorts: 1},
		IssuedAt:   now.Add(-time.Hour).Unix(), NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(24 * time.Hour).Unix()}
	mustSync(t, svc, g)
	tenant, err := svc.ensureTenant(ctx, actor, Key(g))
	if err != nil {
		t.Fatal(err)
	}
	leafSite := insertTenantSite(t, tenant, "ipl-"+uuid.NewString()[:8]+".example.cn")
	subscriberList := uuid.NewString()
	apply := func(cidrs ...string) uuid.UUID {
		t.Helper()
		rule := sqliRule()
		rule.Conditions = []securitypolicy.Condition{{Field: "ip_list", Operator: "in_ip_list", Values: []string{subscriberList}}}
		cfg := siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"www.example.cn"}, HTTPPorts: []int{80},
			Origins: []siteconf.Origin{{Host: "203.0.113.20", Port: 80}}}
		cfg.WAF, _ = json.Marshal(siteWAF{DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{rule},
			IPLists: map[string]siteIPList{subscriberList: {Name: "bad bots", CIDRs: cidrs}}})
		if err := cfg.Normalize(); err != nil {
			t.Fatal(err)
		}
		if blockers := svc.blockers(ctx, g, tenant, nil, uuid.Nil, cfg); len(blockers) != 1 || blockers[0].Code != "leaf_cname_unconfigured" {
			t.Fatalf("waf blocked: %+v", blockers)
		}
		if err := svc.applySecurity(ctx, tenant, leafSite, siteconf.CommitRequest{SiteID: uuid.New(), Revision: 1, Config: cfg}); err != nil {
			t.Fatalf("apply security: %v", err)
		}
		var document []byte
		if err := pool.QueryRow(ctx, `SELECT version.document FROM security_policies policy
			JOIN security_policy_versions version ON version.policy_id=policy.id AND version.revision=policy.revision
			WHERE policy.scope_id=$1 AND policy.name=$2`, tenant.scopeID, leafPolicyName(securitypolicy.KindWAF, leafSite)).Scan(&document); err != nil {
			t.Fatal(err)
		}
		var policy securitypolicy.Policy
		if err := json.Unmarshal(document, &policy); err != nil {
			t.Fatal(err)
		}
		ids := securitypolicy.IPListReferences(policy.Rules)
		if len(ids) != 1 || ids[0].String() == subscriberList {
			t.Fatalf("rule names %v", ids)
		}
		return ids[0]
	}
	first := apply("192.0.2.0/24")
	second := apply("192.0.2.0/24", "198.51.100.7")
	var entries []string
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT entries, revision FROM security_ip_lists WHERE id=$1 AND owner_scope_id=$2`,
		first, tenant.scopeID).Scan(&entries, &revision); err != nil || first != second || revision != 2 || len(entries) != 2 {
		t.Fatalf("leaf list %v rev %d entries %v err %v", second, revision, entries, err)
	}
}
