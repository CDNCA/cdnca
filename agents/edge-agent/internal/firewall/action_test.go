package firewall

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

const (
	actionTenantID = "11111111-1111-4111-8111-111111111111"
	actionSiteID   = "22222222-2222-4222-8222-222222222222"
	actionPolicyID = "33333333-3333-4333-8333-333333333333"
)

type recordingActionApplier struct {
	versions []FirewallVersion
	failNext bool
}

func (applier *recordingActionApplier) Apply(_ context.Context, version FirewallVersion) (Result, error) {
	if applier.failNext {
		applier.failNext = false
		return Result{State: StateFailed, RunningVersionUnchanged: true}, errors.New("candidate rejected")
	}
	if _, err := Compile(version); err != nil {
		return Result{}, err
	}
	applier.versions = append(applier.versions, version)
	return Result{State: StateApplied, VersionID: version.VersionID, ActivePolicyVersion: version.PolicyVersion}, nil
}

func actionPolicyJSON(version int, normal string) []byte {
	return actionPolicyJSONWithExpected(version, normal, 0)
}

func actionPolicyJSONWithExpected(version int, normal string, expected uint64) []byte {
	return []byte(`{
  "schema_version":"cdnca.edge.firewall-action/v1",
  "policy_version":` + strconv.Itoa(version) + `,
  "tenant_id":"` + actionTenantID + `",
  "site_id":"` + actionSiteID + `",
  "policy_id":"` + actionPolicyID + `",
  "expected_active_policy_version":` + strconv.FormatUint(expected, 10) + `,
  "normal_action":"` + normal + `",
  "escalated_action":"nftables",
  "engage_threshold":100,
  "recover_threshold":20,
  "recovery_windows":2,
  "block_networks":["198.51.100.0/24","2001:db8:1::/48"],
  "trusted_proxies":["192.0.2.0/24"],
  "trusted_crawlers":[{"name":"search","networks":["203.0.113.0/24"],"user_agent_prefixes":["SearchBot/"]}],
  "return_page":{"status":429,"content_type":"text/html; charset=utf-8","body":"Request limited"}
}`)
}

func newActionEngineForTest(t *testing.T, applier *recordingActionApplier, version int, normal string) *ActionEngine {
	t.Helper()
	engine, err := NewActionEngine(applier, actionPolicyJSON(version, normal))
	if err != nil {
		t.Fatalf("NewActionEngine() error = %v", err)
	}
	return engine
}

func TestActionEngineUnconfiguredHasZeroImpactAndKeepsStateOnBadCandidate(t *testing.T) {
	applier := &recordingActionApplier{}
	engine, err := NewActionEngine(applier, nil)
	if err != nil {
		t.Fatalf("NewActionEngine() error = %v", err)
	}
	decision, err := engine.Observe(context.Background(), ActionObservation{PeerAddress: "198.51.100.9", Load: 1000})
	if err != nil || decision.Action != RequestActionPass || decision.Reason != "policy_unconfigured" || decision.PolicyVersion != 0 || decision.NFTablesActive {
		t.Fatalf("unconfigured decision=%+v error=%v", decision, err)
	}
	if len(applier.versions) != 0 {
		t.Fatalf("unconfigured engine published firewall versions: %+v", applier.versions)
	}
	if err := engine.ApplyCandidate(context.Background(), []byte(`{"schema_version":"cdnca.edge.firewall-action/v1","policy_version":1}`)); !errors.Is(err, ErrInvalidActionPolicy) {
		t.Fatalf("bad first candidate error=%v", err)
	}
	decision, err = engine.Observe(context.Background(), ActionObservation{PeerAddress: "198.51.100.9", Load: 1000})
	if err != nil || decision.Action != RequestActionPass || decision.Reason != "policy_unconfigured" || engine.ActivePolicyVersion() != 0 {
		t.Fatalf("bad candidate changed unconfigured state: decision=%+v error=%v", decision, err)
	}
	if err := engine.ApplyCandidate(context.Background(), actionPolicyJSON(1, "disconnect")); err != nil {
		t.Fatalf("first valid candidate error=%v", err)
	}
	if got := engine.ActivePolicyVersion(); got != 1 {
		t.Fatalf("active policy version=%d", got)
	}
}

func TestActionEngineExcludesTrustedNetworksFromKernelDenyWithoutBypass(t *testing.T) {
	applier := &recordingActionApplier{}
	candidate := strings.Replace(
		string(actionPolicyJSON(1, "disconnect")),
		`"block_networks":["198.51.100.0/24","2001:db8:1::/48"]`,
		`"block_networks":["192.0.2.0/24","198.51.100.0/24","203.0.113.0/24"]`,
		1,
	)
	engine, err := NewActionEngine(applier, []byte(candidate))
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Observe(context.Background(), ActionObservation{PeerAddress: "198.51.100.9", Load: 100})
	if err != nil || decision.Action != RequestActionDisconnect || !decision.NFTablesActive {
		t.Fatalf("engage decision=%+v error=%v", decision, err)
	}
	if len(applier.versions) != 1 || len(applier.versions[0].Entries) != 1 || applier.versions[0].Entries[0].Network != "198.51.100.0/24" {
		t.Fatalf("trusted networks reached kernel deny: %+v", applier.versions)
	}

	protectedOnly := strings.Replace(
		candidate,
		`"block_networks":["192.0.2.0/24","198.51.100.0/24","203.0.113.0/24"]`,
		`"block_networks":["192.0.2.0/24","203.0.113.0/24"]`,
		1,
	)
	secondApplier := &recordingActionApplier{}
	second, err := NewActionEngine(secondApplier, []byte(protectedOnly))
	if err != nil {
		t.Fatal(err)
	}
	decision, err = second.Observe(context.Background(), ActionObservation{PeerAddress: "203.0.113.9", UserAgent: "Other/1.0", Load: 100})
	if err != nil || decision.Action != RequestActionDisconnect || decision.Reason != "threshold_engaged_l7_only" || decision.NFTablesActive {
		t.Fatalf("protected-only engage decision=%+v error=%v", decision, err)
	}
	if len(secondApplier.versions) != 1 || len(secondApplier.versions[0].Entries) != 0 {
		t.Fatalf("protected-only candidate did not clear owned kernel set: %+v", secondApplier.versions)
	}
	ipOnly, err := second.Observe(context.Background(), ActionObservation{PeerAddress: "203.0.113.9", UserAgent: "Other/1.0", Load: 100})
	if err != nil || ipOnly.Action != RequestActionDisconnect || ipOnly.NFTablesActive {
		t.Fatalf("crawler network alone bypassed L7 enforcement: decision=%+v error=%v", ipOnly, err)
	}
	trusted, err := second.Observe(context.Background(), ActionObservation{PeerAddress: "203.0.113.9", UserAgent: "SearchBot/1.0", Load: 100})
	if err != nil || trusted.Action != RequestActionPass || trusted.Reason != "trusted_crawler" {
		t.Fatalf("dual-evidence crawler decision=%+v error=%v", trusted, err)
	}
}

func TestActionEngineThresholdEngagesNFTablesAndRecoversWithHysteresis(t *testing.T) {
	applier := &recordingActionApplier{}
	engine := newActionEngineForTest(t, applier, 1, "return_page")
	ctx := context.Background()

	decision, err := engine.Observe(ctx, ActionObservation{PeerAddress: "198.51.100.9", Load: 99})
	if err != nil || decision.Action != RequestActionReturnPage || decision.Reason != "below_engage_threshold" || decision.Page == nil {
		t.Fatalf("below threshold decision=%+v error=%v", decision, err)
	}
	decision, err = engine.Observe(ctx, ActionObservation{PeerAddress: "198.51.100.9", Load: 100})
	if err != nil || decision.Action != RequestActionDisconnect || decision.Reason != "threshold_engaged" || !decision.NFTablesActive {
		t.Fatalf("engage decision=%+v error=%v", decision, err)
	}
	if len(applier.versions) != 1 || len(applier.versions[0].Entries) != 2 {
		t.Fatalf("engage versions=%+v", applier.versions)
	}
	engage := applier.versions[0]
	if engage.TenantID != actionTenantID || engage.SiteID != actionSiteID || engage.PolicyKind != "global" || engage.PolicyID != actionPolicyID ||
		engage.PolicyVersion != 1 || engage.ExpectedActivePolicyVersion != 0 || engage.TaskRevision != 1 ||
		engage.Operation != OperationApply || engage.RecoveryReason != RecoveryReasonNotApplicable ||
		!canonicalUUID(engage.IdempotencyKey) || !validDigest(engage.CommandDigest) {
		t.Fatalf("engage command is not scoped CAS: %+v", engage)
	}
	for _, entry := range engage.Entries {
		if entry.TenantID != actionTenantID || entry.SiteID != actionSiteID {
			t.Fatalf("engage entry lost scope: %+v", entry)
		}
	}
	compiled, err := Compile(applier.versions[0])
	if err != nil {
		t.Fatal(err)
	}
	batch := string(compiled.Batch)
	if !strings.Contains(batch, "@deny_v4") || !strings.Contains(batch, "@deny_v6") || !strings.Contains(batch, "198.51.100.0/24") {
		t.Fatalf("nftables candidate missing owned IP sets:\n%s", batch)
	}

	decision, err = engine.Observe(ctx, ActionObservation{PeerAddress: "198.51.100.9", Load: 20})
	if err != nil || decision.Action != RequestActionDisconnect || decision.Reason != "recovery_pending" {
		t.Fatalf("first recovery decision=%+v error=%v", decision, err)
	}
	decision, err = engine.Observe(ctx, ActionObservation{PeerAddress: "198.51.100.9", Load: 20})
	if err != nil || decision.Action != RequestActionReturnPage || decision.Reason != "threshold_recovered" || decision.NFTablesActive {
		t.Fatalf("recovered decision=%+v error=%v", decision, err)
	}
	if len(applier.versions) != 2 || len(applier.versions[1].Entries) != 0 {
		t.Fatalf("recovery did not publish an empty owned set: %+v", applier.versions)
	}
	recover := applier.versions[1]
	if recover.TenantID != actionTenantID || recover.SiteID != actionSiteID || recover.PolicyKind != "global" || recover.PolicyID != actionPolicyID ||
		recover.PolicyVersion != 2 || recover.ExpectedActivePolicyVersion != 1 || recover.TaskRevision != 2 ||
		recover.Operation != OperationApply || recover.RecoveryReason != RecoveryReasonNotApplicable || !validDigest(recover.CommandDigest) {
		t.Fatalf("recovery command is not scoped CAS: %+v", recover)
	}

	secondApplier := &recordingActionApplier{}
	second := newActionEngineForTest(t, secondApplier, 1, "return_page")
	if _, err := second.Observe(ctx, ActionObservation{PeerAddress: "198.51.100.9", Load: 100}); err != nil {
		t.Fatal(err)
	}
	if secondApplier.versions[0].CommandDigest != engage.CommandDigest || secondApplier.versions[0].IdempotencyKey != engage.IdempotencyKey {
		t.Fatal("equivalent scoped action command did not produce stable identity")
	}
}

type forwardingActionApplier struct {
	manager  *Manager
	versions []FirewallVersion
}

func (applier *forwardingActionApplier) Apply(ctx context.Context, version FirewallVersion) (Result, error) {
	applier.versions = append(applier.versions, version)
	return applier.manager.Apply(ctx, version)
}

func TestActionEngineScopedPublicationPreservesExistingACLScope(t *testing.T) {
	runner := &fakeRunner{}
	manager := newTestManager(t, testStateRoot(t), runner, fixedTime)
	acl := scopedVersion("existing-acl", "44444444-4444-4444-8444-444444444444", actionTenantID, actionSiteID, 1, 0, "192.0.2.55")
	if result, err := manager.Apply(context.Background(), acl); err != nil || result.State != StateApplied {
		t.Fatalf("seed ACL result=%+v error=%v", result, err)
	}
	applier := &forwardingActionApplier{manager: manager}
	engine, err := NewActionEngine(applier, actionPolicyJSON(1, "return_page"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Observe(context.Background(), ActionObservation{PeerAddress: "198.51.100.9", Load: 100}); err != nil {
		t.Fatal(err)
	}
	if len(applier.versions) != 1 || applier.versions[0].PolicyKind != "global" || len(applier.versions[0].Entries) != 2 {
		t.Fatalf("SEC-06 command=%+v", applier.versions)
	}
	for _, entry := range applier.versions[0].Entries {
		if entry.Network == "192.0.2.55/32" {
			t.Fatal("SEC-06 command copied the preexisting ACL scope")
		}
	}
	active, err := manager.store.loadActive()
	if err != nil || active == nil || len(active.Scopes) != 2 {
		t.Fatalf("active scopes=%+v error=%v", active, err)
	}
	batch := runner.lastBatch()
	if !strings.Contains(batch, "192.0.2.55/32") || !strings.Contains(batch, "198.51.100.0/24") {
		t.Fatalf("aggregate runtime lost ACL or SEC-06 scope:\n%s", batch)
	}
}

func TestActionEngineTrustedProxyOnlyResolvesSourceAndCrawlerRequiresDualEvidence(t *testing.T) {
	applier := &recordingActionApplier{}
	engine := newActionEngineForTest(t, applier, 1, "disconnect")
	ctx := context.Background()

	proxyOnly, err := engine.Observe(ctx, ActionObservation{
		PeerAddress: "192.0.2.8", ForwardedFor: []string{"198.51.100.12"}, UserAgent: "SearchBot/1.0", Load: 1,
	})
	if err != nil || proxyOnly.ClientAddress != "198.51.100.12" || proxyOnly.Action != RequestActionDisconnect {
		t.Fatalf("trusted proxy incorrectly bypassed: decision=%+v error=%v", proxyOnly, err)
	}

	uaOnly, err := engine.Observe(ctx, ActionObservation{PeerAddress: "198.51.100.12", UserAgent: "SearchBot/1.0", Load: 1})
	if err != nil || uaOnly.Action != RequestActionDisconnect {
		t.Fatalf("crawler UA alone bypassed: decision=%+v error=%v", uaOnly, err)
	}
	ipOnly, err := engine.Observe(ctx, ActionObservation{PeerAddress: "203.0.113.12", UserAgent: "Other/1.0", Load: 1})
	if err != nil || ipOnly.Action != RequestActionDisconnect {
		t.Fatalf("crawler network alone bypassed: decision=%+v error=%v", ipOnly, err)
	}
	trusted, err := engine.Observe(ctx, ActionObservation{PeerAddress: "203.0.113.12", UserAgent: "SearchBot/1.0", Load: 1000})
	if err != nil || trusted.Action != RequestActionPass || trusted.Reason != "trusted_crawler" || len(applier.versions) != 0 {
		t.Fatalf("dual-evidence crawler decision=%+v error=%v versions=%d", trusted, err, len(applier.versions))
	}
}

func TestActionEngineBadPolicyAndBadNFTCandidateKeepLKG(t *testing.T) {
	applier := &recordingActionApplier{}
	engine := newActionEngineForTest(t, applier, 1, "return_page")

	if err := engine.ApplyCandidate(context.Background(), []byte(`{"schema_version":"cdnca.edge.firewall-action/v1","policy_version":2}`)); !errors.Is(err, ErrInvalidActionPolicy) {
		t.Fatalf("bad candidate error=%v", err)
	}
	if got := engine.ActivePolicyVersion(); got != 1 {
		t.Fatalf("bad candidate replaced LKG: version=%d", got)
	}

	if _, err := engine.Observe(context.Background(), ActionObservation{PeerAddress: "198.51.100.9", Load: 100}); err != nil {
		t.Fatal(err)
	}
	if err := engine.ApplyCandidate(context.Background(), actionPolicyJSON(2, "disconnect")); !errors.Is(err, ErrActionActiveVersionConflict) {
		t.Fatalf("stale CAS candidate error=%v", err)
	}
	applier.failNext = true
	if err := engine.ApplyCandidate(context.Background(), actionPolicyJSONWithExpected(2, "disconnect", 1)); !errors.Is(err, ErrActionApplyFailed) {
		t.Fatalf("bad nft candidate error=%v", err)
	}
	if got := engine.ActivePolicyVersion(); got != 1 {
		t.Fatalf("failed nft candidate replaced LKG: version=%d", got)
	}
	decision, err := engine.Observe(context.Background(), ActionObservation{PeerAddress: "198.51.100.9", Load: 100})
	if err != nil || decision.Action != RequestActionDisconnect || !decision.NFTablesActive {
		t.Fatalf("failed candidate disturbed active LKG: decision=%+v error=%v", decision, err)
	}
}

func TestActionPolicyRejectsUnsafePagesThresholdsAndTrustInputs(t *testing.T) {
	tests := map[string]string{
		"unknown schema":        strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), FirewallActionSchemaV1, "cdnca.edge.firewall-action/v2"),
		"script page":           strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), "Request limited", "<script>alert(1)</script>"),
		"event attribute page":  strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), "Request limited", `<img src=x onerror=alert(1)>`),
		"no hysteresis":         strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), `"recover_threshold":20`, `"recover_threshold":100`),
		"all-network proxy":     strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), `"192.0.2.0/24"`, `"0.0.0.0/0"`),
		"malformed block CIDR":  strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), `"198.51.100.0/24"`, `"198.51.100.0/not-a-prefix"`),
		"UA wildcard":           strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), `"SearchBot/"`, `"*"`),
		"duplicate root key":    strings.Replace(string(actionPolicyJSON(1, "return_page")), `"policy_version":1,`, `"policy_version":1,"policy_version":2,`, 1),
		"duplicate nested key":  strings.Replace(string(actionPolicyJSON(1, "return_page")), `"status":429,`, `"status":429,"status":403,`, 1),
		"unknown root field":    strings.Replace(string(actionPolicyJSON(1, "return_page")), `"policy_version":1,`, `"policy_version":1,"future":true,`, 1),
		"unknown page field":    strings.Replace(string(actionPolicyJSON(1, "return_page")), `"status":429,`, `"status":429,"future":true,`, 1),
		"unknown crawler field": strings.Replace(string(actionPolicyJSON(1, "return_page")), `"name":"search",`, `"name":"search","future":true,`, 1),
		"alternate zero prefix": strings.ReplaceAll(string(actionPolicyJSON(1, "return_page")), `"198.51.100.0/24"`, `"198.51.100.0/00"`),
		"trailing object":       string(actionPolicyJSON(1, "return_page")) + `{}`,
		"trailing garbage":      string(actionPolicyJSON(1, "return_page")) + `not-json`,
	}
	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewActionEngine(&recordingActionApplier{}, []byte(candidate)); !errors.Is(err, ErrInvalidActionPolicy) {
				t.Fatalf("NewActionEngine() error=%v", err)
			}
		})
	}
}

func TestFirewallActionLuaSourceContract(t *testing.T) {
	source, err := os.ReadFile("../../../../edge/openresty/firewallaction/engine.lua")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, fragment := range []string{
		`cdnca.edge.firewall-action/v1`,
		`candidate_rejected_lkg`,
		`ngx.exit(444)`,
		`ngx.header["Cache-Control"] = "no-store"`,
		`trusted_proxy`,
		`trusted_crawler`,
		`recovery_windows`,
		`maximum_index == count`,
		`block_networks = build_matcher(policy.block_networks)`,
		`only_keys(policy, POLICY_KEYS)`,
		`canonical_uuid(policy.tenant_id)`,
		`canonical_uuid(policy.site_id)`,
		`canonical_uuid(policy.policy_id)`,
		`expected_active_policy_version`,
		`only_keys(policy.return_page, RETURN_PAGE_KEYS)`,
		`only_keys(crawler, CRAWLER_KEYS)`,
		`value:find("/0+$")`,
		`unique_json_keys(bytes)`,
		`seen[key]`,
		`item:find("[%s%[%]]")`,
		`escape_html`,
		`<main>`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("Lua engine missing %q", fragment)
		}
	}
	if strings.Contains(text, "X-CDNCA-Verified-Crawler") {
		t.Fatal("spoofable crawler verification header must not be trusted")
	}
	if strings.Contains(text, `item:find("[%s%[%]:]")`) {
		t.Fatal("forwarded IPv6 text must not be rejected solely because it contains colons")
	}
}

// FX45: the runtime state (firewallaction.engine status) drives nftables:
// engage applies the block networks, recovery withdraws them, a repeated
// state is a no-op and a state of another policy is ignored.
func TestActionEngineMirrorFollowsRuntimeStateAndIgnoresOtherPolicies(t *testing.T) {
	applier := &recordingActionApplier{}
	engine := newActionEngineForTest(t, applier, 1, "disconnect")
	state := ActionRuntimeState{TenantID: actionTenantID, SiteID: actionSiteID, PolicyID: actionPolicyID, PolicyVersion: 1}

	if changed, err := engine.Mirror(context.Background(), state); err != nil || changed || len(applier.versions) != 0 {
		t.Fatalf("inactive mirror of an idle engine = %v, %v, %d applies", changed, err, len(applier.versions))
	}
	state.Active = true
	stale := state
	stale.PolicyVersion = 2
	if changed, err := engine.Mirror(context.Background(), stale); err != nil || changed || len(applier.versions) != 0 {
		t.Fatalf("mirror of another policy version = %v, %v", changed, err)
	}
	other := state
	other.TenantID = "44444444-4444-4444-8444-444444444444"
	if changed, _ := engine.Mirror(context.Background(), other); changed {
		t.Fatal("mirror of another tenant's state changed nftables")
	}
	if changed, err := engine.Mirror(context.Background(), state); err != nil || !changed {
		t.Fatalf("engage mirror = %v, %v", changed, err)
	}
	if len(applier.versions) != 1 || len(applier.versions[0].Entries) != 2 || applier.versions[0].PolicyVersion != 1 {
		t.Fatalf("engage published %+v", applier.versions)
	}
	if engine.CanRetire() {
		t.Fatal("an engaged engine can be retired")
	}
	if changed, err := engine.Mirror(context.Background(), state); err != nil || changed || len(applier.versions) != 1 {
		t.Fatalf("repeated engage = %v, %v, %d applies", changed, err, len(applier.versions))
	}
	state.Active = false
	if changed, err := engine.Mirror(context.Background(), state); err != nil || !changed {
		t.Fatalf("recover mirror = %v, %v", changed, err)
	}
	if len(applier.versions) != 2 || len(applier.versions[1].Entries) != 0 || applier.versions[1].ExpectedActivePolicyVersion != 1 {
		t.Fatalf("recover published %+v", applier.versions[len(applier.versions)-1])
	}
	if !engine.CanRetire() {
		t.Fatal("a recovered engine cannot be retired")
	}
}

func TestActionEngineMirrorKeepsStateWhenNFTablesRejects(t *testing.T) {
	applier := &recordingActionApplier{failNext: true}
	engine := newActionEngineForTest(t, applier, 1, "return_page")
	state := ActionRuntimeState{TenantID: actionTenantID, SiteID: actionSiteID, PolicyID: actionPolicyID, PolicyVersion: 1, Active: true}
	if changed, err := engine.Mirror(context.Background(), state); err == nil || changed {
		t.Fatalf("rejected engage = %v, %v", changed, err)
	}
	if !engine.CanRetire() {
		t.Fatal("a rejected engage left the engine engaged")
	}
	// The next poll retries and succeeds.
	if changed, err := engine.Mirror(context.Background(), state); err != nil || !changed {
		t.Fatalf("retried engage = %v, %v", changed, err)
	}
}

// FX45: the OpenResty engine itself measures the load (blocked requests per
// second), evaluates once per second, and only touches block_networks
// clients while escalated.
func TestFirewallActionLuaMeasuresLoadAndEscalatesOnlyBlockedNetworks(t *testing.T) {
	source, err := os.ReadFile("../../../../edge/openresty/firewallaction/engine.lua")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, fragment := range []string{
		`function _M.handle(path)`,
		`function _M.status_objects(sites, read)`,
		`cdnca.edge.firewall-action-status/v1`,
		`dictionary:incr(state_prefix(policy) .. "blocked:" .. ngx.time(), 1, 0, COUNTER_TTL)`,
		`dictionary:get(prefix .. "blocked:" .. (second - 1))`,
		`dictionary:add(prefix .. "eval:" .. second, true, COUNTER_TTL)`,
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("Lua engine missing %q", fragment)
		}
	}
	handle := text[strings.Index(text, "function _M.handle(path)"):]
	handle = handle[:strings.Index(handle, "\nend\n")]
	// The non-blocked client check precedes the escalated disconnect: an
	// escalated site no longer disconnects every client.
	if strings.Index(handle, `if not matches(compiled.block_networks, client)`) > strings.Index(handle, `execute(policy, "disconnect")`) {
		t.Fatal("escalated disconnect is reached before the block_networks match")
	}
	for _, absent := range []string{`"load:"`, `nftables_active and not matches`} {
		if strings.Contains(text, absent) {
			t.Errorf("Lua engine still contains %q", absent)
		}
	}
}

// scopedActionFirewall records applies and answers ScopeEntries with the
// last applied global scope (FX45 dynamic routing engines read it back).
type scopedActionFirewall struct {
	recordingActionApplier
}

func (fw *scopedActionFirewall) ScopeEntries(_ context.Context, tenantID, siteID, kind, policyID string) (uint64, []Entry, error) {
	if kind != "global" || len(fw.versions) == 0 {
		return 0, nil, nil
	}
	last := fw.versions[len(fw.versions)-1]
	if last.TenantID != tenantID || last.SiteID != siteID || last.PolicyID != policyID {
		return 0, nil, nil
	}
	return last.PolicyVersion, last.Entries, nil
}

// FX45 under dynamic routing: a new engine (agent restart, republished
// policy object) continues from the kernel's scope version and engaged
// state, and Withdraw recovers a site that left the runtime.
func TestRuntimeActionEngineResumesKernelScopeAndWithdraws(t *testing.T) {
	ctx := context.Background()
	fw := &scopedActionFirewall{}
	engine, err := NewRuntimeActionEngine(ctx, fw, actionPolicyJSON(1, "return_page"))
	if err != nil {
		t.Fatal(err)
	}
	state := ActionRuntimeState{TenantID: actionTenantID, SiteID: actionSiteID, PolicyID: actionPolicyID, PolicyVersion: 1, Active: true}
	if changed, err := engine.Mirror(ctx, state); err != nil || !changed {
		t.Fatalf("engage = %v, %v", changed, err)
	}
	// Restart while engaged, the control plane meanwhile published version 2
	// (its expected_active_policy_version knows nothing of the node scope).
	resumed, err := NewRuntimeActionEngine(ctx, fw, actionPolicyJSON(2, "return_page"))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.CanRetire() {
		t.Fatal("resumed engine lost the kernel engagement")
	}
	state.PolicyVersion = 2
	if changed, err := resumed.Mirror(ctx, state); err != nil || changed {
		t.Fatalf("repeated engage after resume = %v, %v", changed, err)
	}
	if changed, err := resumed.Withdraw(ctx); err != nil || !changed {
		t.Fatalf("withdraw = %v, %v", changed, err)
	}
	last := fw.versions[len(fw.versions)-1]
	if len(fw.versions) != 2 || len(last.Entries) != 0 || last.ExpectedActivePolicyVersion != 1 || last.PolicyVersion != 2 {
		t.Fatalf("withdraw published %+v", fw.versions)
	}
	if changed, err := resumed.Withdraw(ctx); err != nil || changed {
		t.Fatalf("second withdraw = %v, %v", changed, err)
	}
	if _, err := NewRuntimeActionEngine(ctx, fw, []byte(`{}`)); !errors.Is(err, ErrInvalidActionPolicy) {
		t.Fatalf("invalid policy error = %v", err)
	}
}
