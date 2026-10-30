package securitybinding

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// TestWAFQuickBlockPersistGateAndPublish against the real
// schema: turning a quick block on needs the control plane's IP
// intelligence library; the switches are stored on the policy and its
// version; the system rules lead the policy; the policy editor cannot change
// or drop them; replays are idempotent; the published runtime snapshot runs
// them; turning off strips them (unless they are the only rules).
func TestWAFQuickBlockPersistGateAndPublish(t *testing.T) {
	fixture := newBindingFixture(t)
	pool, tenant := fixture.pool, fixture.tenantA
	actor := tenantActor(tenant)
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(pool, func() time.Time { return bindingTestNow }))
	user := securitypolicy.Rule{Name: "admin", Priority: 10, Enabled: true, Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}}
	created, err := service.Create(t.Context(), actor, securitypolicy.CreateRequest{TargetScopeID: tenant.scopeID,
		OwnerUserID: tenant.userID, Fields: securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "site waf",
			Enabled: true, DefaultAction: securitypolicy.ActionAllow, Rules: []securitypolicy.Rule{user}},
		IdempotencyKey: "qb-create", RequestID: "qb-create"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	policy := created.Policy
	block := securitypolicy.QuickBlock{BlockIDCGlobal: true, Carriers: []string{"carrier:cn-mobile"},
		AllowedCrawlers: []securitypolicy.TrustedCrawler{{Networks: []string{"66.249.64.0/19"}, UserAgentPrefixes: []string{"Googlebot"}}}}
	request := securitypolicy.QuickBlockRequest{ID: policy.ID, ExpectedRevision: policy.Revision, QuickBlock: block,
		IdempotencyKey: "qb-on", RequestID: "qb-on"}

	// No verified library on the control plane yet: refused.
	if revision, err := service.QuickBlockLibraryStatus(t.Context(), actor); err != nil || revision != 0 {
		t.Fatalf("library status = %d, %v", revision, err)
	}
	if _, err := service.SetQuickBlock(t.Context(), actor, request); !errors.Is(err, securitypolicy.ErrQuickBlockIPIntelUnavailable) {
		t.Fatalf("SetQuickBlock without library: %v", err)
	}
	artifactsynctest.SeedDownloaded(t, pool, artifactsynctest.IPIntelBase(7, "ipx-test", strings.Repeat("0", 64), 2),
		bytes.Repeat([]byte{1}, 65))
	if revision, err := service.QuickBlockLibraryStatus(t.Context(), actor); err != nil || revision != 7 {
		t.Fatalf("library status = %d, %v", revision, err)
	}

	on, err := service.SetQuickBlock(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("SetQuickBlock: %v", err)
	}
	if on.Policy.Revision != policy.Revision+1 || on.Policy.QuickBlock == nil || !on.Policy.QuickBlock.BlockIDCGlobal ||
		len(on.Policy.Rules) != 4 || on.Policy.Rules[3].Name != "admin" {
		t.Fatalf("quick block policy = %+v", on.Policy)
	}
	for slot, rule := range on.Policy.Rules[:3] {
		if rule.ID != securitypolicy.QuickBlockRuleID(policy.ID, slot+1) {
			t.Fatalf("system rule %d id %s", slot, rule.ID)
		}
	}
	replayed, err := service.SetQuickBlock(t.Context(), actor, request)
	if err != nil || !replayed.Replayed || replayed.Policy.Revision != on.Policy.Revision {
		t.Fatalf("replay = %+v, %v", replayed, err)
	}
	var document []byte
	var audits int
	if err := pool.QueryRow(t.Context(), `SELECT document FROM security_policy_versions WHERE policy_id=$1 AND revision=$2`,
		policy.ID, on.Policy.Revision).Scan(&document); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='security_policy.quick_block' AND resource_id=$1`,
		policy.ID.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("quick block audit events = %d, %v", audits, err)
	}
	var version securitypolicy.Policy
	if err := json.Unmarshal(document, &version); err != nil || version.QuickBlock == nil || len(version.QuickBlock.Carriers) != 1 {
		t.Fatalf("version document quick block = %+v, %v", version.QuickBlock, err)
	}

	// The editor sends the rules back edited (and drops one): the system
	// rules come back exactly as the switches say.
	edited := make([]securitypolicy.Rule, len(on.Policy.Rules))
	copy(edited, on.Policy.Rules)
	edited[0].Action, edited[0].Enabled = securitypolicy.ActionAllow, false
	edited = append(edited[:1], edited[2:]...)
	updated, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: policy.ID, ExpectedRevision: on.Policy.Revision,
		Fields: securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "site waf", Enabled: true,
			DefaultAction: securitypolicy.ActionAllow, Rules: edited},
		IdempotencyKey: "qb-edit", RequestID: "qb-edit"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	onJSON, _ := json.Marshal(on.Policy.Rules)
	updatedJSON, _ := json.Marshal(updated.Policy.Rules)
	if !bytes.Equal(onJSON, updatedJSON) || updated.Policy.QuickBlock == nil {
		t.Fatalf("editor changed system rules:\nbefore %s\nafter  %s", onJSON, updatedJSON)
	}
	// While on, the policy stays default-allow.
	if _, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: policy.ID, ExpectedRevision: updated.Policy.Revision,
		Fields: securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "site waf", Enabled: true,
			DefaultAction: securitypolicy.ActionBlock, Rules: updated.Policy.Rules},
		IdempotencyKey: "qb-default-block", RequestID: "qb-default-block"}); !errors.Is(err, securitypolicy.ErrQuickBlockUnsupported) {
		t.Fatalf("default block with quick block: %v", err)
	}

	// The published runtime snapshot runs the system rules.
	runtime, err := securitypolicy.CompileRuntimeSnapshot(updated.Policy, tenant.siteID)
	if err != nil || len(runtime.Snapshot.Rules) != 4 || runtime.Snapshot.Rules[0].Action != securitypolicy.ActionBlock {
		t.Fatalf("runtime snapshot = %s, %v", runtime.CanonicalJSON, err)
	}
	store := newBindingStore(t, pool, newRecordingSigner(), &testClock{now: bindingTestNow}, 5*time.Minute)
	publication, err := store.Publish(t.Context(), actor, PublishRequest{TenantScopeID: tenant.scopeID, SiteID: tenant.siteID,
		PolicyID: policy.ID, PolicyVersion: updated.Policy.Revision, TargetNodeIDs: []uuid.UUID{tenant.nodeID},
		RolloutID: uuid.New(), IdempotencyKey: "qb-publish", RequestID: "qb-publish"})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if publication.RuntimeSnapshotSHA256 != runtime.SHA256 {
		t.Fatal("published runtime snapshot is not the policy's")
	}

	// Off: only the user rule remains; a stale version is refused.
	off := securitypolicy.QuickBlockRequest{ID: policy.ID, ExpectedRevision: on.Policy.Revision, IdempotencyKey: "qb-off-stale", RequestID: "qb-off"}
	if _, err := service.SetQuickBlock(t.Context(), actor, off); !errors.Is(err, securitypolicy.ErrRevisionConflict) {
		t.Fatalf("stale off: %v", err)
	}
	off.ExpectedRevision, off.IdempotencyKey = updated.Policy.Revision, "qb-off"
	cleared, err := service.SetQuickBlock(t.Context(), actor, off)
	if err != nil || len(cleared.Policy.Rules) != 1 || cleared.Policy.Rules[0].Name != "admin" ||
		cleared.Policy.QuickBlock == nil || cleared.Policy.QuickBlock.Active() {
		t.Fatalf("off = %+v, %v", cleared.Policy, err)
	}

	// A policy whose only rules are the quick block's cannot turn it off.
	only := securitypolicy.QuickBlockRequest{ID: policy.ID, ExpectedRevision: cleared.Policy.Revision,
		QuickBlock: securitypolicy.QuickBlock{BlockIDCCN: true}, IdempotencyKey: "qb-only", RequestID: "qb-only"}
	withOnly, err := service.SetQuickBlock(t.Context(), actor, only)
	if err != nil {
		t.Fatal(err)
	}
	stripped, err := service.Update(t.Context(), actor, securitypolicy.UpdateRequest{ID: policy.ID, ExpectedRevision: withOnly.Policy.Revision,
		Fields: securitypolicy.PolicyFields{Kind: securitypolicy.KindWAF, Name: "site waf", Enabled: true,
			DefaultAction: securitypolicy.ActionAllow, Rules: withOnly.Policy.Rules[:1]},
		IdempotencyKey: "qb-strip-user", RequestID: "qb-strip-user"})
	if err != nil || len(stripped.Policy.Rules) != 1 {
		t.Fatalf("drop the user rule: %+v, %v", stripped.Policy.Rules, err)
	}
	if _, err := service.SetQuickBlock(t.Context(), actor, securitypolicy.QuickBlockRequest{ID: policy.ID,
		ExpectedRevision: stripped.Policy.Revision, IdempotencyKey: "qb-last", RequestID: "qb-last"}); !errors.Is(err, securitypolicy.ErrQuickBlockLastRules) {
		t.Fatalf("turning off the only rules: %v", err)
	}
	// CC policies cannot carry it.
	if _, err := service.SetQuickBlock(t.Context(), actor, securitypolicy.QuickBlockRequest{ID: tenant.policyID, ExpectedRevision: 1,
		QuickBlock: securitypolicy.QuickBlock{BlockIDCCN: true}, IdempotencyKey: "qb-cc", RequestID: "qb-cc"}); !errors.Is(err, securitypolicy.ErrQuickBlockUnsupported) {
		t.Fatalf("CC policy: %v", err)
	}
}
