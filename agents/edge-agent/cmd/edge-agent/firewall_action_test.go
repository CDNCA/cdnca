package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

const (
	fxTenant = "018f1000-0000-7000-8000-000000000001"
	fxSite   = "018f1000-0000-7000-8000-000000000002"
	fxPolicy = "018f1000-0000-7000-8000-000000000003"
)

func fxPolicyJSON(version string) []byte {
	return []byte(`{"schema_version":"cdnca.edge.firewall-action/v1","policy_version":` + version + `,"tenant_id":"` + fxTenant +
		`","site_id":"` + fxSite + `","policy_id":"` + fxPolicy + `","expected_active_policy_version":0,` +
		`"normal_action":"return_page","escalated_action":"nftables","engage_threshold":5,"recover_threshold":0,` +
		`"recovery_windows":2,"block_networks":["198.51.100.0/24"],"trusted_proxies":[],"trusted_crawlers":[],` +
		`"return_page":{"status":429,"content_type":"text/plain; charset=utf-8","body":"limited"}}`)
}

// fxFirewall is a scoped firewall holding the global scopes in memory.
type fxFirewall struct {
	mu     sync.Mutex
	scopes map[string]firewall.FirewallVersion
	fail   bool
}

func (fw *fxFirewall) ScopeEntries(_ context.Context, tenantID, siteID, kind, policyID string) (uint64, []firewall.Entry, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	version, ok := fw.scopes[tenantID+siteID+kind+policyID]
	if !ok {
		return 0, nil, nil
	}
	return version.PolicyVersion, version.Entries, nil
}

func (fw *fxFirewall) Apply(_ context.Context, version firewall.FirewallVersion) (firewall.Result, error) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if fw.fail {
		return firewall.Result{State: firewall.StateFailed}, errors.New("nft rejected")
	}
	key := version.TenantID + version.SiteID + version.PolicyKind + version.PolicyID
	if version.ExpectedActivePolicyVersion != fw.scopes[key].PolicyVersion {
		return firewall.Result{}, firewall.ErrActiveVersionConflict
	}
	fw.scopes[key] = version
	return firewall.Result{State: firewall.StateApplied, ActivePolicyVersion: version.PolicyVersion}, nil
}

func (fw *fxFirewall) entries() int {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	return len(fw.scopes[fxTenant+fxSite+"global"+fxPolicy].Entries)
}

// FX45 under dynamic routing: the poller posts the running sites' firewall
// action objects to the skeleton's health endpoint and mirrors the answered
// escalation into nftables; a site that leaves the runtime is withdrawn.
func TestFirewallActionMirrorPostsObjectsAndFollowsRuntimeState(t *testing.T) {
	policy := fxPolicyJSON("1")
	digest := edgesite.Digest(policy)
	var mu sync.Mutex
	active := false
	var posted []firewallActionSite
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz"+firewallActionStatusSuffix || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		posted = nil
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Errorf("posted body: %v", err)
		}
		sites := []map[string]any{}
		for _, site := range posted {
			sites = append(sites, map[string]any{"tenant_id": fxTenant, "site_id": site.SiteID, "policy_id": fxPolicy,
				"policy_version": 1, "active": active, "sequence": 1, "since": 1, "load": 9})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": firewallActionStatusSchema, "observed_at": 1, "sites": sites})
	}))
	defer server.Close()

	fw := &fxFirewall{scopes: map[string]firewall.FirewallVersion{}}
	running := []edgesite.Site{{TenantID: fxTenant, SiteID: fxSite,
		Security: edgesite.Security{FirewallAction: &edgesite.Ref{Kind: edgesite.RefFirewallAction, ID: fxPolicy, Revision: 1, SHA256: digest}}}}
	objects := map[string][]byte{digest: policy}
	mirror := newFirewallActionMirror(fw, func() []edgesite.Site { return running }, func(d string) ([]byte, error) {
		if content, ok := objects[d]; ok {
			return content, nil
		}
		return nil, errors.New("absent")
	})
	poller := newRuntimeStatusPoller(server.URL+"/healthz", time.Second).withFirewallActions(mirror)
	ctx := context.Background()

	poller.pollFirewallActions(ctx)
	if len(posted) != 1 || posted[0] != (firewallActionSite{SiteID: fxSite, SHA256: digest}) {
		t.Fatalf("posted %+v", posted)
	}
	if fw.entries() != 0 {
		t.Fatal("an idle site engaged nftables")
	}
	mu.Lock()
	active = true
	mu.Unlock()
	fw.fail = true
	poller.pollFirewallActions(ctx)
	if fw.entries() != 0 {
		t.Fatal("rejected apply changed nftables")
	}
	fw.fail = false
	poller.pollFirewallActions(ctx) // retried
	if fw.entries() != 1 {
		t.Fatalf("engaged site has %d nftables entries", fw.entries())
	}
	// Agent restart: a new mirror reads the engagement back, then follows
	// the runtime's recovery.
	restarted := newFirewallActionMirror(fw, func() []edgesite.Site { return running }, mirror.object)
	poller.firewallActions = restarted
	mu.Lock()
	active = false
	mu.Unlock()
	poller.pollFirewallActions(ctx)
	if fw.entries() != 0 {
		t.Fatal("recovered site kept its nftables entries")
	}
	// Engage again, then the site leaves the runtime: withdrawn, nothing
	// posted.
	mu.Lock()
	active = true
	mu.Unlock()
	poller.pollFirewallActions(ctx)
	if fw.entries() != 1 {
		t.Fatal("re-engage did not apply")
	}
	running = nil
	posted = nil
	poller.pollFirewallActions(ctx)
	if fw.entries() != 0 || posted != nil || len(restarted.engines) != 0 {
		t.Fatalf("removed site: entries=%d posted=%+v engines=%d", fw.entries(), posted, len(restarted.engines))
	}
}

func TestFirewallActionMirrorSkipsUnreadableObjects(t *testing.T) {
	fw := &fxFirewall{scopes: map[string]firewall.FirewallVersion{}}
	running := []edgesite.Site{{SiteID: fxSite, Security: edgesite.Security{FirewallAction: &edgesite.Ref{SHA256: "00"}}}}
	mirror := newFirewallActionMirror(fw, func() []edgesite.Site { return running }, func(string) ([]byte, error) { return nil, errors.New("absent") })
	if posted := mirror.sync(context.Background()); len(posted) != 0 {
		t.Fatalf("posted an unreadable object: %+v", posted)
	}
	if newFirewallActionMirror(nil, nil, nil) != nil {
		t.Fatal("mirror without a firewall")
	}
}

// A08: the nftables escalation of a firewall action is a host-wide ANY deny,
// so on a node the site's tenant does not own the escalation stays in
// OpenResty (the site's L7 block and disconnect) and no engine is built.
func TestFirewallActionMirrorSkipsSitesOfTenantsNotOwningTheNode(t *testing.T) {
	policy := fxPolicyJSON("1")
	digest := edgesite.Digest(policy)
	fw := &fxFirewall{scopes: map[string]firewall.FirewallVersion{}}
	running := []edgesite.Site{{ConfigurationScopeID: fxTenant, TenantID: fxTenant, SiteID: fxSite,
		Security: edgesite.Security{FirewallAction: &edgesite.Ref{Kind: edgesite.RefFirewallAction, ID: fxPolicy, Revision: 1, SHA256: digest}}}}
	mirror := newFirewallActionMirror(fw, func() []edgesite.Site { return running }, func(string) ([]byte, error) { return policy, nil })
	mirror.owned = func(string) bool { return false }
	if posted := mirror.sync(context.Background()); len(posted) != 0 || len(mirror.engines) != 0 {
		t.Fatalf("shared node mirrored a tenant firewall action: posted=%+v engines=%d", posted, len(mirror.engines))
	}
	mirror.owned = func(scope string) bool { return scope == fxTenant }
	if posted := mirror.sync(context.Background()); len(posted) != 1 {
		t.Fatalf("owned node lost the firewall action: posted=%+v", posted)
	}
}
