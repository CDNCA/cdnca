//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// FX45 on a real kernel: the runtime status (a stand-in for
// cdnca_security.firewall_action_status) drives the real firewall manager,
// so the site's block networks enter the nftables deny set on engage, stay
// across an agent restart and leave on recovery and when the site leaves
// the runtime. Privileged disposable container only:
//
//	scripts/edge-firewall-action-kernel-smoke.sh
func TestKernelFirewallActionMirrorDrivesNFTables(t *testing.T) {
	if os.Getenv("CDNCA_FIREWALL_ACTION_KERNEL_TEST") != "1" {
		t.Skip("CDNCA_FIREWALL_ACTION_KERNEL_TEST is not set (privileged disposable container only)")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	// the manager creates its state root 0700 itself (a TempDir is 0755)
	manager, err := firewall.NewManager(filepath.Join(t.TempDir(), "firewall"), nft)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	defer exec.Command(nft, "delete", "table", firewall.TableFamily, firewall.TableName).Run()

	policy := fxPolicyJSON("1")
	digest := edgesite.Digest(policy)
	var mu sync.Mutex
	active := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var posted []firewallActionSite
		_ = json.NewDecoder(r.Body).Decode(&posted)
		mu.Lock()
		state := active
		mu.Unlock()
		sites := []map[string]any{}
		for _, site := range posted {
			sites = append(sites, map[string]any{"tenant_id": fxTenant, "site_id": site.SiteID, "policy_id": fxPolicy,
				"policy_version": 1, "active": state})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": firewallActionStatusSchema, "observed_at": 1, "sites": sites})
	}))
	defer server.Close()
	set := func(value bool) { mu.Lock(); active = value; mu.Unlock() }
	running := []edgesite.Site{{TenantID: fxTenant, SiteID: fxSite,
		Security: edgesite.Security{FirewallAction: &edgesite.Ref{Kind: edgesite.RefFirewallAction, ID: fxPolicy, Revision: 1, SHA256: digest}}}}
	sites := func() []edgesite.Site { return running }
	object := func(string) ([]byte, error) { return policy, nil }
	poller := newRuntimeStatusPoller(server.URL+"/healthz", time.Second).withFirewallActions(newFirewallActionMirror(manager, sites, object))
	denied := func() bool {
		output, err := exec.Command(nft, "list", "table", firewall.TableFamily, firewall.TableName).CombinedOutput()
		if err != nil {
			return false
		}
		return strings.Contains(string(output), "198.51.100.0/24")
	}

	poller.pollFirewallActions(ctx)
	if denied() {
		t.Fatal("idle site denied its block networks")
	}
	set(true)
	poller.pollFirewallActions(ctx)
	if !denied() {
		t.Fatal("engaged site's block networks are not in nftables")
	}
	// Agent restart: the new mirror reads the kernel scope back and keeps it.
	poller.firewallActions = newFirewallActionMirror(manager, sites, object)
	poller.pollFirewallActions(ctx)
	if !denied() {
		t.Fatal("restart dropped the engagement")
	}
	set(false)
	poller.pollFirewallActions(ctx)
	if denied() {
		t.Fatal("recovered site's block networks remain in nftables")
	}
	set(true)
	poller.pollFirewallActions(ctx)
	if !denied() {
		t.Fatal("re-engage did not apply")
	}
	running = nil
	poller.pollFirewallActions(ctx)
	if denied() {
		t.Fatal("removed site's block networks remain in nftables")
	}
}
