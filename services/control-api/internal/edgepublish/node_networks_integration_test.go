//go:build integration

package edgepublish_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// Acceptance: adding a node, changing a node's IP and
// removing a secondary IP each queue the system republication (trigger
// node_networks, due at once) of the scope whose release exempts the old
// addresses, and the republished release exempts exactly the current ones;
// each sweep is audited. An unchanged address set queues nothing.
func TestNodeNetworksChangeRepublishesDDoSExemption(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	node := scope.AddNode(t, 6)
	scope.Exec(t, `UPDATE nodes SET ipv4='203.0.113.10', ipv6=NULL,
		management_settings=jsonb_set(management_settings,'{secondary_ips}','["198.51.100.10","198.51.100.11"]'::jsonb)
		WHERE id=$1`, node)
	scope.ActivateDDoSProtection(t)
	watcher, err := edgeautopublish.NewNodeNetworksWatcher(scope.Pool, audit.New(scope.Pool), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.PublishManually(t, "node-networks-baseline", node); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	sweep := func() []uuid.UUID {
		t.Helper()
		queued, err := watcher.SweepOnce(t.Context())
		if err != nil {
			t.Fatalf("node networks sweep: %v", err)
		}
		return queued
	}
	published := func() []string {
		t.Helper()
		var document struct {
			System *struct {
				DDoS *edgeconfig.SiteRuntimeDDoS `json:"ddos"`
			} `json:"system"`
		}
		if err := json.Unmarshal(scope.LatestPublication(t).Snapshot, &document); err != nil {
			t.Fatal(err)
		}
		if document.System == nil || document.System.DDoS == nil {
			t.Fatal("latest release carries no DDoS protection")
		}
		return document.System.DDoS.NodeNetworks
	}
	// Every other publish node of the fixture has no address; the platform
	// node set is this scope's nodes.
	want := func(extra ...string) []string {
		t.Helper()
		value, err := edgeconfig.NewSiteRuntimeDDoS(edgeconfig.DefaultDDoSProtection(), extra)
		if err != nil {
			t.Fatal(err)
		}
		return value.NodeNetworks
	}
	if got := published(); !slices.Equal(got, want("203.0.113.10", "198.51.100.10", "198.51.100.11")) {
		t.Fatalf("baseline node networks = %v", got)
	}
	if queued := sweep(); len(queued) != 0 {
		t.Fatalf("baseline sweep queued %v", queued)
	}

	step := func(name, change string, args []any, networks []string) {
		t.Helper()
		before := scope.LatestPublication(t).SourceRevision
		scope.Exec(t, change, args...)
		if queued := sweep(); !slices.Equal(queued, []uuid.UUID{scope.ScopeID}) {
			t.Fatalf("%s: sweep queued %v", name, queued)
		}
		if due := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
			AND state='pending' AND due_at<=clock_timestamp() AND 'node_networks'=ANY(triggers)`); due != 1 {
			t.Fatalf("%s: node_networks republication not due at once", name)
		}
		if again := sweep(); len(again) != 0 {
			t.Fatalf("%s: unchanged sweep queued %v", name, again)
		}
		if runs := scope.Run(t); runs == 0 {
			t.Fatalf("%s: nothing republished", name)
		}
		attempt := scope.LatestAttempt(t)
		if attempt.Outcome != edgepublish.SystemOutcomePublished ||
			!slices.Equal(attempt.Triggers, []string{edgepublish.SystemTriggerNodeNetworks}) {
			t.Fatalf("%s: attempt = %+v", name, attempt)
		}
		if latest := scope.LatestPublication(t); latest.SourceRevision <= before || !slices.Equal(latest.NodeIDs, []uuid.UUID{node}) {
			t.Fatalf("%s: publication rev %d nodes %v", name, latest.SourceRevision, latest.NodeIDs)
		}
		if got := published(); !slices.Equal(got, networks) {
			t.Fatalf("%s: node networks = %v want %v", name, got, networks)
		}
		event := audittest.Last(t, scope.Pool, `action=$1`, edgeautopublish.NodeNetworksRepublishAction)
		if event.Payload["actor"] != "system" || event.Payload["scope_count"] != float64(1) ||
			!slices.Equal(anyStrings(event.Payload["scope_ids"]), []string{scope.ScopeID.String()}) {
			t.Fatalf("%s: audit payload = %#v", name, event.Payload)
		}
		scope.SettleDeployments(t)
	}

	// 1. A new node (another scope's nodes are platform facts too).
	added := scope.AddNode(t, 6)
	step("new node", `UPDATE nodes SET ipv4='203.0.113.20', ipv6='2001:db8:20::1' WHERE id=$1`, []any{added},
		want("203.0.113.10", "198.51.100.10", "198.51.100.11", "203.0.113.20", "2001:db8:20::1"))
	// 2. A node's primary IP changes.
	step("changed IP", `UPDATE nodes SET ipv4='203.0.113.11' WHERE id=$1`, []any{node},
		want("203.0.113.11", "198.51.100.10", "198.51.100.11", "203.0.113.20", "2001:db8:20::1"))
	// 3. A secondary IP is removed.
	step("removed secondary IP", `UPDATE nodes SET
		management_settings=jsonb_set(management_settings,'{secondary_ips}','["198.51.100.10"]'::jsonb) WHERE id=$1`, []any{node},
		want("203.0.113.11", "198.51.100.10", "203.0.113.20", "2001:db8:20::1"))
}

func anyStrings(value any) []string {
	items, _ := value.([]any)
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, _ := item.(string)
		result = append(result, text)
	}
	return result
}
