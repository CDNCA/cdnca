//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// fix-nodeipgeo: a node's IP 归属 changing (resolved or corrected) queues a
// system republication (node_networks, due at once) of the scopes whose L2
// conditions match node country/ISP/province/city; a scope without such a
// condition is not republished, and the first sweep only records the mark.
func TestNodeLocationChangeRepublishesL2ConditionScopes(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	node := scope.AddNode(t, 6)
	watcher, err := edgeautopublish.NewNodeNetworksWatcher(scope.Pool, audit.New(scope.Pool), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.PublishManually(t, "node-location-baseline", node); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	sweep := func() []uuid.UUID {
		t.Helper()
		queued, err := watcher.SweepOnce(t.Context())
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		return queued
	}
	sweep()
	if queued := sweep(); len(queued) != 0 {
		t.Fatalf("baseline sweep queued %v", queued)
	}
	setISP := func(isp string) {
		scope.Exec(t, `UPDATE nodes SET management_settings=jsonb_set(management_settings,'{ip_location,isp}',to_jsonb($2::text)) WHERE id=$1`, node, isp)
	}
	setISP("中国电信")
	if queued := sweep(); len(queued) != 0 {
		t.Fatalf("no node condition: queued %v", queued)
	}
	scope.Exec(t, `INSERT INTO l2_topology_conditions(id,tenant_scope_id,name,rules,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,'电信节点','[{"field":"node_isp","operator":"eq","value":"中国电信"}]'::jsonb,$3,$3,clock_timestamp(),clock_timestamp())`,
		uuid.New(), scope.ScopeID, scope.UserID)
	setISP("中国联通")
	if queued := sweep(); !slices.Equal(queued, []uuid.UUID{scope.ScopeID}) {
		t.Fatalf("location change queued %v", queued)
	}
	if due := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
		AND state='pending' AND due_at<=clock_timestamp() AND 'node_networks'=ANY(triggers)`); due != 1 {
		t.Fatal("node_networks republication not due at once")
	}
	if again := sweep(); len(again) != 0 {
		t.Fatalf("unchanged sweep queued %v", again)
	}
}
