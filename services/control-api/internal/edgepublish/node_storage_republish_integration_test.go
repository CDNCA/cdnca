//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// fix-nodesettings: changing a node's cache directory, cache limit or log
// directory queues a system republication of every tenant scope (trigger
// node_storage, due at once) and is audited; the first sweep only records
// the mark, an unchanged sweep queues nothing, and a change of another
// management setting is not a storage change.
func TestNodeStorageChangeRepublishesScopes(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	node := scope.AddNode(t, 6)
	watcher, err := edgeautopublish.NewNodeNetworksWatcher(scope.Pool, audit.New(scope.Pool), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.PublishManually(t, "node-storage-baseline", node); err != nil {
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
	sweep() // records the marks
	if queued := sweep(); len(queued) != 0 {
		t.Fatalf("baseline sweep queued %v", queued)
	}
	scope.Exec(t, `UPDATE nodes SET management_settings=management_settings || '{"sort":5}'::jsonb WHERE id=$1`, node)
	if queued := sweep(); len(queued) != 0 {
		t.Fatalf("non-storage change queued %v", queued)
	}

	for _, change := range []string{
		`{"cache_directory":"/data/cdnca-cache"}`, `{"cache_limit_gb":20}`, `{"log_directory":"/data/cdnca-logs"}`,
	} {
		before := scope.LatestPublication(t).SourceRevision
		scope.Exec(t, `UPDATE nodes SET management_settings=management_settings || $2::jsonb WHERE id=$1`, node, change)
		if queued := sweep(); !slices.Equal(queued, []uuid.UUID{scope.ScopeID}) {
			t.Fatalf("%s: sweep queued %v", change, queued)
		}
		if due := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
			AND state='pending' AND due_at<=clock_timestamp() AND 'node_storage'=ANY(triggers)`); due != 1 {
			t.Fatalf("%s: node_storage republication not due at once", change)
		}
		if again := sweep(); len(again) != 0 {
			t.Fatalf("%s: unchanged sweep queued %v", change, again)
		}
		if runs := scope.Run(t); runs == 0 {
			t.Fatalf("%s: nothing republished", change)
		}
		attempt := scope.LatestAttempt(t)
		if attempt.Outcome != edgepublish.SystemOutcomePublished ||
			!slices.Equal(attempt.Triggers, []string{edgepublish.SystemTriggerNodeStorage}) {
			t.Fatalf("%s: attempt = %+v", change, attempt)
		}
		if latest := scope.LatestPublication(t); latest.SourceRevision <= before {
			t.Fatalf("%s: publication rev %d", change, latest.SourceRevision)
		}
		event := audittest.Last(t, scope.Pool, `action=$1`, edgeautopublish.NodeNetworksRepublishAction)
		if event.Payload["trigger"] != edgepublish.SystemTriggerNodeStorage || event.Payload["scope_count"] != float64(1) {
			t.Fatalf("%s: audit payload = %#v", change, event.Payload)
		}
		scope.SettleDeployments(t)
	}
}
