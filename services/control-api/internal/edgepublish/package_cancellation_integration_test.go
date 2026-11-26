//go:build integration

package edgepublish_test

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/jackc/pgx/v5"
)

// Cancelled package subscriptions (user), 合并任务跑:
//
//	TEST_DATABASE_URL=... go -C services/control-api test -tags integration -count=1 -p 1 \
//	  -run 'TestPackageCancellation' ./internal/edgepublish/
//
// Two subscriptions, one site each, published; cancelling the first
// republishes at once (trigger package_suspension) without its site, the
// other site stays. A manual publication afterwards is not refused and still
// leaves the site out; rebinding the site to the live subscription publishes
// it again. Both the clean chain and the overlay path (an unpublished tenant
// edit pending) are covered.
func TestPackageCancellationLeavesSitesOutAndRebindRestores(t *testing.T) {
	for _, pendingEdit := range []bool{false, true} {
		scope := edgepublish.NewSystemRepublishScope(t)
		other := scope.AddSite(t, "package-cancellation-other.example.com", 18084)
		scope.BindSiteToSubscription(t, scope.SiteID)
		second := scope.AddSubscription(t)
		scope.BindSiteTo(t, other, second)
		node := scope.AddNode(t, 6)
		if err := scope.PublishManually(t, "package-cancellation-baseline", node); err != nil {
			t.Fatal(err)
		}
		scope.SettleDeployments(t)
		if sites := scope.PublishedSiteIDs(t); !sites[scope.SiteID] || !sites[other] {
			t.Fatalf("baseline sites %v", sites)
		}
		if pendingEdit {
			scope.EditSiteOrigin(t, other, "198.51.100.78")
			scope.AdvanceRevision(t)
		}
		scope.SetSubscriptionCancelled(t, scope.SubscriptionID, func(tx pgx.Tx, from int64) error {
			return edgeautopublish.RequestPackageSuspensionRepublicationTx(t.Context(), tx, scope.ScopeID,
				scope.SubscriptionID, from, true, "cancel-test")
		})
		if due := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
			AND state='pending' AND due_at<=clock_timestamp() AND 'package_suspension'=ANY(triggers)`); due != 1 {
			t.Fatalf("pending edit %v: cancellation republication not due at once", pendingEdit)
		}
		scope.Run(t)
		if sites := scope.PublishedSiteIDs(t); sites[scope.SiteID] || !sites[other] {
			t.Fatalf("pending edit %v: cancelled sites %v (attempt %+v)", pendingEdit, sites, scope.LatestAttempt(t))
		}
		scope.SettleDeployments(t)

		// The tenant's own publication: the cancelled package refuses nothing.
		scope.AdvanceRevision(t)
		if err := scope.PublishManually(t, "package-cancellation-manual", node); err != nil {
			t.Fatalf("pending edit %v: manual publication beside a cancelled package: %v", pendingEdit, err)
		}
		scope.SettleDeployments(t)
		if sites := scope.PublishedSiteIDs(t); sites[scope.SiteID] || !sites[other] {
			t.Fatalf("pending edit %v: manual publication sites %v", pendingEdit, sites)
		}

		// Rebound to the live subscription, the site goes out again.
		scope.RebindSite(t, scope.SiteID, second)
		scope.AdvanceRevision(t)
		if err := scope.PublishManually(t, "package-cancellation-rebound", node); err != nil {
			t.Fatalf("pending edit %v: publication after rebinding: %v", pendingEdit, err)
		}
		if sites := scope.PublishedSiteIDs(t); !sites[scope.SiteID] || !sites[other] {
			t.Fatalf("pending edit %v: rebound sites %v", pendingEdit, sites)
		}
	}
}
