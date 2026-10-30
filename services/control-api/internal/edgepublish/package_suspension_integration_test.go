//go:build integration

package edgepublish_test

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/jackc/pgx/v5"
)

// Package subscription suspension (bb03, ADR 0019 §5, migration 555), 合并任务跑:
//
//	TEST_DATABASE_URL=... go -C services/control-api test -tags integration -count=1 -p 1 \
//	  -run 'TestPackageSuspension' ./internal/edgepublish/
//
// Two subscriptions, one site each, published; suspending the first
// republishes at once (trigger package_suspension) without its site, the
// other site stays; unsuspending brings it back. Both the clean chain and the
// overlay path (an unpublished tenant edit pending) are covered.
func TestPackageSuspensionStopsOnlyThatSubscriptionAndRestores(t *testing.T) {
	for _, pendingEdit := range []bool{false, true} {
		scope := edgepublish.NewSystemRepublishScope(t)
		other := scope.AddSite(t, "package-suspension-other.example.com", 18083)
		scope.BindSiteToSubscription(t, scope.SiteID)
		second := scope.AddSubscription(t)
		scope.BindSiteTo(t, other, second)
		node := scope.AddNode(t, 6)
		if err := scope.PublishManually(t, "package-suspension-baseline", node); err != nil {
			t.Fatal(err)
		}
		scope.SettleDeployments(t)
		if sites := scope.PublishedSiteIDs(t); !sites[scope.SiteID] || !sites[other] {
			t.Fatalf("baseline sites %v", sites)
		}
		if pendingEdit {
			scope.EditSiteOrigin(t, other, "198.51.100.77")
			scope.AdvanceRevision(t)
		}
		republish := func(suspend bool) func(pgx.Tx, int64) error {
			return func(tx pgx.Tx, from int64) error {
				return edgeautopublish.RequestPackageSuspensionRepublicationTx(t.Context(), tx, scope.ScopeID,
					scope.SubscriptionID, from, suspend, "bb03-test")
			}
		}
		scope.SetSubscriptionSuspended(t, scope.SubscriptionID, true, republish(true))
		if due := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
			AND state='pending' AND due_at<=clock_timestamp() AND 'package_suspension'=ANY(triggers)`); due != 1 {
			t.Fatalf("pending edit %v: package_suspension republication not due at once", pendingEdit)
		}
		scope.Run(t)
		if sites := scope.PublishedSiteIDs(t); sites[scope.SiteID] || !sites[other] {
			t.Fatalf("pending edit %v: suspended sites %v (attempt %+v)", pendingEdit, sites, scope.LatestAttempt(t))
		}
		scope.SettleDeployments(t)
		scope.SetSubscriptionSuspended(t, scope.SubscriptionID, false, republish(false))
		scope.Run(t)
		if sites := scope.PublishedSiteIDs(t); !sites[scope.SiteID] || !sites[other] {
			t.Fatalf("pending edit %v: unsuspended sites %v (attempt %+v)", pendingEdit, sites, scope.LatestAttempt(t))
		}
	}
}
