//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// Package expiry (errpage-4 S3), 待出包前全量跑（errpage-5 只写未跑）:
//
//	TEST_DATABASE_URL=... go -C services/control-api test -tags integration -count=1 -p 1 \
//	  -run 'TestPackageExpiry' ./internal/edgepublish/
//
// The scope has two sites, the first on the package subscription; the node
// declares ERROR_PAGE_SLOTS (a marked site requires it).

func newPackageExpiryScope(t *testing.T) (*edgepublish.SystemRepublishScope, uuid.UUID, uuid.UUID) {
	t.Helper()
	scope := edgepublish.NewSystemRepublishScope(t)
	other := scope.AddSite(t, "package-expiry-other.example.com", 18082)
	scope.BindSiteToSubscription(t, scope.SiteID)
	node := scope.AddNode(t, 6)
	scope.DeclareErrorPageSlots(t, node)
	if err := scope.PublishManually(t, "package-expiry-baseline", node); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	if marks, required := scope.PublishedPackageExpiry(t); marks[scope.SiteID] || marks[other] || required {
		t.Fatalf("baseline marks %v requires slots %v", marks, required)
	}
	return scope, other, node
}

func newPackageExpiryWatcher(t *testing.T, scope *edgepublish.SystemRepublishScope) *edgeautopublish.PackageExpiryWatcher {
	t.Helper()
	watcher, err := edgeautopublish.NewPackageExpiryWatcher(scope.Pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return watcher
}

func sweepPackageExpiry(t *testing.T, watcher *edgeautopublish.PackageExpiryWatcher, step string, want int) {
	t.Helper()
	scopes, err := watcher.SweepOnce(t.Context())
	if err != nil || len(scopes) != want {
		t.Fatalf("%s: sweep queued %v, want %d scope(s) (%v)", step, scopes, want, err)
	}
}

// An expired subscription with expiry_close on: the publication succeeds,
// the subscription's site goes out marked package_expired with
// error_page_slots required, the scope's other site is unchanged.
func TestPackageExpiryPublishMarksExpiredSite(t *testing.T) {
	scope, other, node := newPackageExpiryScope(t)
	scope.SetExpiryClose(t, true)
	scope.EndSubscription(t)
	scope.AdvanceRevision(t)
	if err := scope.PublishManually(t, "package-expiry-expired", node); err != nil {
		t.Fatalf("publication with an expired package: %v", err)
	}
	marks, required := scope.PublishedPackageExpiry(t)
	if !marks[scope.SiteID] || marks[other] || !required {
		t.Fatalf("expired marks %v requires slots %v", marks, required)
	}
}

// expiry_close off: an expired package's site keeps serving (no mark); a
// site whose stored status is package_expired is marked either way.
func TestPackageExpiryPublishHonoursExpiryClose(t *testing.T) {
	scope, other, node := newPackageExpiryScope(t)
	scope.SetExpiryClose(t, false)
	scope.EndSubscription(t)
	scope.AdvanceRevision(t)
	if err := scope.PublishManually(t, "package-expiry-close-off", node); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	if marks, required := scope.PublishedPackageExpiry(t); marks[scope.SiteID] || marks[other] || required {
		t.Fatalf("expiry_close off marks %v requires slots %v", marks, required)
	}
	scope.Exec(t, `UPDATE sites SET status='package_expired',revision=revision+1 WHERE id=$1`, other)
	scope.AdvanceRevision(t)
	if err := scope.PublishManually(t, "package-expiry-status", node); err != nil {
		t.Fatal(err)
	}
	if marks, required := scope.PublishedPackageExpiry(t); marks[scope.SiteID] || !marks[other] || !required {
		t.Fatalf("status package_expired marks %v requires slots %v", marks, required)
	}
}

// The watcher: the term ending queues one package_expiry republication
// (mark recorded) which publishes the site marked; a second sweep queues
// nothing; a renewal queues again, removes the mark and the site is
// republished unmarked.
func TestPackageExpiryWatcherExpiresAndRenews(t *testing.T) {
	scope, other, _ := newPackageExpiryScope(t)
	scope.SetExpiryClose(t, true)
	watcher := newPackageExpiryWatcher(t, scope)
	sweepPackageExpiry(t, watcher, "active term", 0)

	scope.EndSubscription(t)
	sweepPackageExpiry(t, watcher, "term ended", 1)
	if got := scope.Count(t, `SELECT count(*) FROM package_expiry_republication_marks WHERE tenant_scope_id=$1 AND expiry_close`); got != 1 {
		t.Fatalf("marks after expiry = %d", got)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
		AND state='pending' AND 'package_expiry'=ANY(triggers)`); got != 1 {
		t.Fatalf("package_expiry heads = %d", got)
	}
	sweepPackageExpiry(t, watcher, "unchanged expiry", 0)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished ||
		!slices.Contains(attempt.Triggers, edgepublish.SystemTriggerPackageExpiry) {
		t.Fatalf("expiry attempt = %+v", attempt)
	}
	if marks, required := scope.PublishedPackageExpiry(t); !marks[scope.SiteID] || marks[other] || !required {
		t.Fatalf("after expiry marks %v requires slots %v", marks, required)
	}
	scope.SettleDeployments(t)

	scope.RenewSubscription(t)
	sweepPackageExpiry(t, watcher, "renewed", 1)
	if got := scope.Count(t, `SELECT count(*) FROM package_expiry_republication_marks WHERE tenant_scope_id=$1`); got != 0 {
		t.Fatalf("marks after renewal = %d", got)
	}
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished {
		t.Fatalf("renewal attempt = %+v", attempt)
	}
	if marks, required := scope.PublishedPackageExpiry(t); marks[scope.SiteID] || marks[other] || required {
		t.Fatalf("after renewal marks %v requires slots %v", marks, required)
	}
	sweepPackageExpiry(t, watcher, "unchanged renewal", 0)
}

// Toggling expiry_close on an expired package: each switch queues one
// republication (the mark follows the setting) and the published mark
// follows; with it off from the start nothing changes what nodes serve, so
// nothing is queued until it is switched on.
func TestPackageExpiryWatcherFollowsExpiryClose(t *testing.T) {
	scope, _, _ := newPackageExpiryScope(t)
	scope.SetExpiryClose(t, false)
	watcher := newPackageExpiryWatcher(t, scope)
	scope.EndSubscription(t)
	sweepPackageExpiry(t, watcher, "expired with close off", 0)
	if got := scope.Count(t, `SELECT count(*) FROM package_expiry_republication_marks WHERE tenant_scope_id=$1 AND NOT expiry_close`); got != 1 {
		t.Fatalf("marks with close off = %d", got)
	}

	scope.SetExpiryClose(t, true)
	sweepPackageExpiry(t, watcher, "close switched on", 1)
	scope.Run(t)
	if marks, _ := scope.PublishedPackageExpiry(t); !marks[scope.SiteID] {
		t.Fatalf("close on marks %v", marks)
	}
	scope.SettleDeployments(t)

	scope.SetExpiryClose(t, false)
	sweepPackageExpiry(t, watcher, "close switched off", 1)
	if got := scope.Count(t, `SELECT count(*) FROM package_expiry_republication_marks WHERE tenant_scope_id=$1 AND NOT expiry_close`); got != 1 {
		t.Fatalf("marks after close off = %d", got)
	}
	scope.Run(t)
	if marks, required := scope.PublishedPackageExpiry(t); marks[scope.SiteID] || required {
		t.Fatalf("close off marks %v requires slots %v", marks, required)
	}
	sweepPackageExpiry(t, watcher, "unchanged close off", 0)
}
