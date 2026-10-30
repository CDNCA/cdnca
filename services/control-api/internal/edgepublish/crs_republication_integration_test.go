//go:build integration

package edgepublish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/securityrulecatalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// catalogSync drives artifactsync against an in-memory license service
// listing the current seed catalog, the way control-api runs it (the CRS
// rule package digest triggers RuleCatalogPublisher).
type catalogSync struct {
	license   *artifactsynctest.License
	syncer    *artifactsync.Syncer
	crs       rulecatalog.Item
	canonical rulecatalog.Item
}

func newCatalogSync(t *testing.T, scope *edgepublish.SystemRepublishScope) *catalogSync {
	t.Helper()
	installationID := uuid.New()
	license := artifactsynctest.NewLicense(t, installationID, time.Now)
	for _, item := range rulecatalog.CurrentSeed() {
		license.PublishRule(item, "", true)
	}
	// The CRS profile packs (license migration 087) are in the catalog too.
	for _, path := range crsProfileGoldenPaths(t) {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var head struct{ PackID, Version string }
		if err := json.Unmarshal(content, &struct {
			PackID  *string `json:"pack_id"`
			Version *string `json:"version"`
		}{&head.PackID, &head.Version}); err != nil {
			t.Fatal(err)
		}
		entry, err := artifactcatalog.CRSProfilePackEntry(head.PackID, head.Version, 1, content, "")
		if err != nil {
			t.Fatal(err)
		}
		license.Publish(entry, content)
	}
	syncer, err := artifactsync.NewSyncer(artifactsync.SyncerConfig{Client: license,
		Store: artifactsync.NewStore(scope.Pool, time.Now).WithCRSRepublisher(edgeautopublish.RuleCatalogPublisher{}),
		Trust: license.Trust(), InstallationID: installationID, PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)),
		ControlVersion: "1.0.35", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	crs := artifactsynctest.SystemRule(t, rulecatalog.CurrentSeed(), edgepublish.CRSRuleCatalogKey)
	return &catalogSync{license: license, syncer: syncer, crs: crs, canonical: crs}
}

func (catalog *catalogSync) sync(t *testing.T) {
	t.Helper()
	if err := catalog.syncer.SyncOnce(t.Context()); err != nil {
		t.Fatalf("artifact sync: %v", err)
	}
}

// changeCRSFile publishes the next CRS rule package with file changed (the
// CRS manifest is derived from the delivered text, PA-12); restoreCRS
// publishes the next one with the seed text again.

func crsProfileGoldenPaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../../../../libs/rulepack/testdata/crs-profiles/crs-*.json")
	if err != nil || len(paths) != 4 {
		t.Fatalf("CRS profile goldens: %v %v", paths, err)
	}
	return paths
}
func (catalog *catalogSync) changeCRSFile(t *testing.T, file string) {
	t.Helper()
	catalog.crs = artifactsynctest.NextCRSRevision(t, catalog.crs, file)
	catalog.license.PublishRule(catalog.crs, "", true)
}

func (catalog *catalogSync) restoreCRS() {
	next := catalog.canonical
	next.Revision = catalog.crs.Revision + 1
	catalog.crs = next
	catalog.license.PublishRule(catalog.crs, "", true)
}

// A new CRS rule package (its digest changed) whose text differs in a file a
// published release loads queues the scope's system republication (trigger
// rule_catalog, debounced: several packages make one), which publishes the
// new text; the page reads it as pending until then. An unchanged package,
// or a scope without a managed WAF, queues nothing.
func TestRuleCatalogCRSChangeRepublishesPublishedScopes(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	scope.GrantCRSModule(t, nodeA)
	store := securityrulecatalog.NewStore(scope.Pool, time.Now)
	catalog := newCatalogSync(t, scope)
	heads := `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`
	tenant := securityrulecatalog.Viewer{UserID: scope.UserID, ScopeID: scope.ScopeID}
	allow := func(context.Context, pgx.Tx) error { return nil }
	pending := func() securityrulecatalog.Republication {
		t.Helper()
		status, err := store.Republication(t.Context(), tenant, allow)
		if err != nil {
			t.Fatal(err)
		}
		return status
	}

	// No managed WAF published: the first package (all CRS files new)
	// reaches no release.
	if err := scope.PublishManually(t, "crs-plain", nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	catalog.sync(t)
	if got := scope.Count(t, heads); got != 0 || pending().Pending {
		t.Fatalf("plain release: %d republication heads, status %+v", got, pending())
	}

	// The managed WAF release goes to A only (every 1.0.35 agent declares
	// the CRS module, so no node is refused for it).
	scope.BindManagedWAF(t)
	if err := scope.PublishManually(t, "crs-waf", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	before := scope.LatestPublication(t).SourceRevision
	// The node receives the pinned CRS rule file its managed WAF loads.
	const sqli = "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
	if published := scope.PublishedCRSFile(t, nodeA, sqli); published == "" || published != scope.CatalogCRSFile(t, sqli) {
		t.Fatalf("published CRS file %q, catalog %q", published, scope.CatalogCRSFile(t, sqli))
	}

	// Two packages in a row each change the SQL injection rule file the
	// release loads (the second restores the embedded text): one debounced
	// republication.
	for round := range 2 {
		if round == 0 {
			catalog.changeCRSFile(t, sqli)
		} else {
			catalog.restoreCRS()
		}
		catalog.sync(t)
		var state string
		var generation int64
		var triggers []string
		if err := scope.Pool.QueryRow(t.Context(), `SELECT state,generation,triggers FROM edge_system_republication_heads
			WHERE scope_id=$1`, scope.ScopeID).Scan(&state, &generation, &triggers); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		if state != "pending" || generation != int64(round+1) || !slices.Equal(triggers, []string{edgepublish.SystemTriggerRuleCatalog}) {
			t.Fatalf("round %d head = %s generation %d triggers %v", round, state, generation, triggers)
		}
	}
	if status := pending(); !status.Pending || status.PendingScopes != 1 {
		t.Fatalf("status while queued = %+v", status)
	}
	if other, err := store.Republication(t.Context(), securityrulecatalog.Viewer{UserID: uuid.New(), ScopeID: uuid.New()}, allow); err != nil || other.Pending {
		t.Fatalf("another tenant sees %+v (%v)", other, err)
	}
	if scope.Run(t) != 0 {
		t.Fatal("republication ran before its debounce window ended")
	}
	scope.MakeDue(t)
	scope.Run(t)
	attempt := scope.LatestAttempt(t)
	// The republication goes where the release went (A); B, which only has
	// the earlier plain release, is not taken along.
	if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.NodeIDs, []uuid.UUID{nodeA}) ||
		!slices.Equal(attempt.Triggers, []string{edgepublish.SystemTriggerRuleCatalog}) {
		t.Fatalf("attempt = %+v (error %v)", attempt, *attempt.ErrorClass)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_attempts WHERE scope_id=$1 AND outcome='published'`); got != 1 {
		t.Fatalf("published attempts = %d, want one for both deliveries", got)
	}
	after := scope.LatestPublication(t)
	if after.SourceRevision <= before || scope.PublishedCRSFile(t, nodeA, sqli) != scope.CatalogCRSFile(t, sqli) {
		t.Fatalf("republication revision %d (before %d), CRS file %s, catalog %s", after.SourceRevision, before,
			scope.PublishedCRSFile(t, nodeA, sqli), scope.CatalogCRSFile(t, sqli))
	}
	if status := pending(); status.Pending {
		t.Fatalf("status after the republication = %+v", status)
	}

	// The same package again: nothing to republish.
	scope.SettleDeployments(t)
	catalog.sync(t)
	var state string
	if err := scope.Pool.QueryRow(t.Context(), `SELECT state FROM edge_system_republication_heads WHERE scope_id=$1`,
		scope.ScopeID).Scan(&state); err != nil || state != "idle" {
		t.Fatalf("unchanged delivery left head %q (%v)", state, err)
	}
}

// An automatic scope republishes through its own policy: the new package
// queues an automatic request (source rule_catalog, the catalog delivery that
// brought it its resource).
func TestRuleCatalogCRSChangeQueuesAutomaticScope(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	scope.GrantCRSModule(t, nodeA)
	store := securityrulecatalog.NewStore(scope.Pool, time.Now)
	catalog := newCatalogSync(t, scope)
	catalog.sync(t)
	scope.BindManagedWAF(t)
	if err := scope.PublishManually(t, "crs-auto", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	scope.EnableAutomaticPolicy(t, nodeA)
	catalog.changeCRSFile(t, "REQUEST-942-APPLICATION-ATTACK-SQLI.conf")
	catalog.sync(t)
	if got := scope.Count(t, `SELECT count(*) FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_kind='rule_catalog' AND operation='security_rule_catalog.updated'
		  AND reason='catalog_changed' AND source_resource_id=$2::uuid`, catalog.license.Last().Envelope.DeliveryID); got != 1 {
		t.Fatalf("automatic rule catalog requests = %d", got)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`); got != 0 {
		t.Fatalf("automatic scope got %d system heads", got)
	}
	status, err := store.Republication(t.Context(), securityrulecatalog.Viewer{UserID: scope.UserID, ScopeID: scope.ScopeID},
		func(context.Context, pgx.Tx) error { return nil })
	if err != nil || !status.Pending {
		t.Fatalf("automatic scope status = %+v (%v)", status, err)
	}
}
