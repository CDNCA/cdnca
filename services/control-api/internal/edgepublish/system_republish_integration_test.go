//go:build integration

package edgepublish_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/l4forward"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func sortedNodes(nodes ...uuid.UUID) []uuid.UUID {
	sorted := slices.Clone(nodes)
	slices.SortFunc(sorted, func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
	return sorted
}

// createRateLimitedStream saves an L4 stream with a per-client new connection
// rate (G4-a) through the real l4forward service. Like every 1.0.35 forward it
// requires tcp v12; the fixtures' incapable node declares v11.
func createRateLimitedStream(t *testing.T, scope *edgepublish.SystemRepublishScope) {
	t.Helper()
	service := l4forward.NewService(l4forward.NewStore(scope.Pool))
	if _, err := service.Create(t.Context(), l4forward.Actor{ScopeID: scope.ScopeID, UserID: scope.UserID, ScopeKind: "tenant"},
		l4forward.CreateRequest{Fields: l4forward.Fields{PackageSubscriptionID: new(scope.SubscriptionID),
			Name: "rate", Protocol: "tcp", ListenAddress: "*", ListenPort: 18443, UpstreamAddress: "8.8.8.8",
			UpstreamPort: 443, ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100,
			Enabled: true, MaxNewConnectionsPerClientPerSecond: 20, NewConnectionBurst: 5, NewConnectionBanSeconds: 60},
			IdempotencyKey: "syspub-rate", RequestID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
}

func newWatcher(t *testing.T, scope *edgepublish.SystemRepublishScope) *edgeautopublish.CapabilityWatcher {
	t.Helper()
	watcher, err := edgeautopublish.NewCapabilityWatcher(scope.Pool, 0)
	if err != nil {
		t.Fatal(err)
	}
	return watcher
}

// A publication refused because a node lacked a gated capability goes out by
// itself once that node is upgraded; a node still lacking it keeps being
// refused and is listed on the publication record.
func TestSystemRepublishDeliversRefusedPublicationAfterCapabilityUpgrade(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB, nodeC := scope.AddNode(t, 12), scope.AddNode(t, 11), scope.AddNode(t, 11)
	createRateLimitedStream(t, scope)
	watcher := newWatcher(t, scope)
	if _, err := watcher.SweepOnce(t.Context()); err != nil { // every node's current set is its baseline
		t.Fatal(err)
	}

	err := scope.PublishManually(t, "syspub-refused", nodeA, nodeB, nodeC)
	var refusal *edgepublish.TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.NodeID == nodeA {
		t.Fatalf("publication to tcp v11 nodes: %v, want a capability refusal", err)
	}
	publications := `SELECT count(*) FROM edge_config_publications WHERE configuration_scope_id=$1`
	if got := scope.Count(t, publications); got != 0 {
		t.Fatalf("refused publication persisted %d publications", got)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_capability_publication_holds WHERE scope_id=$1
		AND refused_node_ids @> $2`, sortedNodes(nodeB, nodeC)); got != 1 {
		t.Fatalf("capability holds naming B and C = %d", got)
	}
	// No node changed: nothing is republished.
	if queued, err := watcher.SweepOnce(t.Context()); err != nil || queued != 0 {
		t.Fatalf("sweep without a change queued %d (%v)", queued, err)
	}

	// B is upgraded: its new session queues the scope; the held publication
	// goes to A and B, C is refused and listed.
	scope.UpgradeNode(t, nodeB, 12)
	if queued, err := watcher.SweepOnce(t.Context()); err != nil || queued != 1 {
		t.Fatalf("sweep after B's upgrade queued %d (%v)", queued, err)
	}
	scope.MakeDue(t)
	scope.Run(t)
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.NodeIDs, sortedNodes(nodeA, nodeB)) ||
		!slices.Equal(attempt.RefusedNodes, []uuid.UUID{nodeC}) || !slices.Equal(attempt.Triggers, []string{"node_capability"}) {
		t.Fatalf("attempt after B's upgrade = %+v", attempt)
	}
	first := scope.LatestPublication(t)
	if !slices.Equal(first.NodeIDs, sortedNodes(nodeA, nodeB)) || !bytes.Contains(first.Snapshot, []byte(`"new_conn_rate"`)) {
		t.Fatalf("publication nodes %v, snapshot carries new_conn_rate=%v", first.NodeIDs,
			bytes.Contains(first.Snapshot, []byte(`"new_conn_rate"`)))
	}
	// The system is the actor: no user on its audit event; the publication
	// audit names the accountable publisher and says actor_kind=system.
	if got := scope.Count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1
		AND action='edge_system_republication.published' AND actor_user_id IS NULL
		AND payload->>'actor_kind'='system'`); got != 1 {
		t.Fatalf("system republication audits = %d", got)
	}
	if got := scope.Count(t, `SELECT count(*) FROM audit_events WHERE action='edge_publication.publish'
		AND payload->>'actor_kind'='system' AND payload->>'configuration_scope_id'=$1::text`); got != 1 {
		t.Fatalf("system publication audits = %d", got)
	}

	// C is upgraded too: the next republication includes it.
	scope.SettleDeployments(t)
	scope.UpgradeNode(t, nodeC, 12)
	if queued, err := watcher.SweepOnce(t.Context()); err != nil || queued != 1 {
		t.Fatalf("sweep after C's upgrade queued %d (%v)", queued, err)
	}
	scope.MakeDue(t)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished ||
		!slices.Equal(attempt.NodeIDs, sortedNodes(nodeA, nodeB, nodeC)) || len(attempt.RefusedNodes) != 0 {
		t.Fatalf("attempt after C's upgrade = %+v", attempt)
	}
	if second := scope.LatestPublication(t); !slices.Equal(second.NodeIDs, sortedNodes(nodeA, nodeB, nodeC)) ||
		second.SourceRevision <= first.SourceRevision {
		t.Fatalf("second publication = %+v (first at %d)", second.NodeIDs, first.SourceRevision)
	}
}

// A system republication never carries a tenant edit that was not published.
func TestSystemRepublishNeverPublishesUnpublishedEdits(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "syspub-baseline", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	baseline := scope.LatestPublication(t)

	scope.AssertStoredInputsReproduceBundle(t)
	scope.EditOrigin(t, "203.0.113.99") // the tenant's draft
	draft := `SELECT count(*) FROM config_versions config
		LEFT JOIN configuration_artifacts artifact ON artifact.config_version_id=config.id
		WHERE config.configuration_scope_id=$1 AND (position('203.0.113.99' in convert_from(config.canonical_snapshot,'UTF8'))>0
		  OR position('203.0.113.99'::bytea in COALESCE(artifact.wire_bytes,''::bytea))>0)`
	for _, trigger := range []string{edgepublish.SystemTriggerNodeSync, edgepublish.SystemTriggerLineGroup,
		edgepublish.SystemTriggerTrafficEnforcement, edgepublish.SystemTriggerNodeCapability} {
		scope.SettleDeployments(t)
		scope.Request(t, trigger)
		scope.Run(t)
		if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished &&
			attempt.Outcome != edgepublish.SystemOutcomeUnchanged {
			t.Fatalf("%s with an unpublished edit: outcome %s", trigger, attempt.Outcome)
		}
		if got := scope.Count(t, draft); got != 0 {
			t.Fatalf("%s: %d configuration versions carry the unpublished origin", trigger, got)
		}
	}
	_ = baseline

	// Once the tenant publishes its edit, system republication resumes.
	if err := scope.PublishManually(t, "syspub-tenant-publish", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	scope.Request(t, edgepublish.SystemTriggerNodeSync)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished {
		t.Fatalf("after the tenant published: outcome %s", attempt.Outcome)
	}
}

// Without the published source kept (a publication before migration 316) a
// scope with a draft is not republished at all.
func TestSystemRepublishBlocksDraftScopeWithoutStoredSource(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "syspub-no-source", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	scope.DropCompileInputs(t)
	scope.EditOrigin(t, "203.0.113.99")
	scope.SuspendSite(t, "traffic_exceeded")
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomeBlocked ||
		scope.Count(t, `SELECT count(*) FROM config_versions WHERE configuration_scope_id=$1
			AND position('203.0.113.99' in convert_from(canonical_snapshot,'UTF8'))>0`) != 0 {
		t.Fatalf("draft scope without stored source: outcome %s", attempt.Outcome)
	}
}

// Traffic enforcement: the suspended website leaves the nodes without anyone
// publishing, and comes back when it recovers.
func TestSystemRepublishExcludesTrafficSuspendedSite(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "syspub-traffic", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	site := []byte(scope.SiteID.String())
	if !bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("baseline publication lacks the site")
	}
	scope.SuspendSite(t, "traffic_exceeded")
	scope.MakeDue(t)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished ||
		!slices.Equal(attempt.Triggers, []string{"traffic_enforcement"}) {
		t.Fatalf("suspension attempt = %+v", attempt)
	}
	if bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("traffic_exceeded site was republished")
	}
	scope.SettleDeployments(t)
	scope.SuspendSite(t, "active")
	scope.MakeDue(t)
	scope.Run(t)
	if !bytes.Contains(scope.LatestPublication(t).Snapshot, site) {
		t.Fatal("recovered site was not republished")
	}
}

// Triggers within the debounce window merge into one publication; a
// republication with nothing to change publishes nothing.
func TestSystemRepublishDebouncesAndIsIdempotent(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "syspub-debounce", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	publications := `SELECT count(*) FROM edge_config_publications WHERE configuration_scope_id=$1`
	before := scope.Count(t, publications)
	for _, trigger := range []string{edgepublish.SystemTriggerNodeSync, edgepublish.SystemTriggerLineGroup, edgepublish.SystemTriggerNodeSync} {
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			_, err := edgeautopublish.RequestRepublicationTx(t.Context(), tx, edgeautopublish.RepublishRequest{
				ScopeID: scope.ScopeID, Trigger: trigger, SourceResourceID: nodeA, SourceRequestID: "debounce/" + trigger,
				Debounce: time.Hour})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if runs := scope.Run(t); runs != 0 {
		t.Fatalf("debounced head ran %d times before it was due", runs)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
		AND generation=3 AND triggers=ARRAY['line_group','node_sync']`); got != 1 {
		t.Fatal("triggers were not merged into one head")
	}
	scope.MakeDue(t)
	if runs := scope.Run(t); runs != 1 {
		t.Fatalf("merged head ran %d times", runs)
	}
	if got := scope.Count(t, publications); got != before+1 {
		t.Fatalf("publications %d -> %d, want one", before, got)
	}
	before = scope.Count(t, publications)
	// A stop (traffic over limit, domain claim) is not debounced: it is due at
	// once and pulls a debounced pending republication forward.
	for _, immediate := range []string{edgepublish.SystemTriggerTrafficEnforcement, edgepublish.SystemTriggerDomainOwnership} {
		scope.SettleDeployments(t)
		for _, trigger := range []string{edgepublish.SystemTriggerLineGroup, immediate} {
			if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
				_, err := edgeautopublish.RequestRepublicationTx(t.Context(), tx, edgeautopublish.RepublishRequest{
					ScopeID: scope.ScopeID, Trigger: trigger, SourceResourceID: nodeA, Operation: "site.batch.disable",
					SourceRequestID: "immediate/" + trigger, Debounce: time.Hour})
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
		if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
			AND state='pending' AND due_at<=clock_timestamp()`); got != 1 {
			t.Fatalf("%s was debounced", immediate)
		}
		if runs := scope.Run(t); runs != 1 {
			t.Fatalf("%s ran %d times", immediate, runs)
		}
	}
	// A line group trigger that changes no node publishes nothing.
	scope.SettleDeployments(t)
	scope.Request(t, edgepublish.SystemTriggerLineGroup)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomeUnchanged || scope.Count(t, publications) != before+2 {
		t.Fatalf("no-op republication: %+v, publications=%d", attempt, scope.Count(t, publications))
	}
}

// The automatic channel publishes to the nodes that can take a release and
// holds (lists) the ones that cannot, instead of refusing the release; an
// upgrade of a held node republishes it through the scope's policy.
func TestAutomaticPublicationExcludesIncapableNodesAndCatchesUpAfterUpgrade(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 12), scope.AddNode(t, 11)
	scope.EnableAutomaticPolicy(t, nodeA, nodeB)
	store := edgeautopublish.NewStore(scope.Pool)
	worker, err := edgeautopublish.NewWorker(store, scope.AutomaticService(t, store), edgeautopublish.WorkerConfig{
		WorkerID: "syspub-auto", LeaseDuration: time.Minute, RetryDelay: 0})
	if err != nil {
		t.Fatal(err)
	}
	watcher := newWatcher(t, scope)
	if _, err := watcher.SweepOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	createRateLimitedStream(t, scope) // queues an automatic stream.create request
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("automatic worker: worked=%v err=%v", worked, err)
	}
	first := scope.LatestPublication(t)
	if !slices.Equal(first.NodeIDs, []uuid.UUID{nodeA}) || !bytes.Contains(first.Snapshot, []byte(`"new_conn_rate"`)) {
		t.Fatalf("automatic publication went to %v, want only the tcp v12 node %s", first.NodeIDs, nodeA)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_capability_publication_holds WHERE scope_id=$1
		AND source_revision=$2 AND refused_node_ids=ARRAY[$3::uuid]`, first.SourceRevision, nodeB); got != 1 {
		t.Fatalf("held node B listed %d times", got)
	}
	scope.SettleDeployments(t)
	scope.UpgradeNode(t, nodeB, 12)
	if queued, err := watcher.SweepOnce(t.Context()); err != nil || queued != 1 {
		t.Fatalf("sweep after B's upgrade queued %d (%v)", queued, err)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1
		AND source_kind='node_capability' AND source_resource_id=$2`, nodeB); got != 1 {
		t.Fatalf("node_capability automatic requests = %d", got)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("automatic worker after upgrade: worked=%v err=%v", worked, err)
	}
	if second := scope.LatestPublication(t); !slices.Equal(second.NodeIDs, sortedNodes(nodeA, nodeB)) ||
		second.SourceRevision <= first.SourceRevision {
		t.Fatalf("catch-up publication went to %v", second.NodeIDs)
	}
}

// A scope with unpublished edits still gets a traffic stop and its release:
// the release is the published source with only that site taken out or put
// back, and no draft (edited origins, a new site) reaches the artifact.
func TestSystemRepublishStopOverlayNeverCarriesDrafts(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	second := scope.AddSite(t, "second.example.com", 18082)
	if err := scope.PublishManually(t, "syspub-overlay", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	if !bytes.Contains(scope.LatestBundle(t), []byte(`"host":"203.0.113.10"`)) {
		t.Fatal("rendered bundle check cannot see origins")
	}
	scope.EditSiteOrigin(t, scope.SiteID, "203.0.113.77")
	scope.EditSiteOrigin(t, second, "203.0.113.88")
	scope.AddSite(t, "draft-only.example.com", 18083)
	drafts := [][]byte{[]byte("203.0.113.77"), []byte("203.0.113.88"), []byte("draft-only.example.com")}
	assertNoDraft := func(stage string) {
		t.Helper()
		publication, bundle := scope.LatestPublication(t), scope.LatestBundle(t)
		for _, draft := range drafts {
			if bytes.Contains(publication.Snapshot, draft) || bytes.Contains(bundle, draft) {
				t.Fatalf("%s: artifact carries draft %s", stage, draft)
			}
		}
	}

	scope.SuspendSite(t, "traffic_exceeded", second) // immediate, no debounce
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished {
		t.Fatalf("stop with drafts: outcome %s", attempt.Outcome)
	}
	stopped := scope.LatestPublication(t)
	if bytes.Contains(stopped.Snapshot, []byte(second.String())) || !bytes.Contains(stopped.Snapshot, []byte(scope.SiteID.String())) {
		t.Fatal("stop overlay did not take out exactly the stopped site")
	}
	assertNoDraft("stop")
	if got := scope.Count(t, `SELECT count(*) FROM edge_publication_compile_inputs WHERE configuration_scope_id=$1
		AND overlay AND source_revision=$2`, stopped.SourceRevision); got != 1 {
		t.Fatal("stop overlay publication not marked as an overlay")
	}

	scope.SettleDeployments(t)
	scope.SuspendSite(t, "active", second)
	scope.Run(t)
	restored := scope.LatestPublication(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished {
		t.Fatalf("release with drafts: %+v error=%v", attempt, attempt.ErrorClass)
	}
	if !bytes.Contains(restored.Snapshot, []byte(second.String())) || !bytes.Contains(scope.LatestBundle(t), []byte("203.0.113.10")) {
		t.Fatal("release did not put the site back with its published origin")
	}
	assertNoDraft("release")

	// An overdue secondary verification stops a site the same way (317 hold).
	// Queued as traffic_enforcement until g9e adds its own trigger kind.
	scope.SettleDeployments(t)
	scope.HoldForSecondaryVerification(t, second, true, edgepublish.SystemTriggerTrafficEnforcement)
	scope.Run(t)
	if held := scope.LatestPublication(t); bytes.Contains(held.Snapshot, []byte(second.String())) {
		t.Fatal("secondary verification stop was not taken out")
	}
	assertNoDraft("secondary verification stop")
	scope.SettleDeployments(t)
	scope.HoldForSecondaryVerification(t, second, false, edgepublish.SystemTriggerTrafficEnforcement)
	scope.Run(t)
	if released := scope.LatestPublication(t); !bytes.Contains(released.Snapshot, []byte(second.String())) {
		t.Fatal("secondary verification release did not put the site back")
	}
	assertNoDraft("secondary verification release")

	// Once the tenant publishes, its edits go out and the clean path resumes.
	scope.SettleDeployments(t)
	if err := scope.PublishManually(t, "syspub-overlay-tenant", nodeA); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(scope.LatestBundle(t), []byte("203.0.113.77")) {
		t.Fatal("tenant publication lost its edit")
	}
}
