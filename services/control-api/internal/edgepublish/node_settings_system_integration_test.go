//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// System channel, node storage trigger: a manual
// scope whose content its own facts refuse still gets a storage change (the
// release in effect again, publication kind node_settings), and so does a
// scope that turned automatic after the change was queued for it. The
// tenant's rows keep a revision of their own: publishing them after the fix
// works.
func TestSystemRepublicationRedeliversNodeStorageOnRefusedScope(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	scope.DeclareNodeStorage(t, nodeA)
	siteB, subscriptionB := scope.AddSiteOnOwnPackage(t, "nodeset-storage-b.example.com")
	setStorage := func(directory string) {
		t.Helper()
		scope.Exec(t, `UPDATE nodes SET management_settings=management_settings ||
			jsonb_build_object('cache_directory',$2::text,'cache_limit_gb',20) WHERE id=$1`, nodeA, directory)
	}
	setStorage("/data/cdnca-cache-1")
	if err := scope.PublishManually(t, "nodeset-storage-1", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	first := scope.NodeRelease(t, nodeA)
	if first.NodeStorage == nil || first.NodeStorage.CacheDirectory != "/data/cdnca-cache-1" || first.NodeFactsAt <= 0 {
		t.Fatalf("storage did not reach the key document: %+v node_facts_at=%d", first.NodeStorage, first.NodeFactsAt)
	}
	requestStorage := func() {
		t.Helper()
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			_, err := edgeautopublish.RequestRepublicationTx(t.Context(), tx, edgeautopublish.RepublishRequest{
				ScopeID: scope.ScopeID, Trigger: edgepublish.SystemTriggerNodeStorage,
				SourceResourceID: edgeautopublish.NodeNetworksSourceID,
				SourceRequestID:  edgepublish.NodeSettingsRequestPrefixStorage + uuid.NewString(), Immediate: true,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	expectRedelivery := func(step string, base edgepublish.NodeSettingsRelease, directory string) edgepublish.NodeSettingsRelease {
		t.Helper()
		if attempt := scope.LatestAttempt(t); attempt.Outcome != edgepublish.SystemOutcomePublished || attempt.PublicationID == nil {
			t.Fatalf("%s: attempt %+v, want published", step, attempt)
		}
		kind, refusal, baseID := scope.PublicationKind(t)
		if kind != edgepublish.PublicationKindNodeSettings || refusal != edgepublish.AutomaticFailurePackageSubscriptionInactive ||
			baseID == nil || *baseID != base.ConfigVersionID {
			t.Fatalf("%s: publication %s/%s base %v, want node_settings on %s", step, kind, refusal, baseID, base.ConfigVersionID)
		}
		release := scope.NodeRelease(t, nodeA)
		want := siteobject.NodeStorage{CacheDirectory: directory, CacheMaxBytes: 20 << 30}
		if release.NodeStorage == nil || *release.NodeStorage != want || release.ConfigVersionID == base.ConfigVersionID ||
			!slices.Equal(release.Members, base.Members) {
			t.Fatalf("%s: key document storage %+v (want %+v), config %s (base %s), same objects %v", step, release.NodeStorage,
				want, release.ConfigVersionID, base.ConfigVersionID, slices.Equal(release.Members, base.Members))
		}
		// The node keeps its storage from the latest key document: the
		// redelivery's must be later than the release it replaces, or an
		// older release of another scope would win back.
		if release.NodeFactsAt <= base.NodeFactsAt {
			t.Fatalf("%s: node_facts_at %d, base %d", step, release.NodeFactsAt, base.NodeFactsAt)
		}
		if latest := scope.LatestPublication(t); latest.SourceRevision >= scopeRevision(t, scope) {
			t.Fatalf("%s: the redelivery took the tenant's revision %d", step, latest.SourceRevision)
		}
		scope.SettleDeployments(t)
		return release
	}

	// Manual scope, content refused: the storage change still reaches the node.
	scope.RevokeEntitlement(t, subscriptionB)
	setStorage("/data/cdnca-cache-2")
	requestStorage()
	scope.Run(t)
	second := expectRedelivery("manual scope", first, "/data/cdnca-cache-2")

	// Queued while manual, run once the scope is automatic.
	setStorage("/data/cdnca-cache-3")
	requestStorage()
	scope.EnableAutomaticPolicy(t, nodeA)
	scope.Run(t)
	// The base is the release in effect: the first redelivery.
	expectRedelivery("scope turned automatic", second, "/data/cdnca-cache-3")

	// Fixed: the scope's rows publish as content again.
	scope.RebindSite(t, siteB, scope.SubscriptionID)
	if err := scope.PublishManually(t, "nodeset-storage-2", nodeA); err != nil {
		t.Fatal(err)
	}
	if kind, _, _ := scope.PublicationKind(t); kind != edgepublish.PublicationKindContent {
		t.Fatalf("publication after the fix is %s, want content", kind)
	}
}

func scopeRevision(t *testing.T, scope *edgepublish.SystemRepublishScope) int64 {
	t.Helper()
	var revision int64
	if err := scope.Pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		scope.ScopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}
