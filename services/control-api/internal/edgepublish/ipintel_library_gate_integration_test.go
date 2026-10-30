//go:build integration

package edgepublish

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// G3-c gate against the real schema (PA-01): a node is refused carrier / IDC /
// ASN / region rules until its applied node artifact set
// (node_artifact_applied_items, written from the node's receipt) holds an IP
// intelligence library; another item does not count, and a node whose set no
// longer holds the library is refused again.
func TestIPIntelRulesWaitForAnAppliedLibraryItem(t *testing.T) {
	fixture := newPublishFixture(t)
	required := siteRuntimeV2SecurityRequired(ipIntelSite())
	validate := func() error {
		var err error
		if txErr := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			err = ValidateFeatureCapabilityTargets(t.Context(), tx, []uuid.UUID{fixture.nodeID}, required)
			return nil
		}); txErr != nil {
			t.Fatal(txErr)
		}
		return err
	}
	assertPending := func(stage string) {
		t.Helper()
		var refusal *TargetCapabilityError
		if err := validate(); !errors.As(err, &refusal) || refusal.NodeID != fixture.nodeID || !refusal.ipIntelLibraryPending() {
			t.Fatalf("%s: %v, want the node refused for a missing library", stage, err)
		}
	}
	assertPending("no applied set")
	apply := func(artifactID, mediaType string) {
		t.Helper()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO node_artifact_applied_items(
			node_id,artifact_id,version,item_revision,media_type,sha256,set_revision,applied_at) VALUES($1,$2,'7',7,$3,$4,1,now())`,
			fixture.nodeID, artifactID, mediaType, artifactset.Digest([]byte(artifactID))); err != nil {
			t.Fatal(err)
		}
	}
	apply("dataset/other", "application/vnd.cdnca.test-dataset;version=1")
	assertPending("applied set without a library")
	apply("ipintel/base", artifactset.MediaTypeIPIntel)
	if err := validate(); err != nil {
		t.Fatalf("node whose applied set holds a library: %v", err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM node_artifact_applied_items WHERE node_id=$1 AND artifact_id='ipintel/base'`,
		fixture.nodeID); err != nil {
		t.Fatal(err)
	}
	assertPending("library removed from the applied set")
	// Releases without IP intelligence rules never looked at libraries.
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		return ValidateFeatureCapabilityTargets(t.Context(), tx, []uuid.UUID{uuid.New()},
			siteRuntimeV2SecurityRequired(edgeconfig.Site{}))
	}); err != nil {
		t.Fatalf("release without IP intelligence rules: %v", err)
	}
}
