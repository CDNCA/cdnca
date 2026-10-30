package main

import (
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/artifactsetdist"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgestatus"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildNodeArtifactSetDistributor delivers node artifact sets (PA-01, ADR
// 0007 section 4.3) through the edge deployment channel, from the control
// plane's local artifacts (artifactsync: artifact_objects / local_artifacts;
// the artifact syncer wakes it after a round that changed them). It reads
// with the installation's lease features (nil trust: only free entries, as
// artifactsync does). It needs the edge publication signer, the key agents
// verify deployments with; without it there is nothing to sign and no
// distributor.
func buildNodeArtifactSetDistributor(pool *pgxpool.Pool, signer *edgePublishArtifactSigner,
	trust *entitlementguard.TrustStore) (*artifactsetdist.Distributor, error) {
	if signer == nil {
		return nil, nil
	}
	deployments, err := edgedeployment.NewStore(pool)
	if err != nil {
		return nil, err
	}
	// cdncaCE: the community guard grants base features and market purchases
	// without a lease, so the feature recheck applies with or without trust.
	store := artifactsync.NewStore(pool, time.Now).WithFeatures(entitlementguard.NewGuard(pool, time.Now, trust))
	// A delivery ending on a node wakes the distributor for the next one
	// (edgestatus notifies on commit; O2).
	return artifactsetdist.New(artifactsetdist.Config{Pool: pool, Deployments: deployments, Source: store, Signer: signer,
		WakeChannel: edgestatus.NodeArtifactDeliveryChannel})
}

// wakeNodeArtifactSets wakes the distributor (none: nothing to wake), e.g.
// after a site publishes rule pack mounts; a sealed pack still waits for the
// artifact syncer to wrap its key for each node (WrapNodeKeys).
func wakeNodeArtifactSets(distributor *artifactsetdist.Distributor) func() {
	return func() {
		if distributor != nil {
			distributor.Wake()
		}
	}
}
