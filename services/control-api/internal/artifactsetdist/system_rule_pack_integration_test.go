//go:build integration

package artifactsetdist

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/google/uuid"
)

// systemPackSource adds the enabled official system packs (artifactsync.SystemRulePacks) to the
// harness source: what nodes must hold without any site mount.
type systemPackSource struct {
	*staticSource
	system []artifactsync.MountedRulePack
}

func (source *systemPackSource) MountedRulePacks(context.Context) ([]artifactsync.MountedRulePack, error) {
	return nil, nil
}
func (source *systemPackSource) SystemRulePacks(context.Context) ([]artifactsync.MountedRulePack, error) {
	return source.system, nil
}
func (source *systemPackSource) NodeKeyWraps(context.Context, uuid.UUID) ([]artifactsync.NodeKeyWrap, error) {
	return nil, nil
}

// RI-12 e2e, control half: an official system/crs-tuning version reaches the node artifact set
// with no site mount, the node applies it (receipt recorded by edgestatus), and the receipt
// summary the rule intel report carries counts it applied; the next version rejected by the
// node is counted rejected (what pauses the license-side rollout).
func TestSystemRulePackReachesNodesAndReceiptsAreSummed(t *testing.T) {
	harness := newDistHarness(t)
	tuning := artifactsync.MountedRulePack{PackID: "system/crs-tuning", Version: "1.0.0", Content: []byte(`{"tuning":1}`)}
	tuning.SHA256 = artifactset.Digest(tuning.Content)
	source := &systemPackSource{staticSource: harness.source, system: []artifactsync.MountedRulePack{tuning}}
	harness.distributor.config.Source = source
	// The summary names rule_pack/<sha256> items by the stored system pack.
	harness.exec(`INSERT INTO rule_packs(pack_id,layer,current_version,update_policy,created_at,updated_at)
		VALUES('system/crs-tuning','system',NULL,'auto',now(),now())`)
	store := artifactsync.NewStore(harness.pool, nil)
	addVersion := func(pack artifactsync.MountedRulePack) {
		harness.exec(`INSERT INTO rule_pack_artifacts(pack_id,version,engine,engine_min_version,name,sha256,size_bytes,content,source,
			state,downloaded_at,created_at) VALUES($1,$2,'modsecurity',1,'CRS 官方调优',$3,$4,$5,'catalog','downloaded',now(),now())`,
			pack.PackID, pack.Version, pack.SHA256, len(pack.Content), pack.Content)
		harness.exec(`UPDATE rule_packs SET current_version=$2 WHERE pack_id=$1`, pack.PackID, pack.Version)
	}
	addVersion(tuning)

	harness.sweep()
	harness.agent(harness.one(artifactset.MediaTypeSegment))
	harness.sweep()
	receipt := harness.agent(harness.one(artifactset.MediaTypeSet))
	if receipt.Result != artifactset.ResultApplied || len(receipt.Items) != 1 ||
		receipt.Items[0].ArtifactID != RulePackArtifactID(tuning.SHA256) {
		t.Fatalf("system pack set receipt %+v", receipt)
	}
	if harness.count(`SELECT count(*) FROM node_artifact_applied_items WHERE node_id=$1 AND artifact_id=$2`,
		harness.nodeID, RulePackArtifactID(tuning.SHA256)) != 1 {
		t.Fatal("applied system pack not recorded")
	}
	summary, err := store.PackReceipts(harness.ctx)
	if err != nil || len(summary) != 1 || summary[0].PackID != "system/crs-tuning" || summary[0].Version != "1.0.0" ||
		summary[0].Applied != 1 || summary[0].Rejected != 0 {
		t.Fatalf("summary after applied %+v %v", summary, err)
	}

	// 1.0.1 the node's installer refuses: rejected item, the node keeps 1.0.0.
	next := artifactsync.MountedRulePack{PackID: "system/crs-tuning", Version: "1.0.1", Content: []byte(`{"tuning":2}`)}
	next.SHA256 = artifactset.Digest(next.Content)
	addVersion(next)
	source.system = []artifactsync.MountedRulePack{next}
	harness.reject = map[string]string{RulePackArtifactID(next.SHA256): artifactset.ReasonInstallRejected}
	harness.sweep()
	harness.agent(harness.one(artifactset.MediaTypeSegment))
	harness.sweep()
	if receipt = harness.agent(harness.one(artifactset.MediaTypeSet)); receipt.Result != artifactset.ResultRejected {
		t.Fatalf("1.0.1 receipt %+v", receipt)
	}
	summary, err = store.PackReceipts(harness.ctx)
	if err != nil || len(summary) != 1 || summary[0].Version != "1.0.1" || summary[0].Rejected != 1 || summary[0].Applied != 0 {
		t.Fatalf("summary after rejected %+v %v", summary, err)
	}
}
