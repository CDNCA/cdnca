package artifactsetdist

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A sealed pack reaches only a node holding its key wrap, carrying it; a
// plain pack reaches every node without one.
func TestNodeItemsRulePacksAndKeyWraps(t *testing.T) {
	plainBytes, sealedBytes := []byte(`{"plain":true}`), []byte(`{"sealed":true}`)
	plain, err := mountedRulePackItem(artifactsync.MountedRulePack{PackID: "system/a", Version: "1.0.0",
		SHA256: artifactset.Digest(plainBytes), Content: plainBytes}, artifactset.MaxSegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := mountedRulePackItem(artifactsync.MountedRulePack{PackID: "dev/x/b", Version: "2.0.0",
		SHA256: artifactset.Digest(sealedBytes), Sealed: true, Content: sealedBytes}, artifactset.MaxSegmentBytes)
	if err != nil {
		t.Fatal(err)
	}
	if plain.item.ArtifactID != "rule_pack/"+plain.item.SHA256 || plain.item.MediaType != artifactset.MediaTypeRulePack {
		t.Fatalf("plain item = %+v", plain.item)
	}
	desired := []prepared{plain, sealed}
	capabilities := &agentv1.AgentCapabilities{}
	if items := nodeItems(desired, capabilities, nil); len(items) != 1 || items[0].KeyWrap != nil {
		t.Fatalf("items without wraps = %+v", items)
	}
	wraps := map[string]artifactsync.NodeKeyWrap{sealed.item.SHA256: {RecipientKeyID: "x25519:" + plain.item.SHA256,
		WrappedKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}
	items := nodeItems(desired, capabilities, wraps)
	if len(items) != 2 || items[1].KeyWrap == nil || items[1].KeyWrap.WrappedKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("items with wraps = %+v", items)
	}
	if desired[1].item.KeyWrap != nil {
		t.Fatal("nodeItems wrote the wrap into the shared desired item")
	}
}

// packSource is a staticSource with rule packs: mounted and system packs.
type packSource struct {
	staticSource
	mounted, system []artifactsync.MountedRulePack
}

func (source *packSource) MountedRulePacks(context.Context) ([]artifactsync.MountedRulePack, error) {
	return source.mounted, nil
}

func (source *packSource) SystemRulePacks(context.Context) ([]artifactsync.MountedRulePack, error) {
	return source.system, nil
}

func (source *packSource) NodeKeyWraps(context.Context, uuid.UUID) ([]artifactsync.NodeKeyWrap, error) {
	return nil, nil
}

// Enabled official system packs are node items without a site mount; a
// version that is also mounted is one item.
func TestDesiredIncludesSystemRulePacks(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	tuning := artifactsync.MountedRulePack{PackID: "system/crs-tuning", Version: "1.0.1", Content: []byte("tuning")}
	tuning.SHA256 = artifactset.Digest(tuning.Content)
	intel := artifactsync.MountedRulePack{PackID: "system/scanner-signatures", Version: "1.0.0", Content: []byte("intel"), Sealed: true}
	intel.SHA256 = artifactset.Digest(intel.Content)
	source := &packSource{mounted: []artifactsync.MountedRulePack{tuning}, system: []artifactsync.MountedRulePack{tuning, intel}}
	distributor, err := New(Config{Pool: new(pgxpool.Pool), Deployments: new(edgedeployment.Store), Source: source,
		Signer: testSigner{id: "edge-key", private: private}})
	if err != nil {
		t.Fatal(err)
	}
	desired, err := distributor.desired(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(desired) != 2 {
		t.Fatalf("desired = %d items, want 2 (tuning once, intel)", len(desired))
	}
	ids := map[string]bool{}
	for _, entry := range desired {
		ids[entry.item.ArtifactID] = true
		if entry.item.ArtifactID == RulePackArtifactID(intel.SHA256) && !entry.sealed {
			t.Fatal("sealed system pack lost its sealed flag")
		}
	}
	if !ids[RulePackArtifactID(tuning.SHA256)] || !ids[RulePackArtifactID(intel.SHA256)] {
		t.Fatalf("desired ids = %v", ids)
	}
}
