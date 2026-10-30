package artifactsetdist

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/enginemodule/enginemoduletest"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// engineModuleArtifact is a local engine module artifact (and its bytes)
// built for arch, as artifactsync stores it.
func engineModuleArtifact(t *testing.T, arch string) (LocalArtifact, []byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("release"))
	content := enginemoduletest.Encoded(t, []enginemoduletest.Signer{{KeyID: "release-1", Private: ed25519.NewKeyFromSeed(seed[:])}},
		enginemoduletest.Options{Architecture: arch})
	entry, err := artifactcatalog.EngineModuleEntry(content, 4, "")
	if err != nil {
		t.Fatal(err)
	}
	return LocalArtifact{ArtifactID: entry.ArtifactID, Kind: entry.Kind, Version: entry.Version, Revision: entry.Revision,
		SHA256: entry.SHA256, Size: entry.Size, MediaType: entry.MediaType, RequiresCapability: entry.RequiresCapability}, content
}

// Each node gets the engine module of its own OpenResty version and
// architecture, only when it declares WAF_CRS_MODULE; other items go to all.
func TestNodeItemsPickTheNodesEngineModule(t *testing.T) {
	library := []byte("library")
	amd, amdBytes := engineModuleArtifact(t, "amd64")
	arm, armBytes := engineModuleArtifact(t, "arm64")
	var desired []prepared
	for _, pair := range []struct {
		artifact LocalArtifact
		content  []byte
	}{{ipIntelArtifact(1, library), library}, {amd, amdBytes}, {arm, armBytes}} {
		if !nodeArtifact(pair.artifact) {
			t.Fatalf("%s is not a node artifact", pair.artifact.ArtifactID)
		}
		entry, err := prepareItem(pair.artifact, pair.content, artifactset.MaxSegmentBytes)
		if err != nil {
			t.Fatal(err)
		}
		desired = append(desired, entry)
	}
	crs := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1}
	node := func(os, arch, openresty string, features ...*agentv1.Capability) *agentv1.AgentCapabilities {
		return &agentv1.AgentCapabilities{OperatingSystem: os, Architecture: arch, OpenrestyVersion: openresty, Features: features}
	}
	ids := func(items []artifactset.Item) []string {
		result := []string{}
		for _, item := range items {
			result = append(result, item.ArtifactID)
		}
		return result
	}
	for name, test := range map[string]struct {
		capabilities *agentv1.AgentCapabilities
		want         []string
	}{
		"amd64 node":        {node("linux", "amd64", enginemoduletest.DefaultOpenResty, crs), []string{IPIntelArtifactID, amd.ArtifactID}},
		"arm64 node":        {node("linux", "arm64", enginemoduletest.DefaultOpenResty, crs), []string{IPIntelArtifactID, arm.ArtifactID}},
		"no WAF_CRS_MODULE": {node("linux", "amd64", enginemoduletest.DefaultOpenResty), []string{IPIntelArtifactID}},
		"other OpenResty":   {node("linux", "amd64", "1.27.1.2", crs), []string{IPIntelArtifactID}},
		"OpenResty unknown": {node("linux", "amd64", "", crs), []string{IPIntelArtifactID}},
		"not linux":         {node("darwin", "amd64", enginemoduletest.DefaultOpenResty, crs), []string{IPIntelArtifactID}},
	} {
		if got := ids(nodeItems(desired, test.capabilities, nil)); len(got) != len(test.want) || got[len(got)-1] != test.want[len(test.want)-1] {
			t.Fatalf("%s: items %v, want %v", name, got, test.want)
		}
	}
	forged := amd
	forged.ArtifactID = "engine_module/something-else"
	if nodeArtifact(forged) {
		t.Fatal("engine module with a non-platform id is a node artifact")
	}
}
