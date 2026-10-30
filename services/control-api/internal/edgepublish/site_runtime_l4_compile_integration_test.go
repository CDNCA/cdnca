//go:build integration

package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/jackc/pgx/v5"
)

// compiledSiteRuntimeL4 is the scope's L4 part of a site runtime release at
// revision: the shared stream artifact's streams and the release's required
// capabilities, compiled as the publisher does (bindSiteRuntimeV2Streams,
// siteRuntimeStreamFragment).
type compiledSiteRuntimeL4 struct {
	Streams      []edgeconfig.L4StreamRuntimeV2
	Capabilities []*agentv1.Capability
	// Artifact is the L4 runtime file the node receives (nil without streams).
	Artifact []byte
}

func (fixture *publishFixture) compileSiteRuntimeL4(t *testing.T, tx pgx.Tx, revision int64) compiledSiteRuntimeL4 {
	t.Helper()
	streams, err := loadStreamFacts(t.Context(), tx, fixture.scopeID)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := loadL4V2LifecycleProtocols(t.Context(), tx, fixture.scopeID, revision)
	if err != nil {
		t.Fatal(err)
	}
	document := siteRuntimeV2Document{ConfigVersionID: "01990000-0000-7000-8000-000000000001", SourceRevision: revision}
	bindSiteRuntimeV2Streams(&document, fixture.tenantID, streams, lifecycle)
	result := compiledSiteRuntimeL4{Capabilities: siteRuntimeV2CapabilitiesForTest(document.RequiredCapabilities)}
	_, files, err := siteRuntimeStreamFragment(document, fixture.service.config.HealthPort)
	if err != nil {
		t.Fatalf("compile L4 streams: %v", err)
	}
	if artifact := files[edgeconfig.L4RuntimeV2ArtifactPath]; len(artifact) > 0 {
		var wire struct {
			Streams []edgeconfig.L4StreamRuntimeV2 `json:"streams"`
		}
		if err := json.Unmarshal(artifact, &wire); err != nil {
			t.Fatal(err)
		}
		result.Streams, result.Artifact = wire.Streams, artifact
	}
	return result
}

// Bundle is the L4 artifact as a release file set.
func (compiled compiledSiteRuntimeL4) Bundle() edgeconfig.Bundle {
	files := map[string][]byte{}
	if compiled.Artifact != nil {
		files[edgeconfig.L4RuntimeV2ArtifactPath] = compiled.Artifact
	}
	return edgeconfig.Bundle{Files: files}
}

func capabilityVersion(capabilities []*agentv1.Capability, name agentv1.CapabilityName) uint32 {
	for _, capability := range capabilities {
		if capability.GetName() == name {
			return capability.GetApiVersion()
		}
	}
	return 0
}
