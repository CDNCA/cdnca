package edgedeployment

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestDynamicRoutingRootBinding(t *testing.T) {
	scopeID, configID := uuid.New(), uuid.New()
	canonical := []byte(`{"schema":"cdnca.edge.site-runtime/v2","required_capabilities":[{"name":"http1","api_version":1},{"name":"site_runtime","api_version":6}]}`)
	digest := sha256.Sum256(canonical)
	publication, _, err := siteobject.BuildV2(siteobject.BuildV2Input{
		ConfigurationScopeID: scopeID.String(), ConfigVersionID: configID.String(), SourceRevision: 1, KeyEpoch: 1,
		RequiredCapabilities: []siteobject.Capability{{Name: "http1", APIVersion: 1}, {Name: "site_runtime", APIVersion: 9}},
		DocumentSHA256:       hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := "x25519:" + hex.EncodeToString(digest[:])
	artifacts := []ArtifactInput{
		{Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION, MediaType: siteObjectRootMediaTypeV2, WireBytes: publication.RootBytes,
			Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE},
		{Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION, MediaType: siteObjectKeyMediaType, RecipientKeyID: &key,
			Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM},
	}
	nine := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 9}}
	if ok, err := validateSiteObjectConfigBinding(scopeID, configID, canonical, artifacts, nine, true); !ok || err != nil {
		t.Fatalf("v2 root rejected: %v %v", ok, err)
	}
	eight := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 8}}
	if _, err := validateSiteObjectConfigBinding(scopeID, configID, canonical, artifacts, eight, true); err == nil {
		t.Fatal("a v2 root rolled out with site_runtime 8")
	}
	if _, err := validateSiteObjectConfigBinding(scopeID, configID, []byte(`{"schema":"cdnca.edge.site-runtime/v2","required_capabilities":[{"name":"site_runtime","api_version":6}]}`),
		artifacts, nil, false); err == nil {
		t.Fatal("a v2 root bound to another document")
	}
}
