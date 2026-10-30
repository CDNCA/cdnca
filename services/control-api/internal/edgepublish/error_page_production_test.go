package edgepublish

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
)

func TestSITE13ErrorPageArtifactMapsToDeterministicDeploymentInput(t *testing.T) {
	scopeID := uuid.New()
	wire := []byte(`{"schema":"cdnca.edge.error-page-snapshot/v1"}`)
	digest := sha256.Sum256(wire)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	binding := errorpagecontrol.ProductionSnapshotBinding{
		TenantID: uuid.NewString(), ConfigurationScopeID: scopeID.String(), PublicationRevision: 11,
	}
	artifact := errorpagecontrol.ProductionSnapshotArtifact{
		ProductionBundleArtifact: errorpagecontrol.ProductionBundleArtifact{
			WireBytes: wire, SHA256: fmtHexDigest(digest), Signature: ed25519.Sign(private, wire),
			SigningKeyID: "error-page-signing-v1", MediaType: errorpagecontrol.ProductionSnapshotMediaType,
		},
		Binding: binding, SigningPublicKey: private.Public().(ed25519.PublicKey),
	}
	configID, input, snapshotDigest, err := errorPageArtifactInput(scopeID, artifact)
	if err != nil {
		t.Fatal(err)
	}
	replayConfigID, replayInput, replaySnapshotDigest, err := errorPageArtifactInput(scopeID, artifact)
	if err != nil {
		t.Fatal(err)
	}
	if configID == uuid.Nil || configID != replayConfigID || input.ID == uuid.Nil || input.ID != replayInput.ID ||
		snapshotDigest != replaySnapshotDigest || snapshotDigest != digest ||
		input.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION || input.MediaType != errorpagecontrol.ProductionSnapshotMediaType ||
		input.SizeBytes != uint64(len(wire)) || !bytes.Equal(input.SHA256, digest[:]) ||
		!bytes.Equal(input.SigningPublicKey, private.Public().(ed25519.PublicKey)) {
		t.Fatalf("config=%s input=%+v snapshot=%x", configID, input, snapshotDigest)
	}
}

func fmtHexDigest(value [sha256.Size]byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, sha256.Size*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&15]
	}
	return string(result)
}
