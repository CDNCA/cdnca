package edgedeployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

const testSiteRuntimeV2MediaType = "application/vnd.cdnca.edge-site-runtime-bundle+json;version=2"

func TestNormalizeConfigRequestRejectsInvalidIntegrityAndLimits(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := validArtifactInput(t, uuid.New(), "edge-key-1", publicKey, privateKey, []byte("wire"))
	base := PersistConfigRequest{
		ConfigurationScopeID: uuid.New(), CanonicalSnapshot: []byte(`{"sites":[]}`),
		GeneratorName: "edge-generator", GeneratorVersion: "1.0.0", Artifacts: []ArtifactInput{valid},
		IdempotencyKey: "config-limit-test",
	}
	tests := []struct {
		name   string
		change func(*PersistConfigRequest)
	}{
		{name: "empty snapshot", change: func(value *PersistConfigRequest) { value.CanonicalSnapshot = nil }},
		{name: "snapshot too large", change: func(value *PersistConfigRequest) {
			value.CanonicalSnapshot = make([]byte, maxConfigSnapshotBytes+1)
		}},
		{name: "artifact size mismatch", change: func(value *PersistConfigRequest) { value.Artifacts[0].SizeBytes++ }},
		{name: "artifact digest mismatch", change: func(value *PersistConfigRequest) { value.Artifacts[0].SHA256[0] ^= 0xff }},
		{name: "artifact signature mismatch", change: func(value *PersistConfigRequest) { value.Artifacts[0].Signature[0] ^= 0xff }},
		{name: "artifact too large", change: func(value *PersistConfigRequest) {
			value.Artifacts[0].WireBytes = make([]byte, maxArtifactWireBytes+1)
			value.Artifacts[0].SizeBytes = uint64(len(value.Artifacts[0].WireBytes))
			digest := sha256.Sum256(value.Artifacts[0].WireBytes)
			value.Artifacts[0].SHA256 = digest[:]
			value.Artifacts[0].Signature = ed25519.Sign(privateKey, value.Artifacts[0].WireBytes)
		}},
		{name: "artifact total too large", change: func(value *PersistConfigRequest) {
			value.Artifacts = make([]ArtifactInput, maxConfigArtifactBytes/maxArtifactWireBytes+1)
			for index := range value.Artifacts {
				value.Artifacts[index] = validArtifactInput(
					t, uuid.New(), "edge-key-1", publicKey, privateKey, make([]byte, maxArtifactWireBytes),
				)
			}
		}},
		{name: "too many artifacts", change: func(value *PersistConfigRequest) {
			value.Artifacts = make([]ArtifactInput, maxConfigArtifacts+1)
			for index := range value.Artifacts {
				value.Artifacts[index] = validArtifactInput(t, uuid.New(), "edge-key-1", publicKey, privateKey, []byte{byte(index)})
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.CanonicalSnapshot = append([]byte(nil), base.CanonicalSnapshot...)
			request.Artifacts = append([]ArtifactInput(nil), base.Artifacts...)
			request.Artifacts[0].SHA256 = append([]byte(nil), base.Artifacts[0].SHA256...)
			request.Artifacts[0].Signature = append([]byte(nil), base.Artifacts[0].Signature...)
			test.change(&request)
			if _, err := normalizeConfigRequest(request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeConfigRequest() error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestNormalizeRolloutRequestRejectsProtocolLimits(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	request := CreateRolloutRequest{
		ConfigurationScopeID: uuid.New(), ConfigVersionID: uuid.New(),
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, NodeIDs: []uuid.UUID{uuid.New()},
		HealthCheck: HealthCheckPolicy{time.Minute, time.Second, 1}, Deadline: now.Add(time.Hour),
		IdempotencyKey: "rollout-limit", RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
	}
	request.RequiredCapabilities = make([]*agentv1.Capability, maxRequiredCapabilities+1)
	for index := range request.RequiredCapabilities {
		request.RequiredCapabilities[index] = &agentv1.Capability{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: uint32(index + 1),
		}
	}
	if _, err := normalizeRolloutRequest(request, now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("capability limit error = %v, want ErrInvalidInput", err)
	}
	request.RequiredCapabilities = nil
	request.HealthCheck.ActivationTimeout = time.Millisecond + time.Microsecond
	if _, err := normalizeRolloutRequest(request, now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("sub-millisecond policy error = %v, want ErrInvalidInput", err)
	}
}

func TestMarshalDeploymentCommandEnforcesOneMiBLimit(t *testing.T) {
	command := &agentv1.DeploymentCommand{DeploymentId: strings.Repeat("x", maxDeploymentCommandBytes)}
	if _, err := marshalDeploymentCommand(command); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("marshalDeploymentCommand() error = %v, want ErrInvalidInput", err)
	}
	command.DeploymentId = uuid.NewString()
	first, err := marshalDeploymentCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := marshalDeploymentCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("deterministic marshal changed bytes")
	}
}

// The whole site runtime bundle is retired: a config persisting one and a
// rollout requiring site_runtime without site objects are both refused.
func TestSiteRuntimeV2BundleConfigBindingRefused(t *testing.T) {
	scopeID, configID := uuid.New(), uuid.New()
	capabilities := testSiteRuntimeV2Capabilities()
	artifact, canonical := testSiteRuntimeV2Artifact(t, scopeID, configID, capabilities)
	for _, requireCapabilities := range []bool{false, true} {
		if err := validateSiteRuntimeV2ConfigBinding(scopeID, configID, canonical, []ArtifactInput{artifact}, capabilities, requireCapabilities); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("site runtime bundle accepted (require=%t): %v", requireCapabilities, err)
		}
	}
	plain := artifact
	plain.MediaType = "application/octet-stream"
	if err := validateSiteRuntimeV2ConfigBinding(scopeID, configID, canonical, []ArtifactInput{plain}, capabilities, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("site_runtime rollout without site objects accepted: %v", err)
	}
	if err := validateSiteRuntimeV2ConfigBinding(scopeID, configID, canonical, []ArtifactInput{plain}, capabilities[:len(capabilities)-1], true); err != nil {
		t.Fatalf("configuration without site_runtime rejected: %v", err)
	}
}

func testSiteRuntimeV2Artifact(t *testing.T, scopeID, configID uuid.UUID, capabilities []*agentv1.Capability) (ArtifactInput, []byte) {
	t.Helper()
	certificatePEM := testOriginTrustCertificate(t)
	trustDigest := sha256.Sum256(certificatePEM)
	capabilityJSON := make([]string, len(capabilities))
	for index, capability := range capabilities {
		capabilityJSON[index] = fmt.Sprintf(`{"name":%q,"api_version":%d}`, testSiteRuntimeV2CapabilityName(capability.Name), capability.ApiVersion)
	}
	canonical := []byte(fmt.Sprintf(`{"config_version_id":%q,"configuration_scope_id":%q,"required_capabilities":[%s],"schema":"cdnca.edge.site-runtime/v2","sites":[{"origin_pools":[{"origins":[{"trust_ref":"sha256:%s"}]}]}],"source_revision":1}`,
		configID.String(), scopeID.String(), strings.Join(capabilityJSON, ","), hex.EncodeToString(trustDigest[:])))
	wire := marshalTestBundle(t, map[string][]byte{
		"site-runtime.v2.json": canonical,
		"origin-trust/" + hex.EncodeToString(trustDigest[:]) + ".pem": certificatePEM,
	})
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := validArtifactInput(t, uuid.New(), "site-runtime-v2-key", publicKey, privateKey, wire)
	artifact.MediaType = testSiteRuntimeV2MediaType
	return artifact, canonical
}

func testSiteRuntimeV2Capabilities() []*agentv1.Capability {
	return []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.MinSiteRuntimeVersion},
	}
}

func testSiteRuntimeV2CapabilityName(name agentv1.CapabilityName) string {
	switch name {
	case agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1:
		return "http1"
	case agentv1.CapabilityName_CAPABILITY_NAME_HTTP_2:
		return "http2"
	case agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME:
		return "site_runtime"
	default:
		panic("unexpected test capability")
	}
}

func testOriginTrustCertificate(t *testing.T) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "origin test CA"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func marshalTestBundle(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	manifest := edgeconfig.Manifest{Files: make([]edgeconfig.FileManifest, 0, len(files))}
	for path, content := range files {
		digest := sha256.Sum256(content)
		manifest.Files = append(manifest.Files, edgeconfig.FileManifest{Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])})
	}
	manifestDigest, err := edgeconfig.ManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := edgeconfig.MarshalBundle(edgeconfig.Bundle{Manifest: manifest, ManifestSHA256: manifestDigest, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func cloneTestBundleFiles(files map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(files))
	for path, content := range files {
		result[path] = bytes.Clone(content)
	}
	return result
}

func testSiteRuntimeV2TrustPath(files map[string][]byte) string {
	for path := range files {
		if strings.HasPrefix(path, "origin-trust/") {
			return path
		}
	}
	panic("test trust path missing")
}

func validArtifactInput(
	t *testing.T,
	id uuid.UUID,
	keyID string,
	publicKey ed25519.PublicKey,
	privateKey ed25519.PrivateKey,
	wire []byte,
) ArtifactInput {
	t.Helper()
	digest := sha256.Sum256(wire)
	return ArtifactInput{
		ID: id, Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
		WireBytes: append([]byte(nil), wire...), SizeBytes: uint64(len(wire)), SHA256: digest[:],
		Signature: ed25519.Sign(privateKey, wire), SigningKeyID: keyID,
		SigningPublicKey:   append(ed25519.PublicKey(nil), publicKey...),
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: "application/octet-stream",
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
	}
}
