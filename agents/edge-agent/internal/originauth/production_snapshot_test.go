package originauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

func TestSITE09EncryptedSnapshotInstallsFullPolicyAndKeepsLKGOnActivationFailure(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &site09Runtime{}
	installer, err := NewProductionSnapshotInstaller(filepath.Join(root, "policy"), filepath.Join(root, "credentials"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic, recipientPrivate := site09Recipient(t)
	signingPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x27}, ed25519.SeedSize))
	scopeID, tenantID, nodeID := uuid.New(), uuid.New(), uuid.New()
	firstRule, firstRef := uuid.New(), uuid.New()
	first := site09EncryptedSnapshot(t, signingPrivate, recipientPublic, recipientPrivate, scopeID, tenantID, nodeID, 1,
		[]productionSnapshotRule{site09Rule(firstRule, uuid.New(), 1, firstRef)}, []productionSnapshotCredential{site09Credential(firstRef, ProviderS3, "AKIA-FIRST")})
	publication, err := installer.Install(t.Context(), first)
	if err != nil || publication.PolicyVersion != 1 || publication.CurrentPath == "" || len(runtime.activations) != 1 {
		t.Fatalf("publication=%+v activations=%d err=%v", publication, len(runtime.activations), err)
	}
	raw, err := os.ReadFile(publication.CurrentPath)
	if err != nil || !bytes.Contains(raw, []byte(firstRule.String())) || bytes.Contains(raw, []byte("AKIA-FIRST")) {
		t.Fatalf("current policy=%q err=%v", raw, err)
	}
	credentialPath := filepath.Join(root, "credentials", scopeID.String(), firstRef.String()+".json")
	info, err := os.Stat(credentialPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode=%v err=%v", info, err)
	}

	secondRef := uuid.New()
	second := site09EncryptedSnapshot(t, signingPrivate, recipientPublic, recipientPrivate, scopeID, tenantID, nodeID, 2,
		[]productionSnapshotRule{site09Rule(uuid.New(), uuid.New(), 2, secondRef)}, []productionSnapshotCredential{site09Credential(secondRef, ProviderS3, "AKIA-SECOND")})
	secondPublication, err := installer.Install(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(secondPublication.CurrentPath)
	if err != nil || bytes.Contains(baseline, []byte(firstRule.String())) || !bytes.Contains(baseline, []byte(secondRef.String())) {
		t.Fatalf("full replacement policy=%q err=%v", baseline, err)
	}
	runtime.failActivate = true
	thirdRef := uuid.New()
	third := site09EncryptedSnapshot(t, signingPrivate, recipientPublic, recipientPrivate, scopeID, tenantID, nodeID, 3,
		[]productionSnapshotRule{site09Rule(uuid.New(), uuid.New(), 3, thirdRef)}, []productionSnapshotCredential{site09Credential(thirdRef, ProviderS3, "AKIA-THIRD")})
	if _, err := installer.Install(t.Context(), third); !errors.Is(err, ErrProductionActivation) {
		t.Fatalf("activation error=%v", err)
	}
	restored, err := os.ReadFile(publication.CurrentPath)
	if err != nil || !bytes.Equal(restored, baseline) || bytes.Contains(restored, []byte("AKIA-THIRD")) {
		t.Fatalf("failed activation advanced current: %q err=%v", restored, err)
	}
}

func TestSITE09SnapshotRejectsTenantOriginProviderAndRecipientCrossBinding(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	runtime := &site09Runtime{}
	installer, err := NewProductionSnapshotInstaller(filepath.Join(root, "policy"), filepath.Join(root, "credentials"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := site09Recipient(t)
	signer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x28}, ed25519.SeedSize))
	scopeID, tenantID, nodeID, ref := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	artifact := site09EncryptedSnapshot(t, signer, publicKey, privateKey, scopeID, tenantID, nodeID, 1,
		[]productionSnapshotRule{site09Rule(uuid.New(), uuid.New(), 1, ref)}, []productionSnapshotCredential{site09Credential(ref, ProviderS3, "AKIA")})
	artifact.ExpectedTenantScopeID = uuid.NewString()
	if _, err := installer.Install(t.Context(), artifact); err == nil {
		t.Fatal("tenant cross-binding was accepted")
	}
	artifact = site09EncryptedSnapshot(t, signer, publicKey, privateKey, scopeID, tenantID, nodeID, 1,
		[]productionSnapshotRule{site09Rule(uuid.New(), uuid.New(), 1, ref)}, []productionSnapshotCredential{site09Credential(ref, ProviderOSS, "AKIA")})
	if _, err := installer.Install(t.Context(), artifact); err == nil {
		t.Fatal("provider cross-binding was accepted")
	}
	artifact = site09EncryptedSnapshot(t, signer, publicKey, privateKey, scopeID, tenantID, nodeID, 1,
		[]productionSnapshotRule{site09Rule(uuid.New(), uuid.New(), 1, ref)}, []productionSnapshotCredential{site09Credential(ref, ProviderS3, "AKIA")})
	artifact.RecipientKeyID = "x25519:" + strings.Repeat("0", 64)
	if _, err := installer.Install(t.Context(), artifact); err == nil {
		t.Fatal("recipient cross-binding was accepted")
	}
	if len(runtime.activations) != 0 {
		t.Fatal("invalid artifact reached OpenResty")
	}
}

func TestSITE09OpenRestyIncludesBindExactSiteSourceRuleAndEndpoint(t *testing.T) {
	policyPath := "/var/lib/cdnca/origin-auth/current.json"
	binding := OriginBinding{SiteID: uuid.NewString(), SourcePosition: 3, RuleID: uuid.NewString(), Endpoint: "https://s3.us-east-1.amazonaws.com"}
	httpInclude, accessInclude, err := OpenRestyIncludes(policyPath, binding)
	if err != nil || !strings.Contains(httpInclude, "originauth.engine") || !strings.Contains(httpInclude, policyPath) ||
		!strings.Contains(accessInclude, binding.RuleID) || !strings.Contains(accessInclude, binding.Endpoint) || !strings.Contains(accessInclude, "ngx.HTTP_BAD_GATEWAY") {
		t.Fatalf("http=%q access=%q err=%v", httpInclude, accessInclude, err)
	}
	root, _ := filepath.EvalSymlinks(t.TempDir())
	policy := filepath.Join(root, "current.json")
	if err := os.WriteFile(policy, []byte(`{"schema_version":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	runtime, err := NewProductionOpenResty(ProductionOpenRestyConfig{Binary: "/usr/local/openresty/bin/openresty",
		RuntimePrefix: filepath.Join(root, "runtime"), ConfigFile: "nginx.conf", LuaRoot: "/usr/local/share/cdnca",
		Run: func(_ context.Context, binary string, arguments ...string) error {
			calls = append(calls, append([]string{binary}, arguments...))
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	candidate := ProductionCandidate{PublicationRevision: 3, PolicyPath: policy, Bindings: []OriginBinding{binding}}
	if err := runtime.Precheck(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(t.Context(), candidate); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || !strings.Contains(strings.Join(calls[0], " "), " -t ") || !strings.Contains(strings.Join(calls[2], " "), " -s reload ") {
		t.Fatalf("calls=%v", calls)
	}
}

type site09Runtime struct {
	failActivate bool
	activations  []ProductionCandidate
}

func (runtime *site09Runtime) Precheck(context.Context, ProductionCandidate) error { return nil }
func (runtime *site09Runtime) Activate(_ context.Context, candidate ProductionCandidate) error {
	if runtime.failActivate {
		runtime.failActivate = false
		return errors.New("reload failed")
	}
	runtime.activations = append(runtime.activations, candidate)
	return nil
}

func site09Recipient(t *testing.T) ([]byte, []byte) {
	t.Helper()
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicWire, _ := publicKey.MarshalBinary()
	privateWire, _ := privateKey.MarshalBinary()
	return publicWire, privateWire
}

func site09Rule(ruleID, siteID uuid.UUID, position int, ref uuid.UUID) productionSnapshotRule {
	return productionSnapshotRule{RuleID: ruleID.String(), SiteID: siteID.String(), SourcePosition: position, Provider: ProviderS3,
		Algorithm: AlgorithmS3, Endpoint: "https://s3.us-east-1.amazonaws.com", PathPrefix: "/", Region: "us-east-1", Service: "s3",
		SignatureTTLSeconds: 300, CurrentCredentialRevisionRef: ref.String()}
}

func site09Credential(ref uuid.UUID, provider, accessKey string) productionSnapshotCredential {
	return productionSnapshotCredential{RevisionRef: ref.String(), Provider: provider, AccessKeyID: accessKey, SecretAccessKey: "site09-secret",
		NotBeforeUnix: 1_700_000_000, ExpiresAtUnix: 1_900_000_000}
}

func site09EncryptedSnapshot(t *testing.T, signer ed25519.PrivateKey, recipientPublic, recipientPrivate []byte, scopeID, tenantID, nodeID uuid.UUID,
	revision uint64, rules []productionSnapshotRule, credentials []productionSnapshotCredential) EncryptedProductionSnapshot {
	t.Helper()
	publicDigest := sha256.Sum256(recipientPublic)
	recipientKeyID := "x25519:" + hex.EncodeToString(publicDigest[:])
	activation := productionSnapshotActivation{SchemaVersion: ProductionSnapshotActivationSchema, EventID: uuid.NewString(), DeploymentID: uuid.NewString(),
		Attempt: 1, ConfigVersionID: uuid.NewString(), ArtifactID: uuid.NewString(), NodeID: nodeID.String(), RecipientKeyID: recipientKeyID,
		TenantID: tenantID.String(), TenantScopeID: scopeID.String(), PublicationID: uuid.NewString(), PublicationRevision: revision}
	document := productionSnapshotDocument{SchemaVersion: ProductionSnapshotSchema, Activation: activation,
		Publication: productionSnapshotPublication{SchemaVersion: productionPublicationSchema, TenantScopeID: scopeID.String(), PublicationRevision: revision, Rules: rules},
		Credentials: credentials}
	plaintext, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	transport := ProductionArtifactTransport{EventID: activation.EventID, DeploymentID: activation.DeploymentID, Attempt: activation.Attempt,
		ConfigVersionID: activation.ConfigVersionID, ArtifactID: activation.ArtifactID, NodeID: activation.NodeID, RecipientKeyID: recipientKeyID,
		SigningKeyID: "origin-auth-signing-v1", Kind: agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE,
		SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
		Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: ProductionSnapshotMediaType,
		EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM}
	transport.SizeBytes = uint64(len(plaintext) + hpke.KEM_X25519_HKDF_SHA256.Scheme().CiphertextSize() + 16)
	info, aad, err := productionArtifactContext(transport)
	if err != nil {
		t.Fatal(err)
	}
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	publicKey, err := scheme.UnmarshalBinaryPublicKey(recipientPublic)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := productionArtifactSuite.NewSender(publicKey, info)
	if err != nil {
		t.Fatal(err)
	}
	encapsulation, sealer, err := sender.Setup(bytes.NewReader(bytes.Repeat([]byte{0x53}, 128)))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := sealer.Seal(plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	wire := append(encapsulation, ciphertext...)
	digest := sha256.Sum256(wire)
	transport.SHA256 = digest[:]
	transport.Signature = ed25519.Sign(signer, wire)
	transport.SigningPublicKey = signer.Public().(ed25519.PublicKey)
	return EncryptedProductionSnapshot{ProductionArtifactTransport: transport, WireBytes: wire, RecipientPrivateKey: recipientPrivate,
		ExpectedNodeID: nodeID.String(), ExpectedTenantScopeID: scopeID.String(), ExpectedPublicationRevision: revision}
}
