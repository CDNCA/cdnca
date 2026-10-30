package edgepublish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestSITE09OriginAuthSourceKeepsCanonicalSnapshotSecretFreeAndBuildsPerNodeHPKE(t *testing.T) {
	scopeID, tenantID := uuid.New(), uuid.New()
	ref := uuid.New()
	snapshot := originauthcontrol.PublicationSnapshot{
		SchemaVersion: "cdnca.control.originauth-publication/v1", TenantScopeID: scopeID, PublicationRevision: 9,
		Rules: []originauthcontrol.PublicationRule{{RuleID: uuid.New(), SiteID: uuid.New(), SourcePosition: 1,
			Provider: originauthcontrol.ProviderS3, Algorithm: originauthcontrol.AlgorithmS3,
			Endpoint: "https://s3.us-east-1.amazonaws.com", PathPrefix: "/", Region: "us-east-1", Service: "s3",
			SignatureTTLSeconds: 300, CurrentCredentialRevisionRef: ref}},
	}
	canonical, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	material := originauthcontrol.ProductionMaterial{
		PublicationID: uuid.New(), TenantID: tenantID, TenantScopeID: scopeID, PublicationRevision: 9,
		Snapshot: snapshot, CanonicalSnapshot: canonical,
		Credentials: []originauthcontrol.ProductionCredentialMaterial{{RevisionRef: ref, Provider: originauthcontrol.ProviderS3,
			Secret: originauthcontrol.CredentialSecret{AccessKeyID: "AKIA-SITE09", SecretAccessKey: "site09-secret",
				NotBefore: time.Unix(1_700_000_000, 0).UTC(), ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}}},
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x39}, ed25519.SeedSize))
	producer, err := newOriginAuthArtifactProducer(site09ArtifactSigner{private: private}, bytes.NewReader(bytes.Repeat([]byte{0x41}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewOriginAuthSecretRolloutSource(scopeID, site09ProductionSource{material: material}, producer)
	if err != nil {
		t.Fatal(err)
	}
	rollout, err := source(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rollout.CanonicalSnapshot, canonical) || bytes.Contains(rollout.CanonicalSnapshot, []byte("site09-secret")) || rollout.PayloadDigest != sha256.Sum256(canonical) {
		t.Fatal("rollout canonical snapshot contains secrets or changed identity")
	}

	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	recipientPublic, recipientPrivate, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicWire, _ := recipientPublic.MarshalBinary()
	privateWire, _ := recipientPrivate.MarshalBinary()
	recipientDigest := sha256.Sum256(publicWire)
	binding := edgedeployment.SecretArtifactBinding{EventID: uuid.New(), DeploymentID: uuid.New(), RolloutID: uuid.New(), Attempt: 1,
		ConfigVersionID: uuid.New(), ArtifactID: uuid.New(), NodeID: uuid.New(), RecipientKeyID: "x25519:" + hex.EncodeToString(recipientDigest[:]), RecipientPublicKey: publicWire}
	artifact, err := rollout.Builder(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.MediaType != OriginAuthArtifactMediaType || artifact.RecipientKeyID == nil || *artifact.RecipientKeyID != binding.RecipientKeyID ||
		!ed25519.Verify(private.Public().(ed25519.PublicKey), artifact.WireBytes, artifact.Signature) {
		t.Fatalf("artifact binding=%+v", artifact)
	}
	document, err := decryptSITE09ArtifactWithAgentContract(artifact, binding, privateWire)
	if err != nil {
		t.Fatalf("Agent-compatible HPKE decrypt failed: %v", err)
	}
	if document.Activation.NodeID != binding.NodeID.String() || document.Activation.TenantScopeID != scopeID.String() ||
		document.Activation.PublicationRevision != 9 || len(document.Credentials) != 1 || document.Credentials[0].Provider != originauthcontrol.ProviderS3 {
		t.Fatalf("document=%+v", document)
	}

	wrongNodePublic, wrongNodePrivate, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongNodePrivateWire, _ := wrongNodePrivate.MarshalBinary()
	wrongNodePublicWire, _ := wrongNodePublic.MarshalBinary()
	wrongNodeDigest := sha256.Sum256(wrongNodePublicWire)
	if _, err := decryptSITE09ArtifactWithAgentContract(artifact, binding, wrongNodePrivateWire); err == nil {
		t.Fatal("artifact decrypted with another node's private key")
	}

	mutations := []struct {
		name   string
		change func(*edgedeployment.SecretArtifactBinding, *edgedeployment.ArtifactInput)
	}{
		{name: "event replay", change: func(value *edgedeployment.SecretArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.EventID = uuid.New()
		}},
		{name: "deployment replay", change: func(value *edgedeployment.SecretArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.DeploymentID = uuid.New()
		}},
		{name: "attempt replay", change: func(value *edgedeployment.SecretArtifactBinding, _ *edgedeployment.ArtifactInput) { value.Attempt++ }},
		{name: "configuration replay", change: func(value *edgedeployment.SecretArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.ConfigVersionID = uuid.New()
		}},
		{name: "artifact replay", change: func(value *edgedeployment.SecretArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.ArtifactID = uuid.New()
		}},
		{name: "node replay", change: func(value *edgedeployment.SecretArtifactBinding, _ *edgedeployment.ArtifactInput) {
			value.NodeID = uuid.New()
		}},
		{name: "recipient rotation", change: func(_ *edgedeployment.SecretArtifactBinding, value *edgedeployment.ArtifactInput) {
			recipient := "x25519:" + hex.EncodeToString(wrongNodeDigest[:])
			value.RecipientKeyID = &recipient
		}},
		{name: "descriptor size", change: func(_ *edgedeployment.SecretArtifactBinding, value *edgedeployment.ArtifactInput) { value.SizeBytes++ }},
		{name: "descriptor media type", change: func(_ *edgedeployment.SecretArtifactBinding, value *edgedeployment.ArtifactInput) {
			value.MediaType += ";replay=1"
		}},
		{name: "ciphertext tamper", change: func(_ *edgedeployment.SecretArtifactBinding, value *edgedeployment.ArtifactInput) {
			value.WireBytes[len(value.WireBytes)-1] ^= 0x80
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			candidateBinding := binding
			candidateArtifact := artifact
			candidateArtifact.WireBytes = bytes.Clone(artifact.WireBytes)
			test.change(&candidateBinding, &candidateArtifact)
			if _, err := decryptSITE09ArtifactWithAgentContract(candidateArtifact, candidateBinding, privateWire); err == nil {
				t.Fatal("mutated deployment binding decrypted")
			}
		})
	}
}

func TestSITE09OriginAuthEncryptionFailureReturnsNoPublishableArtifact(t *testing.T) {
	public, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicWire, _ := public.MarshalBinary()
	digest := sha256.Sum256(publicWire)
	binding := edgedeployment.SecretArtifactBinding{
		EventID: uuid.New(), DeploymentID: uuid.New(), RolloutID: uuid.New(), Attempt: 1,
		ConfigVersionID: uuid.New(), ArtifactID: uuid.New(), NodeID: uuid.New(),
		RecipientKeyID: "x25519:" + hex.EncodeToString(digest[:]), RecipientPublicKey: publicWire,
	}
	material := site09TestProductionMaterial(uuid.New(), uuid.New())
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	producer, err := newOriginAuthArtifactProducer(site09FailingSigner{private: private}, bytes.NewReader(bytes.Repeat([]byte{0x61}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := producer.Build(t.Context(), binding, material)
	if !errors.Is(err, ErrOriginAuthArtifact) {
		t.Fatalf("Build() error = %v", err)
	}
	if artifact.ID != uuid.Nil || len(artifact.WireBytes) != 0 || artifact.RecipientKeyID != nil {
		t.Fatalf("failed build returned publishable artifact: %+v", artifact)
	}
}

type site09ProductionSource struct {
	material originauthcontrol.ProductionMaterial
}

func (source site09ProductionSource) Build(context.Context, pgx.Tx, uuid.UUID) (originauthcontrol.ProductionMaterial, error) {
	return source.material, nil
}

type site09ArtifactSigner struct{ private ed25519.PrivateKey }

func (signer site09ArtifactSigner) ArtifactSigningKeyID() string { return "origin-auth-signing-v1" }
func (signer site09ArtifactSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer site09ArtifactSigner) SignArtifact(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

type site09FailingSigner struct{ private ed25519.PrivateKey }

func (signer site09FailingSigner) ArtifactSigningKeyID() string { return "origin-auth-signing-v1" }
func (signer site09FailingSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (site09FailingSigner) SignArtifact(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

func decryptSITE09ArtifactWithAgentContract(artifact edgedeployment.ArtifactInput, binding edgedeployment.SecretArtifactBinding, privateWire []byte) (originAuthArtifactDocument, error) {
	info, aad := site09AgentArtifactContext(binding, artifact)
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(privateWire)
	if err != nil {
		return originAuthArtifactDocument{}, err
	}
	encapsulationSize := scheme.CiphertextSize()
	if len(artifact.WireBytes) < encapsulationSize+16 {
		return originAuthArtifactDocument{}, errors.New("truncated artifact")
	}
	receiver, err := originAuthArtifactSuite.NewReceiver(privateKey, info)
	if err != nil {
		return originAuthArtifactDocument{}, err
	}
	opener, err := receiver.Setup(artifact.WireBytes[:encapsulationSize])
	if err != nil {
		return originAuthArtifactDocument{}, err
	}
	plaintext, err := opener.Open(artifact.WireBytes[encapsulationSize:], aad)
	if err != nil {
		return originAuthArtifactDocument{}, err
	}
	var document originAuthArtifactDocument
	if err := json.Unmarshal(plaintext, &document); err != nil {
		return originAuthArtifactDocument{}, err
	}
	return document, nil
}

func site09AgentArtifactContext(binding edgedeployment.SecretArtifactBinding, artifact edgedeployment.ArtifactInput) ([]byte, []byte) {
	recipientKeyID := ""
	if artifact.RecipientKeyID != nil {
		recipientKeyID = *artifact.RecipientKeyID
	}
	encoded := []byte("cdnca-edge-artifact-hpke-binding-v1\x00")
	for _, value := range []string{binding.EventID.String(), binding.DeploymentID.String()} {
		encoded = site09AppendHPKEString(encoded, value)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, binding.Attempt)
	for _, value := range []string{binding.ConfigVersionID.String(), binding.ArtifactID.String(), binding.NodeID.String(), recipientKeyID} {
		encoded = site09AppendHPKEString(encoded, value)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE))
	encoded = binary.BigEndian.AppendUint64(encoded, artifact.SizeBytes)
	encoded = site09AppendHPKEString(encoded, artifact.SigningKeyID)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(artifact.SignatureAlgorithm))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(artifact.Compression))
	encoded = site09AppendHPKEString(encoded, artifact.MediaType)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(artifact.EncryptionAlgorithm))
	digest := sha256.Sum256(encoded)
	return append([]byte("cdnca-edge-artifact-hpke-info-v1\x00"), digest[:]...), append([]byte("cdnca-edge-artifact-hpke-aad-v1\x00"), encoded...)
}

func site09AppendHPKEString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...)
}

func site09TestProductionMaterial(scopeID, tenantID uuid.UUID) originauthcontrol.ProductionMaterial {
	revisionRef := uuid.New()
	snapshot := originauthcontrol.PublicationSnapshot{
		SchemaVersion: "cdnca.control.originauth-publication/v1", TenantScopeID: scopeID, PublicationRevision: 9,
		Rules: []originauthcontrol.PublicationRule{{RuleID: uuid.New(), SiteID: uuid.New(), SourcePosition: 1,
			Provider: originauthcontrol.ProviderS3, Algorithm: originauthcontrol.AlgorithmS3,
			Endpoint: "https://s3.us-east-1.amazonaws.com", PathPrefix: "/", Region: "us-east-1", Service: "s3",
			SignatureTTLSeconds: 300, CurrentCredentialRevisionRef: revisionRef}},
	}
	canonical, _ := json.Marshal(snapshot)
	return originauthcontrol.ProductionMaterial{
		PublicationID: uuid.New(), TenantID: tenantID, TenantScopeID: scopeID, PublicationRevision: 9,
		Snapshot: snapshot, CanonicalSnapshot: canonical,
		Credentials: []originauthcontrol.ProductionCredentialMaterial{{RevisionRef: revisionRef, Provider: originauthcontrol.ProviderS3,
			Secret: originauthcontrol.CredentialSecret{AccessKeyID: "AKIA-SITE09", SecretAccessKey: "site09-secret",
				NotBefore: time.Unix(1_700_000_000, 0).UTC(), ExpiresAt: time.Unix(1_900_000_000, 0).UTC()}}},
	}
}
