package certificatepublish

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

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cloudflare/circl/hpke"
	"github.com/google/uuid"
)

type testArtifactSigner struct {
	id      string
	private ed25519.PrivateKey
	err     error
}

func (signer *testArtifactSigner) ArtifactSigningKeyID() string { return signer.id }
func (signer *testArtifactSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer *testArtifactSigner) SignArtifact(_ context.Context, value []byte) ([]byte, error) {
	if signer.err != nil {
		return nil, signer.err
	}
	return ed25519.Sign(signer.private, value), nil
}

func TestProducerFrozenHPKEVectorDecryptsWithConsumerContract(t *testing.T) {
	request, receiverPrivate := frozenBuildRequest(t)
	signer := &testArtifactSigner{
		id:      "certificate-signing-v1",
		private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize)),
	}
	producer, err := newProducer(signer, bytes.NewReader(bytes.Repeat([]byte{0x33}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := producer.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ID != request.ArtifactID || artifact.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE ||
		artifact.SizeBytes != uint64(len(artifact.WireBytes)) || artifact.MediaType != CertificateArtifactMediaType ||
		artifact.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM ||
		artifact.SignatureAlgorithm != agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519 ||
		artifact.Compression != agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE ||
		artifact.RecipientKeyID == nil || *artifact.RecipientKeyID != request.RecipientKeyID {
		t.Fatalf("unexpected artifact descriptor: %#v", artifact)
	}
	digest := sha256.Sum256(artifact.WireBytes)
	if !bytes.Equal(digest[:], artifact.SHA256) ||
		!ed25519.Verify(artifact.SigningPublicKey, artifact.WireBytes, artifact.Signature) {
		t.Fatal("artifact digest/signature mismatch")
	}

	metadata := metadataFromArtifact(request, artifact)
	info, aad := frozenConsumerContext(t, metadata)
	if got := hex.EncodeToString(info); got != "63646e63612d656467652d61727469666163742d68706b652d696e666f2d763100be76345f905156ea9220e0b0ede64fa7504efd86319e04c1328dc7d833cfdfc2" {
		t.Fatalf("info vector = %s", got)
	}
	if got := sha256.Sum256(aad); hex.EncodeToString(got[:]) != "185bad8b83ac40ceba7c4b71cde8504021920e973f5aceef94a0bba7f2b432b0" {
		t.Fatalf("AAD digest vector = %x", got)
	}
	plaintext := decryptFrozenArtifact(t, receiverPrivate, artifact.WireBytes, info, aad)
	defer clearBytes(plaintext)
	if got := sha256.Sum256(plaintext); hex.EncodeToString(got[:]) != "ef62a8ae571bf361cd18abdb3ccbd23b91699978af46f107be2e0e8736f9a92f" {
		t.Fatalf("plaintext digest vector = %x", got)
	}
	assertFrozenDocument(t, plaintext, request)
	if got := sha256.Sum256(artifact.WireBytes); hex.EncodeToString(got[:]) != "097ce18b4a03e55796717cc3a0783bb3bb45d9d3096e9f711a0fc1d70115bade" {
		t.Fatalf("wire digest vector = %x", got)
	}
}

func TestProducerUsesFreshCiphertextAndBindsEveryAADField(t *testing.T) {
	request, receiverPrivate := frozenBuildRequest(t)
	signer := &testArtifactSigner{
		id:      "certificate-signing-v1",
		private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize)),
	}
	firstProducer, _ := newProducer(signer, bytes.NewReader(bytes.Repeat([]byte{0x44}, 256)))
	secondProducer, _ := newProducer(signer, bytes.NewReader(bytes.Repeat([]byte{0x55}, 256)))
	first, err := firstProducer.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondProducer.Build(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.WireBytes, second.WireBytes) {
		t.Fatal("independent HPKE publications reused ciphertext")
	}

	base := metadataFromArtifact(request, first)
	tests := []struct {
		name   string
		mutate func(*artifactMetadata)
	}{
		{name: "event", mutate: func(value *artifactMetadata) { value.EventID = uuid.NewString() }},
		{name: "deployment", mutate: func(value *artifactMetadata) { value.DeploymentID = uuid.NewString() }},
		{name: "attempt", mutate: func(value *artifactMetadata) { value.Attempt++ }},
		{name: "config", mutate: func(value *artifactMetadata) { value.ConfigVersionID = uuid.NewString() }},
		{name: "artifact", mutate: func(value *artifactMetadata) { value.ArtifactID = uuid.NewString() }},
		{name: "recipient", mutate: func(value *artifactMetadata) { value.RecipientKeyID += "x" }},
		{name: "kind", mutate: func(value *artifactMetadata) { value.Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION }},
		{name: "size", mutate: func(value *artifactMetadata) { value.SizeBytes++ }},
		{name: "signing key", mutate: func(value *artifactMetadata) { value.SigningKeyID += "x" }},
		{name: "signature", mutate: func(value *artifactMetadata) { value.SignatureAlgorithm++ }},
		{name: "compression", mutate: func(value *artifactMetadata) { value.Compression++ }},
		{name: "media type", mutate: func(value *artifactMetadata) { value.MediaType += "x" }},
		{name: "encryption", mutate: func(value *artifactMetadata) { value.EncryptionAlgorithm++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := base
			test.mutate(&mutated)
			info, aad := frozenConsumerContext(t, mutated)
			if plaintext, err := tryDecryptFrozen(receiverPrivate, first.WireBytes, info, aad); err == nil {
				clearBytes(plaintext)
				t.Fatal("tampered AAD decrypted")
			}
		})
	}
}

func TestProducerBuildRemovalEncryptsSignedEmptyBundle(t *testing.T) {
	request, receiverPrivate := frozenBuildRequest(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, ed25519.SeedSize))
	producer, err := newProducer(
		&testArtifactSigner{id: "certificate-signing-v1", private: key},
		bytes.NewReader(bytes.Repeat([]byte{0x76}, 256)),
	)
	if err != nil {
		t.Fatal(err)
	}
	removal := RemovalBuildRequest{
		EventID: request.EventID, DeploymentID: request.DeploymentID, Attempt: request.Attempt,
		ConfigVersionID: request.ConfigVersionID, ArtifactID: request.ArtifactID,
		RecipientKeyID: request.RecipientKeyID, RecipientPublicKey: request.RecipientPublicKey,
		TenantScopeID: request.Materials[0].TenantScopeID,
		RemovedSites:  []RemovedSite{{TenantID: request.Materials[0].TenantID, SiteID: request.Materials[0].SiteID, BindingRevision: 5}},
	}
	artifact, err := producer.BuildRemoval(t.Context(), removal)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), artifact.WireBytes, artifact.Signature) {
		t.Fatal("removal artifact signature did not verify")
	}
	metadata := metadataFromArtifact(removal.buildRequest(), artifact)
	info, aad := frozenConsumerContext(t, metadata)
	plaintext := decryptFrozenArtifact(t, receiverPrivate, artifact.WireBytes, info, aad)
	defer clearBytes(plaintext)
	if !bytes.Contains(plaintext, []byte(`"certificates":[]`)) ||
		!bytes.Contains(plaintext, []byte(`"bindings":[]`)) {
		t.Fatalf("removal document is not an explicit empty bundle: %s", plaintext)
	}
	var document struct {
		Activation struct {
			Certificates []json.RawMessage `json:"certificates"`
		} `json:"activation"`
		Bundle struct {
			Bindings []json.RawMessage `json:"bindings"`
		} `json:"bundle"`
	}
	if err := json.Unmarshal(plaintext, &document); err != nil {
		t.Fatal(err)
	}
	if document.Activation.Certificates == nil || document.Bundle.Bindings == nil ||
		len(document.Activation.Certificates) != 0 || len(document.Bundle.Bindings) != 0 {
		t.Fatalf("removal document=%+v", document)
	}
	if _, err := producer.Build(t.Context(), requestWithMaterials(request, nil)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ordinary Build accepted an empty bundle: %v", err)
	}
}

func TestEncodeDocumentPreallocatesSingleBackingArray(t *testing.T) {
	request, _ := frozenBuildRequest(t)
	maxDocumentBytes := maxArtifactWireBytes - hpke.KEM_X25519_HKDF_SHA256.Scheme().CiphertextSize() - hpkeTagSize

	t.Run("multiple maximum escape expansion materials", func(t *testing.T) {
		materials := allocationTestMaterials(request.Materials[0], 3)
		for index := range materials {
			materials[index].CertificatePEM = bytes.Repeat([]byte{0x01}, maxCertificateBytes)
			materials[index].PrivateKeyPEM = bytes.Repeat([]byte{0x01}, maxPrivateKeyBytes)
		}
		assertSingleDocumentBacking(t, request, materials, -1)
	})

	t.Run("exact wire limit", func(t *testing.T) {
		materials := allocationTestMaterials(request.Materials[0], 26)
		for index := range materials[:25] {
			materials[index].CertificatePEM = bytes.Repeat([]byte{'C'}, maxCertificateBytes)
			materials[index].PrivateKeyPEM = bytes.Repeat([]byte{'K'}, maxPrivateKeyBytes)
		}
		materials[25].CertificatePEM = []byte{'C'}
		materials[25].PrivateKeyPEM = []byte{'K'}
		partial, err := encodeDocument(request, materials)
		if err != nil {
			t.Fatal(err)
		}
		remaining := maxDocumentBytes - len(partial)
		clearBytes(partial)
		if remaining <= 0 || remaining > maxCertificateBytes-1 {
			t.Fatalf("unexpected exact-limit remainder: %d", remaining)
		}
		materials[25].CertificatePEM = bytes.Repeat([]byte{'C'}, remaining+1)
		assertSingleDocumentBacking(t, request, materials, maxDocumentBytes)
		materials[25].CertificatePEM = bytes.Repeat([]byte{'C'}, remaining+2)
		if document, err := encodeDocument(request, materials); !errors.Is(err, ErrInvalidInput) || document != nil {
			clearBytes(document)
			t.Fatalf("oversized document result=%d error=%v", len(document), err)
		}
	})
}

func assertSingleDocumentBacking(
	t *testing.T,
	request BuildRequest,
	materials []certificateasset.PublicationMaterial,
	wantLength int,
) {
	t.Helper()
	capacity, err := certificateDocumentCapacity(request, materials)
	if err != nil {
		t.Fatal(err)
	}
	storage := make([]byte, capacity)
	document := appendCertificateDocument(storage[:0], request, materials)
	defer clearBytes(document)
	if len(document) == 0 || &document[0] != &storage[0] || cap(document) != capacity {
		t.Fatalf("document backing changed: len=%d cap=%d want-cap=%d", len(document), cap(document), capacity)
	}
	encoded, err := encodeDocument(request, materials)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(encoded)
	if !bytes.Equal(document, encoded) || len(encoded) != capacity || cap(encoded) != capacity {
		t.Fatalf("preallocated output differs: len=%d cap=%d want=%d", len(encoded), cap(encoded), capacity)
	}
	if wantLength >= 0 && len(document) != wantLength {
		t.Fatalf("document len=%d want=%d", len(document), wantLength)
	}
}

func allocationTestMaterials(base certificateasset.PublicationMaterial, count int) []certificateasset.PublicationMaterial {
	materials := make([]certificateasset.PublicationMaterial, count)
	for index := range materials {
		materials[index] = base
		materials[index].SiteID[15] = byte(index + 1)
	}
	return materials
}

func TestProducerRejectsInvalidInputAndSignerFailure(t *testing.T) {
	request, _ := frozenBuildRequest(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	producer, err := newProducer(&testArtifactSigner{id: "certificate-signing-v1", private: key}, bytes.NewReader(bytes.Repeat([]byte{0x77}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*BuildRequest)
	}{
		{name: "attempt zero", mutate: func(value *BuildRequest) { value.Attempt = 0 }},
		{name: "attempt two", mutate: func(value *BuildRequest) { value.Attempt = 2 }},
		{name: "wrong recipient", mutate: func(value *BuildRequest) { value.RecipientKeyID += "x" }},
		{name: "duplicate site", mutate: func(value *BuildRequest) { value.Materials = append(value.Materials, value.Materials[0]) }},
		{name: "missing certificate version UUID", mutate: func(value *BuildRequest) { value.Materials[0].CertificateVersionID = uuid.Nil }},
		{name: "missing private key", mutate: func(value *BuildRequest) { value.Materials[0].PrivateKeyPEM = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := request
			invalid.Materials = append([]certificateasset.PublicationMaterial(nil), request.Materials...)
			test.mutate(&invalid)
			if _, err := producer.Build(context.Background(), invalid); !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrRecipientKey) {
				t.Fatalf("Build() error = %v", err)
			}
		})
	}
	failing, err := newProducer(&testArtifactSigner{
		id: "certificate-signing-v1", private: key, err: errors.New("signer unavailable"),
	}, bytes.NewReader(bytes.Repeat([]byte{0x77}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Build(context.Background(), request); !errors.Is(err, ErrSigning) {
		t.Fatalf("signer failure = %v", err)
	}
}

func TestProducerRejectsCrossTenantCertificateMaterialsBeforeEncryption(t *testing.T) {
	request, _ := frozenBuildRequest(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	producer, err := newProducer(&testArtifactSigner{id: "certificate-signing-v1", private: key},
		bytes.NewReader(bytes.Repeat([]byte{0x77}, 256)))
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*certificateasset.PublicationMaterial)
	}{
		{name: "tenant", mutate: func(value *certificateasset.PublicationMaterial) { value.TenantID = uuid.New() }},
		{name: "tenant scope", mutate: func(value *certificateasset.PublicationMaterial) { value.TenantScopeID = uuid.New() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			candidate.Materials = append([]certificateasset.PublicationMaterial(nil), request.Materials...)
			second := candidate.Materials[0]
			second.SiteID = uuid.New()
			test.mutate(&second)
			candidate.Materials = append(candidate.Materials, second)
			if _, err := producer.Build(t.Context(), candidate); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Build() cross-%s error = %v", test.name, err)
			}
		})
	}
}

func frozenBuildRequest(t *testing.T) (BuildRequest, []byte) {
	t.Helper()
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	publicKey, privateKey := scheme.DeriveKeyPair(bytes.Repeat([]byte{0x2a}, scheme.SeedSize()))
	publicBytes, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := privateKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(publicBytes)
	return BuildRequest{
		EventID:      uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		DeploymentID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Attempt: 1,
		ConfigVersionID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		ArtifactID:      uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		RecipientKeyID:  "x25519:" + hex.EncodeToString(digest[:]), RecipientPublicKey: publicBytes,
		Materials: []certificateasset.PublicationMaterial{{
			TenantID:             uuid.MustParse("55555555-5555-4555-8555-555555555555"),
			TenantScopeID:        uuid.MustParse("66666666-6666-4666-8666-666666666666"),
			SiteID:               uuid.MustParse("77777777-7777-4777-8777-777777777777"),
			AssetID:              uuid.MustParse("88888888-8888-4888-8888-888888888888"),
			CertificateVersionID: uuid.MustParse("99999999-9999-4999-8999-999999999999"), CertificateVersion: 9,
			BindingRevision: 4, SiteDomain: "edge.example.test", CertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"),
			PrivateKeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n"),
		}},
	}, privateBytes
}

func requestWithMaterials(request BuildRequest, materials []certificateasset.PublicationMaterial) BuildRequest {
	request.Materials = materials
	return request
}

func metadataFromArtifact(request BuildRequest, artifact edgedeployment.ArtifactInput) artifactMetadata {
	return artifactMetadata{
		EventID: request.EventID.String(), DeploymentID: request.DeploymentID.String(),
		Attempt: request.Attempt, ConfigVersionID: request.ConfigVersionID.String(),
		ArtifactID: artifact.ID.String(), RecipientKeyID: *artifact.RecipientKeyID,
		Kind: artifact.Kind, SizeBytes: artifact.SizeBytes, SigningKeyID: artifact.SigningKeyID,
		SignatureAlgorithm: artifact.SignatureAlgorithm, Compression: artifact.Compression,
		MediaType: artifact.MediaType, EncryptionAlgorithm: artifact.EncryptionAlgorithm,
	}
}

func frozenConsumerContext(t *testing.T, metadata artifactMetadata) ([]byte, []byte) {
	t.Helper()
	binding := append([]byte(nil), hpkeBindingDomain...)
	for _, value := range []string{metadata.EventID, metadata.DeploymentID} {
		binding = appendFrozenString(binding, value)
	}
	binding = binary.BigEndian.AppendUint32(binding, metadata.Attempt)
	for _, value := range []string{metadata.ConfigVersionID, metadata.ArtifactID, metadata.RecipientKeyID} {
		binding = appendFrozenString(binding, value)
	}
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Kind))
	binding = binary.BigEndian.AppendUint64(binding, metadata.SizeBytes)
	binding = appendFrozenString(binding, metadata.SigningKeyID)
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.SignatureAlgorithm))
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.Compression))
	binding = appendFrozenString(binding, metadata.MediaType)
	binding = binary.BigEndian.AppendUint32(binding, uint32(metadata.EncryptionAlgorithm))
	digest := sha256.Sum256(binding)
	return append([]byte(hpkeInfoDomain), digest[:]...), append([]byte(hpkeAADDomain), binding...)
}

func appendFrozenString(target []byte, value string) []byte {
	target = binary.BigEndian.AppendUint32(target, uint32(len(value)))
	return append(target, value...)
}

func decryptFrozenArtifact(t *testing.T, privateKey, wire, info, aad []byte) []byte {
	t.Helper()
	plaintext, err := tryDecryptFrozen(privateKey, wire, info, aad)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func tryDecryptFrozen(privateKey, wire, info, aad []byte) ([]byte, error) {
	scheme := hpke.KEM_X25519_HKDF_SHA256.Scheme()
	key, err := scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	receiver, err := hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM).NewReceiver(key, info)
	if err != nil {
		return nil, err
	}
	opener, err := receiver.Setup(wire[:scheme.CiphertextSize()])
	if err != nil {
		return nil, err
	}
	return opener.Open(wire[scheme.CiphertextSize():], aad)
}

func assertFrozenDocument(t *testing.T, plaintext []byte, request BuildRequest) {
	t.Helper()
	var document struct {
		SchemaVersion string `json:"schema_version"`
		Activation    struct {
			SchemaVersion   string `json:"schema_version"`
			ConfigVersionID string `json:"config_version_id"`
			RecipientKeyID  string `json:"recipient_key_id"`
			CommandEventID  string `json:"command_event_id"`
			DeploymentID    string `json:"deployment_id"`
			Attempt         uint32 `json:"attempt"`
			ArtifactID      string `json:"artifact_id"`
			Certificates    []struct {
				TenantID             string `json:"tenant_id"`
				TenantScopeID        string `json:"tenant_scope_id"`
				SiteID               string `json:"site_id"`
				CertificateID        string `json:"certificate_id"`
				CertificateVersionID string `json:"certificate_version_id"`
				Version              uint64 `json:"version"`
				BindingRevision      uint64 `json:"binding_revision"`
			} `json:"certificates"`
		} `json:"activation"`
		Bundle struct {
			SchemaVersion string `json:"schema_version"`
			VersionID     string `json:"version_id"`
			Bindings      []struct {
				SiteID         string   `json:"site_id"`
				Domains        []string `json:"domains"`
				CertificatePEM string   `json:"certificate_chain_pem"`
				PrivateKeyPEM  string   `json:"private_key_pem"`
			} `json:"bindings"`
		} `json:"bundle"`
	}
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != CertificateArtifactSchemaVersion ||
		document.Activation.SchemaVersion != CertificateActivationVersion ||
		document.Activation.ConfigVersionID != request.ConfigVersionID.String() ||
		document.Activation.RecipientKeyID != request.RecipientKeyID ||
		document.Activation.CommandEventID != request.EventID.String() ||
		document.Activation.DeploymentID != request.DeploymentID.String() ||
		document.Activation.Attempt != request.Attempt || document.Activation.ArtifactID != request.ArtifactID.String() ||
		len(document.Activation.Certificates) != 1 ||
		document.Activation.Certificates[0].TenantScopeID != request.Materials[0].TenantScopeID.String() ||
		document.Activation.Certificates[0].CertificateVersionID != request.Materials[0].CertificateVersionID.String() ||
		document.Activation.Certificates[0].Version != uint64(request.Materials[0].CertificateVersion) ||
		document.Activation.Certificates[0].BindingRevision != uint64(request.Materials[0].BindingRevision) ||
		document.Bundle.SchemaVersion != CertificateBundleVersion ||
		document.Bundle.VersionID != request.ConfigVersionID.String() || len(document.Bundle.Bindings) != 1 ||
		document.Bundle.Bindings[0].SiteID != request.Materials[0].SiteID.String() ||
		len(document.Bundle.Bindings[0].Domains) != 1 || document.Bundle.Bindings[0].Domains[0] != request.Materials[0].SiteDomain ||
		!bytes.Equal([]byte(document.Bundle.Bindings[0].CertificatePEM), request.Materials[0].CertificatePEM) ||
		!bytes.Equal([]byte(document.Bundle.Bindings[0].PrivateKeyPEM), request.Materials[0].PrivateKeyPEM) {
		t.Fatalf("unexpected document: %#v", document)
	}
}
