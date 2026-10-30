package certificateenvelope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
)

type kmsFixture struct {
	dek            []byte
	encryptedDEK   []byte
	decryptCalls   int
	encryptCalls   int
	reEncryptCalls int
	lastEncrypt    *kms.EncryptInput
	lastDecrypt    *kms.DecryptInput
	lastReEncrypt  *kms.ReEncryptInput
	encryptErr     error
	decryptErr     error
	reEncryptErr   error
}

func (fixture *kmsFixture) Encrypt(_ context.Context, input *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	fixture.encryptCalls++
	fixture.lastEncrypt = input
	if fixture.encryptErr != nil {
		return nil, fixture.encryptErr
	}
	fixture.dek = append(fixture.dek[:0], input.Plaintext...)
	return &kms.EncryptOutput{CiphertextBlob: append([]byte(nil), fixture.encryptedDEK...), KeyId: input.KeyId}, nil
}

func (fixture *kmsFixture) Decrypt(_ context.Context, input *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	fixture.decryptCalls++
	fixture.lastDecrypt = input
	if fixture.decryptErr != nil {
		return nil, fixture.decryptErr
	}
	return &kms.DecryptOutput{Plaintext: append([]byte(nil), fixture.dek...), KeyId: input.KeyId}, nil
}

func (fixture *kmsFixture) ReEncrypt(_ context.Context, input *kms.ReEncryptInput, _ ...func(*kms.Options)) (*kms.ReEncryptOutput, error) {
	fixture.reEncryptCalls++
	fixture.lastReEncrypt = input
	if fixture.reEncryptErr != nil {
		return nil, fixture.reEncryptErr
	}
	return &kms.ReEncryptOutput{CiphertextBlob: []byte("wrapped-dek-v2"), KeyId: input.DestinationKeyId}, nil
}

func testEnvelopeContext() certificateasset.PrivateKeyEnvelopeContext {
	return certificateasset.PrivateKeyEnvelopeContext{
		TenantScopeID:                uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		AssetID:                      uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		VersionID:                    uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Version:                      7,
		CertificateFingerprintSHA256: [32]byte{1, 2, 3},
		CertificatePublicKeySHA256:   [32]byte{4, 5, 6},
		PrivateKeyReference:          "certificate-assets/asset-7",
	}
}

func TestEnvelopeSealUnsealUsesKMSWrappedDEKAndCanonicalAAD(t *testing.T) {
	fixture := &kmsFixture{encryptedDEK: []byte("wrapped-dek-v1")}
	enveloper, err := New(fixture, "kms-key-v1")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("private-key-pkcs8-material")
	ctx := testEnvelopeContext()
	envelope, err := enveloper.Seal(context.Background(), certificateasset.PrivateKeySealRequest{
		Context: ctx, PlaintextPKCS8: plaintext,
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.encryptCalls != 1 || fixture.lastEncrypt == nil || fixture.lastEncrypt.KeyId == nil ||
		*fixture.lastEncrypt.KeyId != "kms-key-v1" || len(fixture.lastEncrypt.Plaintext) != 32 {
		t.Fatalf("KMS Encrypt contract = %#v calls=%d", fixture.lastEncrypt, fixture.encryptCalls)
	}
	if envelope.KeyID != "kms-key-v1" || bytes.Contains(envelope.Ciphertext, plaintext) ||
		bytes.Contains(envelope.Metadata, plaintext) || len(envelope.Nonce) != 12 {
		t.Fatalf("envelope exposes plaintext or has invalid shape: %#v", envelope)
	}
	var metadata map[string]any
	if err := json.Unmarshal(envelope.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata["schema"] != "cdnca.certificate-private-key-envelope.v1" ||
		metadata["kind"] != "pkcs8" || metadata["algorithm"] != "AES-256-GCM" {
		t.Fatalf("metadata contract = %#v", metadata)
	}
	if fixture.lastEncrypt.EncryptionContext["cdnca.aad.sha256"] == "" {
		t.Fatalf("KMS encryption context missing canonical AAD digest: %#v", fixture.lastEncrypt.EncryptionContext)
	}
	decrypted, err := enveloper.Unseal(context.Background(), certificateasset.PrivateKeyUnsealRequest{
		Context: ctx, Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) || fixture.decryptCalls != 1 || fixture.lastDecrypt == nil ||
		fixture.lastDecrypt.EncryptionContext["cdnca.aad.sha256"] != fixture.lastEncrypt.EncryptionContext["cdnca.aad.sha256"] {
		t.Fatalf("unseal result or AAD mismatch: %q %#v", decrypted, fixture.lastDecrypt)
	}
}

func TestEnvelopeRewrapOnlyReencryptsDEKAndBindsTargetKey(t *testing.T) {
	fixture := &kmsFixture{encryptedDEK: []byte("wrapped-dek-v1")}
	enveloper, err := New(fixture, "kms-key-v1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := testEnvelopeContext()
	original, err := enveloper.Seal(context.Background(), certificateasset.PrivateKeySealRequest{
		Context: ctx, PlaintextPKCS8: []byte("private-key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	rewrapped, err := enveloper.Rewrap(context.Background(), certificateasset.PrivateKeyRewrapRequest{
		Context: ctx, Envelope: original, TargetKeyID: "kms-key-v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if fixture.reEncryptCalls != 1 || fixture.decryptCalls != 0 || fixture.lastReEncrypt == nil ||
		fixture.lastReEncrypt.SourceKeyId == nil || *fixture.lastReEncrypt.SourceKeyId != "kms-key-v1" ||
		fixture.lastReEncrypt.DestinationKeyId == nil || *fixture.lastReEncrypt.DestinationKeyId != "kms-key-v2" {
		t.Fatalf("rewrap must use KMS ReEncrypt only: calls=(%d,%d) input=%#v", fixture.reEncryptCalls, fixture.decryptCalls, fixture.lastReEncrypt)
	}
	if rewrapped.KeyID != "kms-key-v2" || !bytes.Equal(rewrapped.Ciphertext, original.Ciphertext) ||
		!bytes.Equal(rewrapped.Nonce, original.Nonce) || bytes.Equal(rewrapped.Metadata, original.Metadata) {
		t.Fatalf("rewrap changed local ciphertext/nonce or not metadata: %#v", rewrapped)
	}
}

func TestEnvelopeSealOpaquePreservesResolverMetadataWithoutWrappedMaterial(t *testing.T) {
	fixture := &kmsFixture{encryptedDEK: []byte("wrapped-dek-v1")}
	enveloper, err := New(fixture, "kms-key-v1")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := []byte("provider-wrapped-key-material")
	source := json.RawMessage(`{"provider":"test-kms","format":"wrapped-key-v1"}`)
	envelope, err := enveloper.SealOpaque(context.Background(), certificateasset.OpaquePrivateKeySealRequest{
		Context: testEnvelopeContext(), WrappedKeyMaterial: wrapped, Metadata: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Schema string          `json:"schema"`
		Kind   string          `json:"kind"`
		Source json.RawMessage `json:"source"`
	}
	if err := json.Unmarshal(envelope.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Schema != "cdnca.acme-certificate-envelope.v1" || metadata.Kind != "opaque_wrapped" ||
		!bytes.Equal(metadata.Source, source) || bytes.Contains(envelope.Metadata, wrapped) {
		t.Fatalf("opaque envelope metadata = %s", envelope.Metadata)
	}
	var tamperedFields map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Metadata, &tamperedFields); err != nil {
		t.Fatal(err)
	}
	tamperedFields["source"] = json.RawMessage(`{"provider":"tampered"}`)
	tampered, err := json.Marshal(tamperedFields)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Metadata = tampered
	if _, err := enveloper.Unseal(context.Background(), certificateasset.PrivateKeyUnsealRequest{
		Context: testEnvelopeContext(), Envelope: envelope,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("opaque metadata tamper error = %v", err)
	}
}

func TestEnvelopeRejectsAADMismatchAndRedactsProviderErrors(t *testing.T) {
	fixture := &kmsFixture{encryptedDEK: []byte("wrapped-dek-v1"), decryptErr: errors.New("kms private secret provider detail")}
	enveloper, err := New(fixture, "kms-key-v1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := testEnvelopeContext()
	envelope, err := enveloper.Seal(context.Background(), certificateasset.PrivateKeySealRequest{
		Context: ctx, PlaintextPKCS8: []byte("private-key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong := ctx
	wrong.Version++
	if _, err := enveloper.Unseal(context.Background(), certificateasset.PrivateKeyUnsealRequest{Context: wrong, Envelope: envelope}); !errors.Is(err, ErrAADMismatch) {
		t.Fatalf("AAD mismatch error = %v", err)
	}
	if fixture.decryptCalls != 0 {
		t.Fatal("AAD mismatch must fail before KMS Decrypt")
	}
	if _, err := enveloper.Unseal(context.Background(), certificateasset.PrivateKeyUnsealRequest{Context: ctx, Envelope: envelope}); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private secret") {
		t.Fatalf("provider detail leaked or wrong error: %v", err)
	}
}

var _ certificateasset.PrivateKeyEnveloper = (*Envelope)(nil)
