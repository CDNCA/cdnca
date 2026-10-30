package certificatepublish

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
)

const acmeResolverTestKeyID = "acme-publication-kek-v1"

var acmeResolverTestKey = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

type acmeResolverFixture struct {
	request    certificateasset.OpaquePublicationResolveRequest
	privateDER []byte
}

func TestACMEPublicationResolverRoundTripAndInputOwnership(t *testing.T) {
	fixture := newACMEResolverFixture(t)
	key := append([]byte(nil), acmeResolverTestKey...)
	resolver, err := NewACMEPublicationResolver(acmeResolverTestKeyID, key)
	if err != nil {
		t.Fatal(err)
	}
	clearBytes(key)
	metadataBefore := append([]byte(nil), fixture.request.OuterEnvelopeMetadata...)
	wrappedBefore := append([]byte(nil), fixture.request.WrappedKeyMaterial...)

	resolved, err := resolver(t.Context(), fixture.request)
	if err != nil {
		t.Fatalf("resolve error = %v", err)
	}
	defer clearBytes(resolved)
	if !bytes.Equal(resolved, fixture.privateDER) {
		t.Fatal("resolved PKCS#8 differs from wrapped material")
	}
	if len(resolved) == 0 || &resolved[0] == &fixture.request.WrappedKeyMaterial[0] {
		t.Fatal("resolved PKCS#8 aliases wrapped ciphertext")
	}
	if !bytes.Equal(fixture.request.OuterEnvelopeMetadata, metadataBefore) ||
		!bytes.Equal(fixture.request.WrappedKeyMaterial, wrappedBefore) {
		t.Fatal("resolver modified caller-owned input")
	}

	resolved[0] ^= 0xff
	again, err := resolver(t.Context(), fixture.request)
	if err != nil {
		t.Fatalf("second resolve error = %v", err)
	}
	defer clearBytes(again)
	if !bytes.Equal(again, fixture.privateDER) {
		t.Fatal("caller mutation affected resolver or input state")
	}
}

func TestACMEPublicationResolverMatchesWrappingAADCharacterForCharacter(t *testing.T) {
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	orderID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index)
	}
	keyRef := "acme:v1:" + tenantID.String() + ":certificate:" + orderID.String()
	aad, err := buildACMEWrappingAAD(tenantID, keyRef, "ecdsa", digest, "test-kek-v1")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"cdnca.acme-wrapped-key.v1","tenant_id":"11111111-1111-4111-8111-111111111111","purpose":"certificate","key_ref":"acme:v1:11111111-1111-4111-8111-111111111111:certificate:22222222-2222-4222-8222-222222222222","algorithm":"ecdsa","public_spki_sha256":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","wrapping_key_id":"test-kek-v1"}`
	if string(aad) != want {
		t.Fatalf("wrapping AAD = %q, want %q", aad, want)
	}
}

func TestACMEPublicationResolverRejectsTamperingAndMismatches(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *acmeResolverFixture) ([]byte, string)
	}{
		{name: "wrong KEK", mutate: func(_ *testing.T, _ *acmeResolverFixture) ([]byte, string) {
			key := append([]byte(nil), acmeResolverTestKey...)
			key[0] ^= 0xff
			return key, acmeResolverTestKeyID
		}},
		{name: "wrong key ID", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			mutateACMEWrappedMetadata(t, fixture, func(metadata *acmeWrappedKeyMetadata) {
				metadata.WrappingKeyID = "other-kek-v1"
			})
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "cross tenant", mutate: func(_ *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			fixture.request.TenantScopeID = uuid.New()
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "wrong purpose", mutate: func(_ *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			fixture.request.PrivateKeyReference = strings.Replace(
				fixture.request.PrivateKeyReference, ":certificate:", ":account:", 1,
			)
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "wrong reference", mutate: func(_ *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			parts := strings.Split(fixture.request.PrivateKeyReference, ":")
			parts[4] = uuid.NewString()
			fixture.request.PrivateKeyReference = strings.Join(parts, ":")
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "wrong algorithm", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			mutateACMEWrappedMetadata(t, fixture, func(metadata *acmeWrappedKeyMetadata) {
				metadata.Algorithm = "rsa"
			})
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "wrong SPKI", mutate: func(_ *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			fixture.request.ExpectedPublicKeySHA256[0] ^= 0xff
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "AAD digest", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			mutateACMEWrappedMetadata(t, fixture, func(metadata *acmeWrappedKeyMetadata) {
				metadata.WrappingAADSHA[0] ^= 0xff
			})
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "nonce", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			mutateACMEWrappedMetadata(t, fixture, func(metadata *acmeWrappedKeyMetadata) {
				metadata.WrappingNonce[0] ^= 0xff
			})
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "ciphertext", mutate: func(_ *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			fixture.request.WrappedKeyMaterial[0] ^= 0xff
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "source schema", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			mutateACMEWrappedMetadata(t, fixture, func(metadata *acmeWrappedKeyMetadata) {
				metadata.Schema = "cdnca.acme-wrapped-key.v2"
			})
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "outer schema", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			mutateACMEOuterMetadata(t, fixture, func(metadata *acmeOuterEnvelopeMetadata) {
				metadata.Schema = "cdnca.acme-certificate-envelope.v2"
			})
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "outer kind", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			mutateACMEOuterMetadata(t, fixture, func(metadata *acmeOuterEnvelopeMetadata) {
				metadata.Kind = "plaintext_pkcs8"
			})
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "bad PKCS8", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			*fixture = newACMEResolverFixtureWithPlaintext(
				t, []byte("not-pkcs8"), fixture.request.ExpectedPublicKeySHA256, "ecdsa",
			)
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
		{name: "private key mismatch", mutate: func(t *testing.T, fixture *acmeResolverFixture) ([]byte, string) {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			otherDER, err := x509.MarshalPKCS8PrivateKey(other)
			if err != nil {
				t.Fatal(err)
			}
			*fixture = newACMEResolverFixtureWithPlaintext(
				t, otherDER, fixture.request.ExpectedPublicKeySHA256, "ecdsa",
			)
			return acmeResolverTestKey, acmeResolverTestKeyID
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newACMEResolverFixture(t)
			key, keyID := test.mutate(t, &fixture)
			resolver, err := NewACMEPublicationResolver(keyID, key)
			if err != nil {
				t.Fatal(err)
			}
			metadataBefore := append([]byte(nil), fixture.request.OuterEnvelopeMetadata...)
			wrappedBefore := append([]byte(nil), fixture.request.WrappedKeyMaterial...)
			resolved, err := resolver(t.Context(), fixture.request)
			if !errors.Is(err, ErrACMEKeyResolution) || resolved != nil {
				clearBytes(resolved)
				t.Fatalf("resolve = (%d bytes, %v), want nil fixed error", len(resolved), err)
			}
			if err.Error() != ErrACMEKeyResolution.Error() ||
				strings.Contains(err.Error(), fixture.request.PrivateKeyReference) ||
				strings.Contains(err.Error(), hex.EncodeToString(fixture.request.WrappedKeyMaterial)) {
				t.Fatalf("resolution error leaked request detail: %q", err)
			}
			if !bytes.Equal(fixture.request.OuterEnvelopeMetadata, metadataBefore) ||
				!bytes.Equal(fixture.request.WrappedKeyMaterial, wrappedBefore) {
				t.Fatal("failed resolution modified caller-owned input")
			}
		})
	}
}

func TestACMEPublicationResolverRejectsMalformedInputsAndRecoversPanics(t *testing.T) {
	fixture := newACMEResolverFixture(t)
	resolver, err := NewACMEPublicationResolver(acmeResolverTestKeyID, acmeResolverTestKey)
	if err != nil {
		t.Fatal(err)
	}

	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		request certificateasset.OpaquePublicationResolveRequest
	}{
		{name: "nil context", request: fixture.request},
		{name: "canceled context", ctx: canceled, request: fixture.request},
		{name: "panic context", ctx: panicErrorContext{Context: t.Context()}, request: fixture.request},
		{name: "nil tenant", ctx: t.Context(), request: mutateACMERequest(fixture.request, func(request *certificateasset.OpaquePublicationResolveRequest) {
			request.TenantScopeID = uuid.Nil
		})},
		{name: "trailing outer JSON", ctx: t.Context(), request: mutateACMERequest(fixture.request, func(request *certificateasset.OpaquePublicationResolveRequest) {
			request.OuterEnvelopeMetadata = append(request.OuterEnvelopeMetadata, []byte(` {}`)...)
		})},
		{name: "unknown outer field", ctx: t.Context(), request: mutateACMERequest(fixture.request, func(request *certificateasset.OpaquePublicationResolveRequest) {
			request.OuterEnvelopeMetadata = append(request.OuterEnvelopeMetadata[:len(request.OuterEnvelopeMetadata)-1], []byte(`,"secret":"forbidden"}`)...)
		})},
		{name: "duplicate outer field", ctx: t.Context(), request: mutateACMERequest(fixture.request, func(request *certificateasset.OpaquePublicationResolveRequest) {
			request.OuterEnvelopeMetadata = append(request.OuterEnvelopeMetadata[:len(request.OuterEnvelopeMetadata)-1], []byte(`,"kind":"opaque_wrapped"}`)...)
		})},
		{name: "duplicate source field", ctx: t.Context(), request: requestWithRawACMESource(t, fixture.request, func(source []byte) []byte {
			return append(source[:len(source)-1], []byte(`,"algorithm":"ecdsa"}`)...)
		})},
		{name: "short nonce", ctx: t.Context(), request: requestWithACMEWrappedMetadata(t, fixture.request, func(metadata *acmeWrappedKeyMetadata) {
			metadata.WrappingNonce = metadata.WrappingNonce[:len(metadata.WrappingNonce)-1]
		})},
		{name: "short ciphertext", ctx: t.Context(), request: mutateACMERequest(fixture.request, func(request *certificateasset.OpaquePublicationResolveRequest) {
			request.WrappedKeyMaterial = request.WrappedKeyMaterial[:15]
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := resolver(test.ctx, test.request)
			if !errors.Is(err, ErrACMEKeyResolution) || resolved != nil {
				clearBytes(resolved)
				t.Fatalf("resolve = (%d bytes, %v), want nil fixed error", len(resolved), err)
			}
		})
	}

	var nilResolver *acmePublicationResolver
	resolved, err := nilResolver.resolve(t.Context(), fixture.request)
	if !errors.Is(err, ErrACMEKeyResolution) || resolved != nil {
		clearBytes(resolved)
		t.Fatalf("nil resolver = (%d bytes, %v), want nil fixed error", len(resolved), err)
	}
}

func TestACMEPublicationResolverAcceptsKeyStoreAlgorithms(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		algorithm  string
		privateKey any
		publicKey  any
	}{
		{name: "ECDSA", algorithm: "ecdsa", privateKey: ecdsaKey, publicKey: &ecdsaKey.PublicKey},
		{name: "Ed25519", algorithm: "ed25519", privateKey: ed25519Key, publicKey: ed25519Key.Public()},
		{name: "RSA", algorithm: "rsa", privateKey: rsaKey, publicKey: &rsaKey.PublicKey},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privateDER, err := x509.MarshalPKCS8PrivateKey(test.privateKey)
			if err != nil {
				t.Fatal(err)
			}
			publicDER, err := x509.MarshalPKIXPublicKey(test.publicKey)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(publicDER)
			fixture := newACMEResolverFixtureWithPlaintext(t, privateDER, digest, test.algorithm)
			resolver, err := NewACMEPublicationResolver(acmeResolverTestKeyID, acmeResolverTestKey)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := resolver(t.Context(), fixture.request)
			if err != nil {
				t.Fatal(err)
			}
			defer clearBytes(resolved)
			if !bytes.Equal(resolved, privateDER) {
				t.Fatal("resolved PKCS#8 differs")
			}
		})
	}
}

func TestNewACMEPublicationResolverRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		keyID string
		key   []byte
	}{
		{name: "empty key ID", key: acmeResolverTestKey},
		{name: "trimmed key ID", keyID: " key", key: acmeResolverTestKey},
		{name: "control key ID", keyID: "key\n", key: acmeResolverTestKey},
		{name: "invalid UTF8 key ID", keyID: string([]byte{0xff}), key: acmeResolverTestKey},
		{name: "short AES key", keyID: acmeResolverTestKeyID, key: acmeResolverTestKey[:31]},
		{name: "long AES key", keyID: acmeResolverTestKeyID, key: append(append([]byte(nil), acmeResolverTestKey...), 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver, err := NewACMEPublicationResolver(test.keyID, test.key)
			if resolver != nil || !errors.Is(err, ErrACMEResolverConfig) ||
				err.Error() != ErrACMEResolverConfig.Error() {
				t.Fatalf("NewACMEPublicationResolver() = (%v, %v)", resolver, err)
			}
		})
	}
}

func newACMEResolverFixture(t *testing.T) acmeResolverFixture {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return newACMEResolverFixtureWithPlaintext(t, privateDER, sha256.Sum256(publicDER), "ecdsa")
}

func newACMEResolverFixtureWithPlaintext(
	t *testing.T,
	plaintext []byte,
	expectedPublicKeySHA256 [32]byte,
	algorithm string,
) acmeResolverFixture {
	t.Helper()
	tenantID := uuid.MustParse("7e192b58-5f51-44f2-bab2-1c2822492430")
	orderID := uuid.MustParse("35ee7a33-03f6-4da0-9509-f27fbac4ca03")
	keyRef := "acme:v1:" + tenantID.String() + ":certificate:" + orderID.String()
	aad := independentACMEWrappingAAD(
		t, tenantID, keyRef, algorithm, expectedPublicKeySHA256, acmeResolverTestKeyID,
	)
	nonce := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c}
	block, err := aes.NewCipher(acmeResolverTestKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := aead.Seal(nil, nonce, plaintext, aad)
	aadDigest := sha256.Sum256(aad)
	source, err := json.Marshal(acmeWrappedKeyMetadata{
		Schema: acmeWrappedKeySchema, Algorithm: algorithm,
		WrappingKeyID: acmeResolverTestKeyID, WrappingNonce: nonce,
		WrappingAADSHA: aadDigest[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	outer, err := json.Marshal(acmeOuterEnvelopeMetadata{
		Schema: acmeCertificateEnvelopeSchema,
		Kind:   acmeWrappedKeyKind,
		Source: source,
	})
	if err != nil {
		t.Fatal(err)
	}
	return acmeResolverFixture{
		request: certificateasset.OpaquePublicationResolveRequest{
			TenantScopeID: tenantID, PrivateKeyReference: keyRef,
			ExpectedPublicKeySHA256: expectedPublicKeySHA256,
			OuterEnvelopeMetadata:   outer,
			WrappedKeyMaterial:      wrapped,
		},
		privateDER: append([]byte(nil), plaintext...),
	}
}

func independentACMEWrappingAAD(
	t *testing.T,
	tenantID uuid.UUID,
	keyRef, algorithm string,
	publicDigest [32]byte,
	wrappingKeyID string,
) []byte {
	t.Helper()
	aad, err := json.Marshal(struct {
		Schema        string `json:"schema"`
		TenantID      string `json:"tenant_id"`
		Purpose       string `json:"purpose"`
		KeyRef        string `json:"key_ref"`
		Algorithm     string `json:"algorithm"`
		PublicSPKI    string `json:"public_spki_sha256"`
		WrappingKeyID string `json:"wrapping_key_id"`
	}{
		Schema: acmeWrappedKeySchema, TenantID: tenantID.String(),
		Purpose: acmeCertificateKeyPurpose, KeyRef: keyRef, Algorithm: algorithm,
		PublicSPKI: hex.EncodeToString(publicDigest[:]), WrappingKeyID: wrappingKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return aad
}

func mutateACMEWrappedMetadata(
	t *testing.T,
	fixture *acmeResolverFixture,
	mutate func(*acmeWrappedKeyMetadata),
) {
	t.Helper()
	fixture.request = requestWithACMEWrappedMetadata(t, fixture.request, mutate)
}

func requestWithACMEWrappedMetadata(
	t *testing.T,
	request certificateasset.OpaquePublicationResolveRequest,
	mutate func(*acmeWrappedKeyMetadata),
) certificateasset.OpaquePublicationResolveRequest {
	t.Helper()
	request = cloneACMERequest(request)
	var outer acmeOuterEnvelopeMetadata
	if err := json.Unmarshal(request.OuterEnvelopeMetadata, &outer); err != nil {
		t.Fatal(err)
	}
	var source acmeWrappedKeyMetadata
	if err := json.Unmarshal(outer.Source, &source); err != nil {
		t.Fatal(err)
	}
	mutate(&source)
	var err error
	outer.Source, err = json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	request.OuterEnvelopeMetadata, err = json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func requestWithRawACMESource(
	t *testing.T,
	request certificateasset.OpaquePublicationResolveRequest,
	mutate func([]byte) []byte,
) certificateasset.OpaquePublicationResolveRequest {
	t.Helper()
	request = cloneACMERequest(request)
	var outer acmeOuterEnvelopeMetadata
	if err := json.Unmarshal(request.OuterEnvelopeMetadata, &outer); err != nil {
		t.Fatal(err)
	}
	outer.Source = mutate(append([]byte(nil), outer.Source...))
	encoded, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	request.OuterEnvelopeMetadata = encoded
	return request
}

func mutateACMEOuterMetadata(
	t *testing.T,
	fixture *acmeResolverFixture,
	mutate func(*acmeOuterEnvelopeMetadata),
) {
	t.Helper()
	var outer acmeOuterEnvelopeMetadata
	if err := json.Unmarshal(fixture.request.OuterEnvelopeMetadata, &outer); err != nil {
		t.Fatal(err)
	}
	mutate(&outer)
	encoded, err := json.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	fixture.request.OuterEnvelopeMetadata = encoded
}

func mutateACMERequest(
	request certificateasset.OpaquePublicationResolveRequest,
	mutate func(*certificateasset.OpaquePublicationResolveRequest),
) certificateasset.OpaquePublicationResolveRequest {
	request = cloneACMERequest(request)
	mutate(&request)
	return request
}

func cloneACMERequest(
	request certificateasset.OpaquePublicationResolveRequest,
) certificateasset.OpaquePublicationResolveRequest {
	request.OuterEnvelopeMetadata = append([]byte(nil), request.OuterEnvelopeMetadata...)
	request.WrappedKeyMaterial = append([]byte(nil), request.WrappedKeyMaterial...)
	return request
}

type panicErrorContext struct {
	context.Context
}

func (panicErrorContext) Err() error {
	panic("context error")
}
