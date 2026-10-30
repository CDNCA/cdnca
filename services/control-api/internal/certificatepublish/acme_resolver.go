package certificatepublish

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/google/uuid"
)

const (
	acmeCertificateEnvelopeSchema = "cdnca.acme-certificate-envelope.v1"
	acmeWrappedKeySchema          = "cdnca.acme-wrapped-key.v1"
	acmeWrappedKeyKind            = "opaque_wrapped"
	acmeCertificateKeyPurpose     = "certificate"

	maxACMEEnvelopeMetadataBytes = 16 << 10
	maxACMEWrappedKeyBytes       = 128 << 10
	maxACMEPublicationKeys       = 4
)

var (
	ErrACMEResolverConfig = errors.New("invalid ACME publication resolver configuration")
	ErrACMEKeyResolution  = errors.New("ACME publication key resolution failed")
)

type acmePublicationResolver struct {
	aeads map[string]cipher.AEAD
}

type ACMEPublicationWrappingKey struct {
	ID       string
	Material []byte
}

type acmeOuterEnvelopeMetadata struct {
	Schema string          `json:"schema"`
	Kind   string          `json:"kind"`
	Source json.RawMessage `json:"source"`
}

type acmeWrappedKeyMetadata struct {
	Schema         string `json:"schema"`
	Algorithm      string `json:"algorithm"`
	WrappingKeyID  string `json:"wrapping_key_id"`
	WrappingNonce  []byte `json:"wrapping_nonce"`
	WrappingAADSHA []byte `json:"wrapping_aad_sha256"`
}

func NewACMEPublicationResolver(
	wrappingKeyID string,
	wrappingKey []byte,
) (certificateasset.OpaquePublicationResolver, error) {
	return NewACMEPublicationResolverKeyring(ACMEPublicationWrappingKey{
		ID: wrappingKeyID, Material: wrappingKey,
	})
}

func NewACMEPublicationResolverKeyring(
	active ACMEPublicationWrappingKey,
	previous ...ACMEPublicationWrappingKey,
) (certificateasset.OpaquePublicationResolver, error) {
	if len(previous)+1 > maxACMEPublicationKeys {
		return nil, ErrACMEResolverConfig
	}
	aeads := make(map[string]cipher.AEAD, len(previous)+1)
	keys := append([]ACMEPublicationWrappingKey{active}, previous...)
	for _, key := range keys {
		if !validACMEWrappingKeyID(key.ID) || len(key.Material) != 32 {
			return nil, ErrACMEResolverConfig
		}
		if _, duplicate := aeads[key.ID]; duplicate {
			return nil, ErrACMEResolverConfig
		}
		keyCopy := append([]byte(nil), key.Material...)
		block, err := aes.NewCipher(keyCopy)
		clearBytes(keyCopy)
		if err != nil {
			return nil, ErrACMEResolverConfig
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrACMEResolverConfig
		}
		aeads[key.ID] = aead
	}
	resolver := &acmePublicationResolver{aeads: aeads}
	return resolver.resolve, nil
}

func (resolver *acmePublicationResolver) resolve(
	ctx context.Context,
	request certificateasset.OpaquePublicationResolveRequest,
) (plaintext []byte, err error) {
	defer func() {
		if recover() != nil {
			clearBytes(plaintext)
			plaintext = nil
			err = ErrACMEKeyResolution
		}
		if err != nil {
			clearBytes(plaintext)
			plaintext = nil
		}
	}()

	if resolver == nil || len(resolver.aeads) == 0 || ctx == nil || ctx.Err() != nil ||
		request.TenantScopeID == uuid.Nil ||
		len(request.OuterEnvelopeMetadata) == 0 ||
		len(request.OuterEnvelopeMetadata) > maxACMEEnvelopeMetadataBytes ||
		len(request.WrappedKeyMaterial) == 0 ||
		len(request.WrappedKeyMaterial) > maxACMEWrappedKeyBytes {
		return nil, ErrACMEKeyResolution
	}
	if !validACMECertificateKeyReference(request.PrivateKeyReference, request.TenantScopeID) {
		return nil, ErrACMEKeyResolution
	}

	var outer acmeOuterEnvelopeMetadata
	if err := decodeStrictACMEJSON(request.OuterEnvelopeMetadata, &outer); err != nil ||
		outer.Schema != acmeCertificateEnvelopeSchema || outer.Kind != acmeWrappedKeyKind ||
		len(outer.Source) == 0 {
		return nil, ErrACMEKeyResolution
	}
	var metadata acmeWrappedKeyMetadata
	if err := decodeStrictACMEJSON(outer.Source, &metadata); err != nil ||
		metadata.Schema != acmeWrappedKeySchema ||
		!validACMEPrivateKeyAlgorithm(metadata.Algorithm) ||
		len(metadata.WrappingAADSHA) != sha256.Size {
		return nil, ErrACMEKeyResolution
	}
	aead, found := resolver.aeads[metadata.WrappingKeyID]
	if !found || len(request.WrappedKeyMaterial) < aead.Overhead() ||
		len(metadata.WrappingNonce) != aead.NonceSize() {
		return nil, ErrACMEKeyResolution
	}

	aad, aadErr := buildACMEWrappingAAD(
		request.TenantScopeID,
		request.PrivateKeyReference,
		metadata.Algorithm,
		request.ExpectedPublicKeySHA256,
		metadata.WrappingKeyID,
	)
	if aadErr != nil {
		return nil, ErrACMEKeyResolution
	}
	expectedAADDigest := sha256.Sum256(aad)
	if subtle.ConstantTimeCompare(metadata.WrappingAADSHA, expectedAADDigest[:]) != 1 {
		return nil, ErrACMEKeyResolution
	}

	plaintext, err = aead.Open(
		nil,
		metadata.WrappingNonce,
		request.WrappedKeyMaterial,
		aad,
	)
	if err != nil || len(plaintext) == 0 {
		return plaintext, ErrACMEKeyResolution
	}
	parsed, parseErr := x509.ParsePKCS8PrivateKey(plaintext)
	if parseErr != nil || acmePrivateKeyAlgorithm(parsed) != metadata.Algorithm {
		return plaintext, ErrACMEKeyResolution
	}
	publicKey := acmePrivateKeyPublic(parsed)
	if publicKey == nil {
		return plaintext, ErrACMEKeyResolution
	}
	publicDER, marshalErr := x509.MarshalPKIXPublicKey(publicKey)
	if marshalErr != nil {
		return plaintext, ErrACMEKeyResolution
	}
	publicDigest := sha256.Sum256(publicDER)
	if subtle.ConstantTimeCompare(publicDigest[:], request.ExpectedPublicKeySHA256[:]) != 1 {
		return plaintext, ErrACMEKeyResolution
	}
	return plaintext, nil
}

func buildACMEWrappingAAD(
	tenantScopeID uuid.UUID,
	keyReference, algorithm string,
	publicKeySHA256 [32]byte,
	wrappingKeyID string,
) ([]byte, error) {
	if tenantScopeID == uuid.Nil ||
		!validACMECertificateKeyReference(keyReference, tenantScopeID) ||
		!validACMEPrivateKeyAlgorithm(algorithm) || !validACMEWrappingKeyID(wrappingKeyID) {
		return nil, ErrACMEKeyResolution
	}
	return json.Marshal(struct {
		Schema        string `json:"schema"`
		TenantID      string `json:"tenant_id"`
		Purpose       string `json:"purpose"`
		KeyRef        string `json:"key_ref"`
		Algorithm     string `json:"algorithm"`
		PublicSPKI    string `json:"public_spki_sha256"`
		WrappingKeyID string `json:"wrapping_key_id"`
	}{
		Schema: acmeWrappedKeySchema, TenantID: tenantScopeID.String(),
		Purpose: acmeCertificateKeyPurpose, KeyRef: keyReference, Algorithm: algorithm,
		PublicSPKI: hex.EncodeToString(publicKeySHA256[:]), WrappingKeyID: wrappingKeyID,
	})
}

func decodeStrictACMEJSON(input []byte, target any) error {
	if err := rejectDuplicateACMEJSONFields(input); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrACMEKeyResolution
	}
	return nil
}

func rejectDuplicateACMEJSONFields(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrACMEKeyResolution
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return ErrACMEKeyResolution
		}
		if _, duplicate := seen[key]; duplicate {
			return ErrACMEKeyResolution
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return ErrACMEKeyResolution
		}
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return ErrACMEKeyResolution
	}
	if _, err = decoder.Token(); err != io.EOF {
		return ErrACMEKeyResolution
	}
	return nil
}

func validACMECertificateKeyReference(reference string, tenantScopeID uuid.UUID) bool {
	if reference == "" || len(reference) > 200 || reference != strings.TrimSpace(reference) ||
		!utf8.ValidString(reference) || strings.IndexFunc(reference, unicode.IsControl) >= 0 {
		return false
	}
	parts := strings.Split(reference, ":")
	if len(parts) != 5 || parts[0] != "acme" || parts[1] != "v1" ||
		parts[3] != acmeCertificateKeyPurpose {
		return false
	}
	tenantID, tenantErr := uuid.Parse(parts[2])
	orderID, orderErr := uuid.Parse(parts[4])
	return tenantErr == nil && orderErr == nil && tenantID == tenantScopeID &&
		tenantID != uuid.Nil && orderID != uuid.Nil &&
		parts[2] == tenantID.String() && parts[4] == orderID.String()
}

func validACMEWrappingKeyID(keyID string) bool {
	return keyID != "" && len(keyID) <= 200 && keyID == strings.TrimSpace(keyID) &&
		utf8.ValidString(keyID) && strings.IndexFunc(keyID, unicode.IsControl) < 0
}

func validACMEPrivateKeyAlgorithm(algorithm string) bool {
	return algorithm == "rsa" || algorithm == "ecdsa" || algorithm == "ed25519"
}

func acmePrivateKeyAlgorithm(privateKey any) string {
	switch privateKey.(type) {
	case *rsa.PrivateKey:
		return "rsa"
	case *ecdsa.PrivateKey:
		return "ecdsa"
	case ed25519.PrivateKey:
		return "ed25519"
	default:
		return ""
	}
}

func acmePrivateKeyPublic(privateKey any) any {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case ed25519.PrivateKey:
		return key.Public()
	default:
		return nil
	}
}
