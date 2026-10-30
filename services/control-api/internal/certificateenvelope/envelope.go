package certificateenvelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
)

const (
	privateKeyEnvelopeSchema = "cdnca.certificate-private-key-envelope.v1"
	opaqueEnvelopeSchema     = "cdnca.acme-certificate-envelope.v1"
	envelopeAlgorithm        = "AES-256-GCM"
	encryptionContextKey     = "cdnca.aad.sha256"
	dekBytes                 = 32
)

var (
	ErrInvalidInput = errors.New("invalid certificate envelope input")
	ErrUnavailable  = errors.New("certificate envelope unavailable")
	ErrAADMismatch  = errors.New("certificate envelope AAD mismatch")
)

type KMSAPI interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
	ReEncrypt(context.Context, *kms.ReEncryptInput, ...func(*kms.Options)) (*kms.ReEncryptOutput, error)
}

type Envelope struct {
	kms   KMSAPI
	keyID string
}

func New(client KMSAPI, keyID string) (*Envelope, error) {
	if client == nil || !validKeyID(keyID) {
		return nil, ErrInvalidInput
	}
	return &Envelope{kms: client, keyID: keyID}, nil
}

func (e *Envelope) Seal(ctx context.Context, request certificateasset.PrivateKeySealRequest) (certificateasset.PrivateKeyEnvelope, error) {
	if len(request.PlaintextPKCS8) == 0 {
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	return e.seal(ctx, request.Context, request.PlaintextPKCS8, "pkcs8", nil)
}

func (e *Envelope) SealOpaque(ctx context.Context, request certificateasset.OpaquePrivateKeySealRequest) (certificateasset.PrivateKeyEnvelope, error) {
	if len(request.WrappedKeyMaterial) == 0 || len(request.Metadata) == 0 || !json.Valid(request.Metadata) {
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, request.Metadata); err != nil {
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	return e.seal(ctx, request.Context, request.WrappedKeyMaterial, "opaque_wrapped", compact.Bytes())
}

func (e *Envelope) Unseal(ctx context.Context, request certificateasset.PrivateKeyUnsealRequest) ([]byte, error) {
	aad, aadDigest, err := canonicalAAD(request.Context)
	if err != nil {
		return nil, err
	}
	metadata, err := decodeMetadata(request.Envelope, aadDigest)
	if err != nil {
		return nil, err
	}
	if len(request.Envelope.Nonce) != 12 || len(request.Envelope.Ciphertext) < 16 {
		return nil, ErrInvalidInput
	}
	dek, err := e.decryptDEK(ctx, request.Envelope.KeyID, metadata.EncryptedDEK, metadata.AADContext)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, ErrUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	plaintext, err := gcm.Open(nil, request.Envelope.Nonce, request.Envelope.Ciphertext,
		authenticatedAAD(aad, metadata.Source))
	if err != nil {
		return nil, ErrUnavailable
	}
	return plaintext, nil
}

func (e *Envelope) Rewrap(ctx context.Context, request certificateasset.PrivateKeyRewrapRequest) (certificateasset.PrivateKeyEnvelope, error) {
	if !validKeyID(request.TargetKeyID) {
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	_, aadDigest, err := canonicalAAD(request.Context)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	metadata, err := decodeMetadata(request.Envelope, aadDigest)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	if len(request.Envelope.Nonce) != 12 || len(request.Envelope.Ciphertext) < 16 {
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	if request.Envelope.KeyID == request.TargetKeyID {
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	result, err := e.kms.ReEncrypt(ctx, &kms.ReEncryptInput{
		SourceKeyId:                  aws.String(request.Envelope.KeyID),
		DestinationKeyId:             aws.String(request.TargetKeyID),
		CiphertextBlob:               append([]byte(nil), metadata.EncryptedDEK...),
		SourceEncryptionContext:      metadata.AADContext,
		DestinationEncryptionContext: metadata.AADContext,
	})
	if err != nil || result == nil || len(result.CiphertextBlob) == 0 {
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	metadata.EncryptedDEK = append([]byte(nil), result.CiphertextBlob...)
	metadata.KeyID = request.TargetKeyID
	raw, err := json.Marshal(metadata)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	if len(raw) > 4096 {
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	return certificateasset.PrivateKeyEnvelope{
		KeyID:      request.TargetKeyID,
		Ciphertext: append([]byte(nil), request.Envelope.Ciphertext...),
		Nonce:      append([]byte(nil), request.Envelope.Nonce...),
		Metadata:   raw,
	}, nil
}

type envelopeMetadata struct {
	Schema       string            `json:"schema"`
	Kind         string            `json:"kind"`
	Algorithm    string            `json:"algorithm"`
	EncryptedDEK []byte            `json:"encrypted_dek"`
	KeyID        string            `json:"kms_key_id"`
	AADDigest    string            `json:"aad_sha256"`
	AADContext   map[string]string `json:"-"`
	Source       json.RawMessage   `json:"source,omitempty"`
}

func (e *Envelope) seal(
	ctx context.Context,
	envelopeContext certificateasset.PrivateKeyEnvelopeContext,
	material []byte,
	kind string,
	source json.RawMessage,
) (certificateasset.PrivateKeyEnvelope, error) {
	aad, aadDigest, err := canonicalAAD(envelopeContext)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, err
	}
	if kind == "opaque_wrapped" && (len(source) == 0 || !json.Valid(source)) {
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	dek := make([]byte, dekBytes)
	defer zeroBytes(dek)
	if _, err := rand.Read(dek); err != nil {
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	ciphertext := gcm.Seal(nil, nonce, material, authenticatedAAD(aad, source))
	contextMap := map[string]string{encryptionContextKey: hex.EncodeToString(aadDigest[:])}
	result, err := e.kms.Encrypt(ctx, &kms.EncryptInput{
		KeyId: aws.String(e.keyID), Plaintext: append([]byte(nil), dek...), EncryptionContext: contextMap,
	})
	if err != nil || result == nil || len(result.CiphertextBlob) == 0 {
		zeroBytes(ciphertext)
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	metadata := envelopeMetadata{
		Schema: privateKeyEnvelopeSchema, Kind: kind, Algorithm: envelopeAlgorithm,
		EncryptedDEK: append([]byte(nil), result.CiphertextBlob...), KeyID: e.keyID,
		AADDigest: hex.EncodeToString(aadDigest[:]), AADContext: contextMap,
	}
	if kind == "opaque_wrapped" {
		metadata.Schema = opaqueEnvelopeSchema
		metadata.Source = append(json.RawMessage(nil), source...)
	}
	raw, err := json.Marshal(metadata)
	if err != nil {
		zeroBytes(ciphertext)
		return certificateasset.PrivateKeyEnvelope{}, ErrUnavailable
	}
	if len(raw) > 4096 {
		zeroBytes(ciphertext)
		return certificateasset.PrivateKeyEnvelope{}, ErrInvalidInput
	}
	return certificateasset.PrivateKeyEnvelope{
		KeyID: e.keyID, Ciphertext: ciphertext, Nonce: nonce, Metadata: raw,
	}, nil
}

func authenticatedAAD(canonicalAAD []byte, source json.RawMessage) []byte {
	if len(source) == 0 {
		return canonicalAAD
	}
	result := make([]byte, 0, len(canonicalAAD)+1+len(source))
	result = append(result, canonicalAAD...)
	result = append(result, 0)
	return append(result, source...)
}

func (e *Envelope) decryptDEK(ctx context.Context, keyID string, encryptedDEK []byte, encryptionContext map[string]string) ([]byte, error) {
	if !validKeyID(keyID) || len(encryptedDEK) == 0 || len(encryptedDEK) > 16*1024 {
		return nil, ErrInvalidInput
	}
	result, err := e.kms.Decrypt(ctx, &kms.DecryptInput{
		KeyId: aws.String(keyID), CiphertextBlob: append([]byte(nil), encryptedDEK...), EncryptionContext: encryptionContext,
	})
	if err != nil || result == nil || len(result.Plaintext) != dekBytes {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), result.Plaintext...), nil
}

func canonicalAAD(value certificateasset.PrivateKeyEnvelopeContext) ([]byte, [32]byte, error) {
	aad, err := value.CanonicalAAD()
	if err != nil {
		return nil, [32]byte{}, ErrInvalidInput
	}
	digest := sha256.Sum256(aad)
	return aad, digest, nil
}

func decodeMetadata(envelope certificateasset.PrivateKeyEnvelope, aadDigest [32]byte) (envelopeMetadata, error) {
	if !validKeyID(envelope.KeyID) || len(envelope.Metadata) == 0 || len(envelope.Metadata) > 4096 {
		return envelopeMetadata{}, ErrInvalidInput
	}
	var metadata envelopeMetadata
	decoder := json.NewDecoder(strings.NewReader(string(envelope.Metadata)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil || metadata.EncryptedDEK == nil ||
		len(metadata.EncryptedDEK) == 0 || len(metadata.EncryptedDEK) > 16*1024 ||
		metadata.Algorithm != envelopeAlgorithm || metadata.KeyID != envelope.KeyID ||
		metadata.AADDigest != hex.EncodeToString(aadDigest[:]) {
		if metadata.AADDigest != "" && metadata.AADDigest != hex.EncodeToString(aadDigest[:]) {
			return envelopeMetadata{}, ErrAADMismatch
		}
		return envelopeMetadata{}, ErrInvalidInput
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return envelopeMetadata{}, ErrInvalidInput
	}
	if metadata.Schema == privateKeyEnvelopeSchema && metadata.Kind != "pkcs8" {
		return envelopeMetadata{}, ErrInvalidInput
	}
	if metadata.Schema == opaqueEnvelopeSchema && (metadata.Kind != "opaque_wrapped" || len(metadata.Source) == 0 || !json.Valid(metadata.Source)) {
		return envelopeMetadata{}, ErrInvalidInput
	}
	if metadata.Schema != privateKeyEnvelopeSchema && metadata.Schema != opaqueEnvelopeSchema {
		return envelopeMetadata{}, ErrInvalidInput
	}
	metadata.AADContext = map[string]string{encryptionContextKey: hex.EncodeToString(aadDigest[:])}
	return metadata, nil
}

func validKeyID(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && utf8.ValidString(value) &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ certificateasset.PrivateKeyEnveloper = (*Envelope)(nil)
