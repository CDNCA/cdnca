// Package edgesignertrust is the node signer trust document
// (cdnca.edge-signer-trust/v1) and its per-node carrier.
//
// The document is signed by the signer revocation offline root (the same root
// and pin as the v2 checkpoint) and lists the platform release keys nodes
// should trust (trusted_keys, for rotation without reinstalling) and the keys
// they must stop trusting (revoked_keys). control-api verifies it against its
// offline-root pin and forwards the exact bytes to every node inside a
// NodeBundle signed with its edge publication key, which nodes already trust
// for deployments. A node's effective artifact trust is its installed
// artifacts.json plus trusted_keys minus revoked_keys
// (docs/architecture/signer-revocation-offline-and-edge.md).
package edgesignertrust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	DocumentSchema    = "cdnca.edge-signer-trust/v1"
	EnvelopeSchema    = "cdnca.edge-signer-trust-envelope/v1"
	Algorithm         = "Ed25519"
	AuthorityOffline  = "offline_root"
	MaxDocumentBytes  = 256 << 10
	MaxTrustedKeys    = 64
	MaxRevokedKeys    = 256
	maxRevision       = 1 << 53
	canonicalTimeForm = "2006-01-02T15:04:05Z"
)

var (
	ErrInvalidDocument = errors.New("edge signer trust document is invalid")
	ErrUntrusted       = errors.New("edge signer trust document signature is not trusted")

	keyIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// UsageInstallationBan marks a trusted key that nodes accept only for
// installation ban notices and service tickets (ADR 0014 §6.1,
// installationban.KeyUsage). Such keys are never artifact signers.
const UsageInstallationBan = "installation-ban"

// TrustedKey has the shape of an artifacts.json entry. An empty Usage is an
// artifact (release) key; UsageInstallationBan is the license lease key.
type TrustedKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	Usage        string `json:"usage,omitempty"`
}

// ArtifactKey reports whether the key may sign artifacts.
func (key TrustedKey) ArtifactKey() bool { return key.Usage == "" }

// RevokedKey matches a key by ID, or by the SHA-256 of its PKIX public key
// when set (so a revoked key cannot come back under another ID).
type RevokedKey struct {
	KeyID           string `json:"key_id"`
	PublicKeySHA256 string `json:"public_key_sha256,omitempty"`
	RevokedAt       string `json:"revoked_at"`
	Reason          string `json:"reason"`
}

type Document struct {
	Schema      string       `json:"schema"`
	Revision    uint64       `json:"revision"`
	IssuedAt    string       `json:"issued_at"`
	TrustedKeys []TrustedKey `json:"trusted_keys"`
	RevokedKeys []RevokedKey `json:"revoked_keys"`
}

type Envelope struct {
	Schema                 string `json:"schema"`
	Algorithm              string `json:"algorithm"`
	AuthorityKind          string `json:"authority_kind"`
	AuthorityKeyID         string `json:"authority_key_id"`
	AuthorityKeyGeneration uint64 `json:"authority_key_generation"`
	DocumentSHA256         string `json:"document_sha256"`
}

// Signed is the wire object; the signature covers the canonical envelope,
// which binds the canonical document digest.
type Signed struct {
	Document  Document `json:"document"`
	Envelope  Envelope `json:"envelope"`
	Signature string   `json:"signature"`
}

// RootPin is an offline root public key a verifier trusts.
type RootPin struct {
	KeyID      string
	Generation uint64
	PublicKey  ed25519.PublicKey
}

// Normalize sorts both lists, then validates. Operators write drafts in any
// order; only normalized documents are signed.
func Normalize(document Document) (Document, error) {
	document.TrustedKeys = append([]TrustedKey{}, document.TrustedKeys...)
	document.RevokedKeys = append([]RevokedKey{}, document.RevokedKeys...)
	sort.Slice(document.TrustedKeys, func(i, j int) bool { return document.TrustedKeys[i].KeyID < document.TrustedKeys[j].KeyID })
	sort.Slice(document.RevokedKeys, func(i, j int) bool { return document.RevokedKeys[i].KeyID < document.RevokedKeys[j].KeyID })
	if err := validateDocument(document); err != nil {
		return Document{}, err
	}
	return document, nil
}

func validateDocument(document Document) error {
	if document.Schema != DocumentSchema || document.Revision == 0 || document.Revision > maxRevision ||
		!canonicalTime(document.IssuedAt) || document.TrustedKeys == nil || document.RevokedKeys == nil ||
		len(document.TrustedKeys) > MaxTrustedKeys || len(document.RevokedKeys) > MaxRevokedKeys {
		return ErrInvalidDocument
	}
	for index, revoked := range document.RevokedKeys {
		if !keyIDPattern.MatchString(revoked.KeyID) || index > 0 && document.RevokedKeys[index-1].KeyID >= revoked.KeyID ||
			revoked.PublicKeySHA256 != "" && !sha256Pattern.MatchString(revoked.PublicKeySHA256) ||
			!canonicalTime(revoked.RevokedAt) || !reasonPattern.MatchString(revoked.Reason) {
			return ErrInvalidDocument
		}
	}
	for index, trusted := range document.TrustedKeys {
		if !keyIDPattern.MatchString(trusted.KeyID) || index > 0 && document.TrustedKeys[index-1].KeyID >= trusted.KeyID ||
			trusted.Usage != "" && trusted.Usage != UsageInstallationBan {
			return ErrInvalidDocument
		}
		publicKey, err := ParsePublicKeyPEM(trusted.PublicKeyPEM)
		if err != nil || document.Revokes(trusted.KeyID, publicKey) {
			return ErrInvalidDocument
		}
		if _, ed := publicKey.(ed25519.PublicKey); trusted.Usage == UsageInstallationBan && !ed {
			return ErrInvalidDocument
		}
	}
	return nil
}

// InstallationBanKeys returns the Ed25519 keys nodes accept for installation
// ban notices and service tickets (trusted keys with UsageInstallationBan).
func (document Document) InstallationBanKeys() map[string]ed25519.PublicKey {
	keys := map[string]ed25519.PublicKey{}
	for _, trusted := range document.TrustedKeys {
		if trusted.Usage != UsageInstallationBan {
			continue
		}
		if publicKey, err := ParsePublicKeyPEM(trusted.PublicKeyPEM); err == nil {
			if key, ok := publicKey.(ed25519.PublicKey); ok && !document.Revokes(trusted.KeyID, key) {
				keys[trusted.KeyID] = key
			}
		}
	}
	return keys
}

// Revokes reports whether the document revokes keyID or the given public key.
func (document Document) Revokes(keyID string, publicKey crypto.PublicKey) bool {
	fingerprint := ""
	if publicKey != nil {
		fingerprint, _ = PublicKeySHA256(publicKey)
	}
	for _, revoked := range document.RevokedKeys {
		if revoked.KeyID == keyID || fingerprint != "" && revoked.PublicKeySHA256 == fingerprint {
			return true
		}
	}
	return false
}

// CanonicalDocument returns the signed bytes of a normalized, valid document.
func CanonicalDocument(document Document) ([]byte, error) {
	if err := validateDocument(document); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > MaxDocumentBytes {
		return nil, ErrInvalidDocument
	}
	return encoded, nil
}

func canonicalEnvelope(envelope Envelope) ([]byte, error) {
	if envelope.Schema != EnvelopeSchema || envelope.Algorithm != Algorithm || envelope.AuthorityKind != AuthorityOffline ||
		!keyIDPattern.MatchString(envelope.AuthorityKeyID) || envelope.AuthorityKeyGeneration == 0 ||
		decodeDigest(envelope.DocumentSHA256) == nil {
		return nil, ErrInvalidDocument
	}
	return json.Marshal(envelope)
}

// Sign signs a normalized document with the offline root and returns the
// canonical wire bytes.
func Sign(document Document, keyID string, generation uint64, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidDocument
	}
	canonical, err := CanonicalDocument(document)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	envelope := Envelope{Schema: EnvelopeSchema, Algorithm: Algorithm, AuthorityKind: AuthorityOffline,
		AuthorityKeyID: keyID, AuthorityKeyGeneration: generation,
		DocumentSHA256: base64.RawURLEncoding.EncodeToString(digest[:])}
	envelopeBytes, err := canonicalEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Signed{Document: document, Envelope: envelope,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, envelopeBytes))})
}

// Decode strictly decodes canonical wire bytes and checks the structure and
// the document digest, but not the signature (see Verify).
func Decode(encoded []byte) (Signed, error) {
	if len(encoded) == 0 || len(encoded) > MaxDocumentBytes+4096 {
		return Signed{}, ErrInvalidDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed Signed
	if err := decoder.Decode(&signed); err != nil {
		return Signed{}, ErrInvalidDocument
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Signed{}, ErrInvalidDocument
	}
	document, err := CanonicalDocument(signed.Document)
	if err != nil {
		return Signed{}, err
	}
	if _, err := canonicalEnvelope(signed.Envelope); err != nil || decodeSignature(signed.Signature) == nil {
		return Signed{}, ErrInvalidDocument
	}
	digest := sha256.Sum256(document)
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) ||
		!bytes.Equal(decodeDigest(signed.Envelope.DocumentSHA256), digest[:]) {
		return Signed{}, ErrInvalidDocument
	}
	return signed, nil
}

// Verify decodes and verifies the offline root signature against pins.
func Verify(encoded []byte, pins []RootPin) (Signed, error) {
	signed, err := Decode(encoded)
	if err != nil {
		return Signed{}, err
	}
	envelope, _ := canonicalEnvelope(signed.Envelope)
	for _, pin := range pins {
		if pin.KeyID == signed.Envelope.AuthorityKeyID && pin.Generation == signed.Envelope.AuthorityKeyGeneration &&
			len(pin.PublicKey) == ed25519.PublicKeySize {
			if ed25519.Verify(pin.PublicKey, envelope, decodeSignature(signed.Signature)) {
				return signed, nil
			}
			return Signed{}, ErrUntrusted
		}
	}
	return Signed{}, ErrUntrusted
}

// ParsePublicKeyPEM accepts the key types artifacts.json may hold: Ed25519
// and ECDSA P-256 PKIX public keys.
func ParsePublicKeyPEM(value string) (crypto.PublicKey, error) {
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, ErrInvalidDocument
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrInvalidDocument
	}
	switch key := parsed.(type) {
	case ed25519.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			return key, nil
		}
	}
	return nil, ErrInvalidDocument
}

// PublicKeySHA256 is the lowercase hex SHA-256 of the PKIX DER public key.
func PublicKeySHA256(publicKey crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", ErrInvalidDocument
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

// CanonicalTime formats a timestamp for document fields.
func CanonicalTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(canonicalTimeForm)
}

func canonicalTime(value string) bool {
	parsed, err := time.Parse(canonicalTimeForm, value)
	return err == nil && !parsed.IsZero() && parsed.Format(canonicalTimeForm) == value
}

func decodeDigest(value string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
}

func decodeSignature(value string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
}
