package artifactcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

const (
	SignatureDomain = "cdnca-artifact-catalog-signature/v1"
	MaxSignedBytes  = MaxCatalogBytes + 64<<10
	maxUnixSeconds  = 253402300799
	signingSkew     = 5 * time.Minute
)

var (
	ErrInvalidEnvelope      = errors.New("invalid artifact catalog envelope")
	ErrDigestMismatch       = errors.New("artifact catalog digest mismatch")
	ErrInvalidSignature     = errors.New("invalid artifact catalog signature")
	ErrTargetMismatch       = errors.New("artifact catalog targets another installation")
	ErrNotYetValid          = errors.New("artifact catalog is not yet valid")
	ErrExpired              = errors.New("artifact catalog expired")
	ErrRevisionOutOfOrder   = errors.New("artifact catalog revision is out of order")
	ErrSupersedesMismatch   = errors.New("artifact catalog supersedes mismatch")
	ErrSigningKeyIDRejected = errors.New("artifact catalog signing key id rejected")

	uuidPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// Envelope is the signed header of one installation's catalog delivery
// (same fields as the earlier security rule catalog envelope). Field order is
// alphabetical so the canonical JSON is easy to reproduce.
type Envelope struct {
	CatalogSHA256  string  `json:"catalog_sha256"`
	DeliveryID     string  `json:"delivery_id"`
	Domain         string  `json:"domain"`
	ExpiresAt      int64   `json:"expires_at"`
	InstallationID string  `json:"installation_id"`
	KeyID          string  `json:"key_id"`
	Schema         string  `json:"schema"`
	ScopeRevision  uint64  `json:"scope_revision"`
	SignedAt       int64   `json:"signed_at"`
	Supersedes     *string `json:"supersedes"`
	ValidFrom      int64   `json:"valid_from"`
}

type Signed struct {
	Envelope  Envelope `json:"envelope"`
	Catalog   Catalog  `json:"catalog"`
	Signature string   `json:"signature"`
}

// Signer matches entitlement.Signer (the license service online key).
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// Verifier matches the control-api entitlementguard trust store.
type Verifier interface {
	VerifyDetached(keyID string, payload, signature []byte, signedAt, now time.Time) error
}

// Head is the last applied delivery on the consumer side.
type Head struct {
	DeliveryID    string
	ScopeRevision uint64
	CatalogSHA256 string
}

type VerifyOptions struct {
	Now            time.Time
	InstallationID string
	Head           *Head
}

type Verified struct {
	Signed           Signed
	CanonicalCatalog []byte
	Duplicate        bool
}

func CanonicalEnvelope(envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// Sign builds the signed delivery; catalog_sha256, key_id, domain and schema
// are filled in.
func Sign(ctx context.Context, envelope Envelope, catalog Catalog, signer Signer) (Signed, error) {
	if signer == nil || !keyIDPattern.MatchString(signer.KeyID()) {
		return Signed{}, ErrSigningKeyIDRejected
	}
	_, digest, err := CanonicalCatalog(catalog)
	if err != nil {
		return Signed{}, err
	}
	envelope.Domain, envelope.Schema, envelope.KeyID = SignatureDomain, CatalogSchema, signer.KeyID()
	envelope.CatalogSHA256 = DigestString(digest)
	payload, err := CanonicalEnvelope(envelope)
	if err != nil {
		return Signed{}, err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return Signed{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return Signed{}, ErrInvalidSignature
	}
	return Signed{Envelope: envelope, Catalog: catalog, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func (signed Signed) Encode() ([]byte, error) {
	if err := validateShape(signed); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(signed)
	if err != nil || len(encoded) > MaxSignedBytes {
		return nil, ErrInvalidEnvelope
	}
	return encoded, nil
}

// Decode strictly parses a signed delivery: no unknown fields, no duplicate
// keys, one JSON document, bounded size, valid shape and digest.
func Decode(encoded []byte) (Signed, error) {
	if len(encoded) < 2 || len(encoded) > MaxSignedBytes || !json.Valid(encoded) || rulecatalog.RejectDuplicateKeys(encoded) != nil {
		return Signed{}, ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed Signed
	if err := decoder.Decode(&signed); err != nil {
		return Signed{}, ErrInvalidEnvelope
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Signed{}, ErrInvalidEnvelope
	}
	if err := validateShape(signed); err != nil {
		return Signed{}, err
	}
	return signed, nil
}

// VerifyEd25519 checks only the signature with a raw public key (license
// service self-check before persisting a delivery).
func VerifyEd25519(signed Signed, publicKey ed25519.PublicKey) error {
	if err := validateShape(signed); err != nil || len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidEnvelope
	}
	payload, _ := CanonicalEnvelope(signed.Envelope)
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Verify is the consumer check: shape, digest, detached signature through
// the deployment trust chain, target, validity window and a monotonic
// scope_revision/supersedes chain against the applied head.
func Verify(signed Signed, trust Verifier, options VerifyOptions) (Verified, error) {
	if trust == nil || options.Now.IsZero() || !uuidPattern.MatchString(options.InstallationID) {
		return Verified{}, ErrInvalidEnvelope
	}
	if err := validateShape(signed); err != nil {
		return Verified{}, err
	}
	canonical, _, _ := CanonicalCatalog(signed.Catalog)
	payload, _ := CanonicalEnvelope(signed.Envelope)
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	signedAt := time.Unix(signed.Envelope.SignedAt, 0).UTC()
	if signedAt.After(options.Now.UTC().Add(signingSkew)) {
		return Verified{}, ErrInvalidEnvelope
	}
	verifyThrough := time.Unix(signed.Envelope.ExpiresAt, 0).UTC().Add(-time.Nanosecond)
	if err := trust.VerifyDetached(signed.Envelope.KeyID, payload, signature, signedAt, verifyThrough); err != nil {
		return Verified{}, errors.Join(ErrInvalidSignature, err)
	}
	if signed.Envelope.InstallationID != options.InstallationID {
		return Verified{}, ErrTargetMismatch
	}
	now := options.Now.UTC().Unix()
	if now < signed.Envelope.ValidFrom {
		return Verified{}, ErrNotYetValid
	}
	if now >= signed.Envelope.ExpiresAt {
		return Verified{}, ErrExpired
	}
	duplicate, err := verifyRevision(signed.Envelope, options.Head)
	if err != nil {
		return Verified{}, err
	}
	return Verified{Signed: signed, CanonicalCatalog: canonical, Duplicate: duplicate}, nil
}

func verifyRevision(envelope Envelope, head *Head) (bool, error) {
	if head == nil || head.ScopeRevision == 0 {
		if envelope.ScopeRevision > 1 && envelope.Supersedes == nil {
			return false, ErrSupersedesMismatch
		}
		return false, nil
	}
	switch {
	case envelope.ScopeRevision == head.ScopeRevision:
		if envelope.DeliveryID == head.DeliveryID && envelope.CatalogSHA256 == head.CatalogSHA256 {
			return true, nil
		}
		return false, ErrRevisionOutOfOrder
	case envelope.ScopeRevision < head.ScopeRevision:
		return false, ErrRevisionOutOfOrder
	case envelope.Supersedes == nil:
		return false, ErrSupersedesMismatch
	case envelope.ScopeRevision == head.ScopeRevision+1 && *envelope.Supersedes != head.DeliveryID:
		// Revisions can skip only when an intermediate delivery was never
		// received; a direct successor must chain to the applied head.
		return false, ErrSupersedesMismatch
	}
	return false, nil
}

func validateShape(signed Signed) error {
	if err := validateEnvelope(signed.Envelope); err != nil {
		return err
	}
	_, digest, err := CanonicalCatalog(signed.Catalog)
	if err != nil {
		return ErrInvalidEnvelope
	}
	if DigestString(digest) != signed.Envelope.CatalogSHA256 {
		return ErrDigestMismatch
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != signed.Signature {
		return ErrInvalidEnvelope
	}
	return nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.Domain != SignatureDomain || envelope.Schema != CatalogSchema || !keyIDPattern.MatchString(envelope.KeyID) ||
		!uuidPattern.MatchString(envelope.DeliveryID) || !uuidPattern.MatchString(envelope.InstallationID) ||
		envelope.ScopeRevision < 1 || envelope.ScopeRevision > maxRevision || !validDigest(envelope.CatalogSHA256) ||
		envelope.SignedAt <= 0 || envelope.SignedAt > maxUnixSeconds || envelope.ValidFrom <= 0 ||
		envelope.ExpiresAt > maxUnixSeconds || envelope.ValidFrom >= envelope.ExpiresAt || envelope.SignedAt >= envelope.ExpiresAt {
		return ErrInvalidEnvelope
	}
	if envelope.ScopeRevision == 1 && envelope.Supersedes != nil ||
		envelope.Supersedes != nil && (!uuidPattern.MatchString(*envelope.Supersedes) || *envelope.Supersedes == envelope.DeliveryID) {
		return ErrInvalidEnvelope
	}
	return nil
}

func validDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && len(value) == 43
}

// ValidUUID reports a canonical lowercase UUID.
func ValidUUID(value string) bool { return uuidPattern.MatchString(value) }

// ValidDigest reports an envelope catalog digest (base64url SHA-256).
func ValidDigest(value string) bool { return validDigest(value) }
