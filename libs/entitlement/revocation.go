package entitlement

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"time"
)

const (
	RevocationSetSchemaV2           = "cdnca.entitlement.revocation-set/v2"
	RevocationSetSignatureDomainV2  = "cdnca-entitlement-revocation-set-signature/v2"
	RevocationSetFetchProofDomainV2 = "cdnca-entitlement-revocation-set-fetch-proof/v2"
	RevocationSetAudience           = "cdnca-control-plane"
	RevocationSetPath               = "/installation/v2/entitlement-revocation-sets/current"
	RevocationSetMediaTypeV2        = "application/vnd.cdnca.entitlement-revocation-set.v2+json"
	RevocationSetAlgorithm          = "Ed25519"
	RevocationSetMaxSerials         = 65_536
	RevocationSetMaxBytes           = 1 << 20
	RevocationSetWindow             = 15 * time.Minute
	RevocationFetchClockSkew        = 5 * time.Minute
	revocationMaxUnixTimestamp      = int64(253402300799)
)

// RevocationLeaseRefreshGenerationHeader carries the installation's plugin market lease
// refresh generation on every revocation set response (200 and 304). The controller
// renews its lease as soon as the value differs from the last one seen.
const RevocationLeaseRefreshGenerationHeader = "X-Cdnca-Lease-Refresh-Generation"

var (
	ErrInvalidRevocationSet           = errors.New("invalid entitlement revocation set")
	ErrInvalidRevocationEnvelope      = errors.New("invalid entitlement revocation envelope")
	ErrInvalidRevocationSignature     = errors.New("invalid entitlement revocation signature")
	ErrRevocationAudienceMismatch     = errors.New("entitlement revocation audience mismatch")
	ErrRevocationCustomerMismatch     = errors.New("entitlement revocation customer mismatch")
	ErrRevocationInstallationMismatch = errors.New("entitlement revocation installation mismatch")
	ErrRevocationLicenseMismatch      = errors.New("entitlement revocation license mismatch")
	ErrRevocationNotCurrent           = errors.New("entitlement revocation set is not current")
	ErrRevocationKeyWindow            = errors.New("entitlement revocation signing key does not cover artifact")
	ErrInvalidRevocationFetchProof    = errors.New("invalid entitlement revocation fetch proof")
	ErrRevocationFetchExpired         = errors.New("entitlement revocation fetch proof is outside the clock window")
)

var (
	revocationUUIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	revocationKeyIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	revocationDigestPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	revocationETagPattern   = regexp.MustCompile(`^"sha256-[A-Za-z0-9_-]{43}"$`)
)

// RevocationSigner is intentionally independent from the lease signer API.
type RevocationSigner interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type RevocationSet struct {
	Schema         string   `json:"schema"`
	Audience       string   `json:"audience"`
	CustomerID     string   `json:"customer_id"`
	InstallationID string   `json:"installation_id"`
	LicenseID      string   `json:"license_id"`
	Revision       uint64   `json:"revision"`
	IssuedAt       int64    `json:"issued_at"`
	ExpiresAt      int64    `json:"expires_at"`
	RevokedSerials []uint64 `json:"revoked_serials"`
}

type SignedRevocationSet struct {
	Algorithm string        `json:"algorithm"`
	KeyID     string        `json:"key_id"`
	Body      RevocationSet `json:"body"`
	Signature string        `json:"signature"`
}

type revocationSigningDocument struct {
	Domain    string        `json:"domain"`
	Algorithm string        `json:"algorithm"`
	KeyID     string        `json:"key_id"`
	Body      RevocationSet `json:"body"`
}

type RevocationKeyWindow struct {
	NotBefore   time.Time
	SignUntil   *time.Time
	VerifyUntil *time.Time
}

type RevocationVerifyOptions struct {
	Now                    time.Time
	ExpectedAudience       string
	ExpectedCustomerID     string
	ExpectedInstallationID string
	ExpectedLicenseID      string
	KeyWindow              RevocationKeyWindow
}

type RevocationFetchProof struct {
	InstallationID string
	RequestID      string
	RequestedAt    int64
	KnownRevision  uint64
	KnownDigest    string
	IfNoneMatch    string
	Signature      string
}

func SignRevocationSet(ctx context.Context, body RevocationSet, signer RevocationSigner,
	window RevocationKeyWindow,
) (SignedRevocationSet, error) {
	if signer == nil || !revocationKeyIDPattern.MatchString(signer.KeyID()) {
		return SignedRevocationSet{}, ErrInvalidRevocationEnvelope
	}
	if err := body.validate(); err != nil {
		return SignedRevocationSet{}, err
	}
	if !window.covers(body) {
		return SignedRevocationSet{}, ErrRevocationKeyWindow
	}
	document := revocationSigningDocument{Domain: RevocationSetSignatureDomainV2,
		Algorithm: RevocationSetAlgorithm, KeyID: signer.KeyID(), Body: body}
	payload, err := json.Marshal(document)
	if err != nil {
		return SignedRevocationSet{}, fmt.Errorf("marshal entitlement revocation signing document: %w", err)
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return SignedRevocationSet{}, fmt.Errorf("sign entitlement revocation set: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedRevocationSet{}, ErrInvalidRevocationSignature
	}
	return SignedRevocationSet{Algorithm: RevocationSetAlgorithm, KeyID: signer.KeyID(), Body: body,
		Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func (signed SignedRevocationSet) Encode() ([]byte, error) {
	if err := signed.validateEnvelope(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("encode entitlement revocation set: %w", err)
	}
	if len(encoded) > RevocationSetMaxBytes {
		return nil, ErrInvalidRevocationEnvelope
	}
	return encoded, nil
}

func DecodeRevocationSet(encoded []byte) (SignedRevocationSet, error) {
	if len(encoded) == 0 || len(encoded) > RevocationSetMaxBytes || validateUniqueJSON(encoded) != nil {
		return SignedRevocationSet{}, ErrInvalidRevocationEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var signed SignedRevocationSet
	if err := decoder.Decode(&signed); err != nil {
		return SignedRevocationSet{}, ErrInvalidRevocationEnvelope
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SignedRevocationSet{}, ErrInvalidRevocationEnvelope
	}
	if err := signed.validateEnvelope(); err != nil {
		return SignedRevocationSet{}, err
	}
	canonical, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return SignedRevocationSet{}, ErrInvalidRevocationEnvelope
	}
	return signed, nil
}

func VerifyRevocationSet(signed SignedRevocationSet, publicKey ed25519.PublicKey,
	options RevocationVerifyOptions,
) (RevocationSet, error) {
	if err := signed.validateEnvelope(); err != nil {
		return RevocationSet{}, err
	}
	if len(publicKey) != ed25519.PublicKeySize || !options.KeyWindow.covers(signed.Body) {
		return RevocationSet{}, ErrRevocationKeyWindow
	}
	document, err := json.Marshal(revocationSigningDocument{Domain: RevocationSetSignatureDomainV2,
		Algorithm: signed.Algorithm, KeyID: signed.KeyID, Body: signed.Body})
	if err != nil {
		return RevocationSet{}, ErrInvalidRevocationEnvelope
	}
	signature, _ := decodeRawURL(signed.Signature, ed25519.SignatureSize)
	if !ed25519.Verify(publicKey, document, signature) {
		return RevocationSet{}, ErrInvalidRevocationSignature
	}
	if options.ExpectedAudience == "" || signed.Body.Audience != options.ExpectedAudience {
		return RevocationSet{}, ErrRevocationAudienceMismatch
	}
	if options.ExpectedCustomerID == "" || signed.Body.CustomerID != options.ExpectedCustomerID {
		return RevocationSet{}, ErrRevocationCustomerMismatch
	}
	if options.ExpectedInstallationID == "" || signed.Body.InstallationID != options.ExpectedInstallationID {
		return RevocationSet{}, ErrRevocationInstallationMismatch
	}
	if options.ExpectedLicenseID == "" || signed.Body.LicenseID != options.ExpectedLicenseID {
		return RevocationSet{}, ErrRevocationLicenseMismatch
	}
	if options.Now.IsZero() || notYetValid(options.Now.UTC().Unix(), signed.Body.IssuedAt) ||
		options.Now.UTC().Unix() >= signed.Body.ExpiresAt {
		return RevocationSet{}, ErrRevocationNotCurrent
	}
	return signed.Body, nil
}

func RevocationSetDigest(encoded []byte) [32]byte { return sha256.Sum256(encoded) }

func RevocationSetETag(encoded []byte) string {
	digest := RevocationSetDigest(encoded)
	return `"sha256-` + base64.RawURLEncoding.EncodeToString(digest[:]) + `"`
}

func RevocationFetchProofMessage(proof RevocationFetchProof) ([]byte, error) {
	if !validRevocationFetchProofFields(proof, false) {
		return nil, ErrInvalidRevocationFetchProof
	}
	fields := []string{RevocationSetFetchProofDomainV2, "GET", RevocationSetPath, proof.RequestID,
		proof.InstallationID, strconv.FormatInt(proof.RequestedAt, 10),
		strconv.FormatUint(proof.KnownRevision, 10), proof.KnownDigest, proof.IfNoneMatch}
	var input bytes.Buffer
	for _, field := range fields {
		if uint64(len(field)) > math.MaxUint32 {
			return nil, ErrInvalidRevocationFetchProof
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		input.Write(size[:])
		input.WriteString(field)
	}
	digest := sha256.Sum256(input.Bytes())
	return digest[:], nil
}

func VerifyRevocationFetchProof(proof RevocationFetchProof, publicKey ed25519.PublicKey, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize || !validRevocationFetchProofFields(proof, true) || now.IsZero() {
		return ErrInvalidRevocationFetchProof
	}
	delta := now.UTC().Unix() - proof.RequestedAt
	if delta < -int64(RevocationFetchClockSkew/time.Second) || delta > int64(RevocationFetchClockSkew/time.Second) {
		return ErrRevocationFetchExpired
	}
	message, err := RevocationFetchProofMessage(proof)
	if err != nil {
		return err
	}
	signature, ok := decodeRawURL(proof.Signature, ed25519.SignatureSize)
	if !ok || !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidRevocationFetchProof
	}
	return nil
}

func (body RevocationSet) validate() error {
	if body.Schema != RevocationSetSchemaV2 || body.Audience != RevocationSetAudience ||
		!validCanonicalUUID(body.CustomerID) || !validCanonicalUUID(body.InstallationID) ||
		!validCanonicalUUID(body.LicenseID) || body.Revision == 0 || body.Revision > math.MaxInt64 ||
		body.IssuedAt <= 0 || body.ExpiresAt > revocationMaxUnixTimestamp || body.ExpiresAt <= body.IssuedAt ||
		body.ExpiresAt-body.IssuedAt != int64(RevocationSetWindow/time.Second) || body.RevokedSerials == nil ||
		len(body.RevokedSerials) > RevocationSetMaxSerials {
		return ErrInvalidRevocationSet
	}
	var previous uint64
	for _, serial := range body.RevokedSerials {
		if serial == 0 || serial > math.MaxInt64 || serial <= previous {
			return ErrInvalidRevocationSet
		}
		previous = serial
	}
	return nil
}

func (signed SignedRevocationSet) validateEnvelope() error {
	if signed.Algorithm != RevocationSetAlgorithm || !revocationKeyIDPattern.MatchString(signed.KeyID) {
		return ErrInvalidRevocationEnvelope
	}
	if err := signed.Body.validate(); err != nil {
		return err
	}
	if _, ok := decodeRawURL(signed.Signature, ed25519.SignatureSize); !ok {
		return ErrInvalidRevocationEnvelope
	}
	return nil
}

func (window RevocationKeyWindow) covers(body RevocationSet) bool {
	if window.NotBefore.IsZero() || window.NotBefore.UTC().Unix() > body.IssuedAt {
		return false
	}
	if window.SignUntil != nil && window.SignUntil.UTC().Unix() < body.ExpiresAt {
		return false
	}
	if window.VerifyUntil != nil && window.VerifyUntil.UTC().Unix() < body.ExpiresAt {
		return false
	}
	return window.SignUntil == nil || window.VerifyUntil == nil || !window.VerifyUntil.Before(*window.SignUntil)
}

func validRevocationFetchProofFields(proof RevocationFetchProof, requireSignature bool) bool {
	if !validCanonicalUUID(proof.InstallationID) || !validVisibleASCIIRevocation(proof.RequestID, 128) ||
		proof.RequestedAt <= 0 || proof.KnownRevision > math.MaxInt64 {
		return false
	}
	if (proof.KnownRevision == 0) != (proof.KnownDigest == "") ||
		(proof.KnownDigest != "" && !validRawDigest(proof.KnownDigest)) ||
		(proof.KnownRevision == 0 && proof.IfNoneMatch != "") ||
		(proof.IfNoneMatch != "" && (proof.IfNoneMatch != `"sha256-`+proof.KnownDigest+`"` ||
			!revocationETagPattern.MatchString(proof.IfNoneMatch))) {
		return false
	}
	if requireSignature {
		_, ok := decodeRawURL(proof.Signature, ed25519.SignatureSize)
		return ok
	}
	return true
}

func validCanonicalUUID(value string) bool {
	return value != "00000000-0000-0000-0000-000000000000" && revocationUUIDPattern.MatchString(value)
}

func validVisibleASCIIRevocation(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validRawDigest(value string) bool {
	if !revocationDigestPattern.MatchString(value) {
		return false
	}
	_, ok := decodeRawURL(value, sha256.Size)
	return ok
}

func decodeRawURL(value string, size int) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return decoded, err == nil && len(decoded) == size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validateUniqueJSON(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidRevocationEnvelope
			}
			if _, exists := seen[key]; exists {
				return ErrInvalidRevocationEnvelope
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidRevocationEnvelope
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(map[json.Delim]byte{'{': '}', '[': ']'}[delimiter]) {
		return ErrInvalidRevocationEnvelope
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidRevocationEnvelope
	}
	return nil
}
