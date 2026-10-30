// Package installationban is the installation ban contract (ADR 0014 LIC-BAN-01).
//
// The license service signs two documents for one control installation with
// its lease signing key:
//
//   - BanNotice (cdnca.installation-ban/v1): the installation is banned until a
//     time or permanently, or a ban was lifted.
//   - ServiceTicket (cdnca.installation-service-ticket/v1): the installation's
//     nodes may take new sites, scale and upgrade until not_after (the node
//     offline tolerance, renewed daily). An expired ticket freezes the node; it
//     keeps serving what is already published. Only a ban in
//     effect stops traffic.
//
// control-api forwards the exact bytes to its nodes and cannot forge or extend
// either document. Both share one per-installation revision sequence: verifiers
// keep the highest revision they accepted and refuse anything lower, so an old
// "lifted" notice or an old ticket cannot be replayed after a newer ban.
package installationban

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	NoticeSchema          = "cdnca.installation-ban/v1"
	TicketSchema          = "cdnca.installation-service-ticket/v1"
	NoticeSignatureDomain = "cdnca-installation-ban-signature/v1"
	TicketSignatureDomain = "cdnca-installation-service-ticket-signature/v1"
	Algorithm             = "Ed25519"

	StateBanned = "banned"
	StateLifted = "lifted"

	// KeyUsage marks the node signer trust entries (edgesignertrust.TrustedKey.Usage)
	// nodes accept for these documents; such keys are never trusted for artifacts.
	KeyUsage = "installation-ban"

	// DefaultNodeOfflineTolerance is how long a ticket keeps nodes unfrozen
	// without a renewal: the controller's 30-day lease grace
	// (configurable, at most MaxTicketValidity).
	DefaultNodeOfflineTolerance = 30 * 24 * time.Hour
	// TicketRenewInterval is how often the license service issues a fresh ticket.
	TicketRenewInterval = 24 * time.Hour
	// MaxTicketValidity bounds not_after - issued_at for any configured tolerance.
	MaxTicketValidity = 31 * 24 * time.Hour
	// MaxClockSkew is the tolerated difference between a verifier's clock and
	// the signer's, and how far a node clock may fall back before the node
	// treats its ticket as expired.
	MaxClockSkew = 10 * time.Minute

	MaxDocumentBytes  = 16 << 10
	MaxReasonTextRune = 500
	maxUnixTimestamp  = int64(253402300799)
)

var (
	ErrInvalidDocument   = errors.New("installation ban document is invalid")
	ErrUntrusted         = errors.New("installation ban document signature is not trusted")
	ErrInstallationMatch = errors.New("installation ban document is for another installation")
	ErrNotYetValid       = errors.New("installation ban document is issued in the future")
	ErrTicketExpired     = errors.New("installation service ticket has expired")
	ErrRevisionRollback  = errors.New("installation ban document revision is older than the accepted one")
	ErrRevisionConflict  = errors.New("installation ban document revision was already accepted with other content")
	ErrInvalidSigner     = errors.New("installation ban signer is invalid")
	uuidPattern          = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	keyIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	reasonCodePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Signer is the lease signing key (same shape as entitlement.Signer).
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// BanNotice body. Times are Unix seconds; Until nil means permanent.
type BanNotice struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	CustomerID     string `json:"customer_id"`
	BanID          string `json:"ban_id"`
	Revision       uint64 `json:"revision"`
	State          string `json:"state"`
	ReasonCode     string `json:"reason_code"`
	ReasonText     string `json:"reason_text"`
	StartsAt       int64  `json:"starts_at"`
	Until          *int64 `json:"until"`
	IssuedAt       int64  `json:"issued_at"`
}

// ServiceTicket body. Times are Unix seconds.
type ServiceTicket struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	CustomerID     string `json:"customer_id"`
	LicenseID      string `json:"license_id"`
	Revision       uint64 `json:"revision"`
	IssuedAt       int64  `json:"issued_at"`
	NotAfter       int64  `json:"not_after"`
}

type SignedNotice struct {
	Algorithm string    `json:"algorithm"`
	KeyID     string    `json:"key_id"`
	Body      BanNotice `json:"body"`
	Signature string    `json:"signature"`
}

type SignedTicket struct {
	Algorithm string        `json:"algorithm"`
	KeyID     string        `json:"key_id"`
	Body      ServiceTicket `json:"body"`
	Signature string        `json:"signature"`
}

type signingDocument[T any] struct {
	Domain    string `json:"domain"`
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Body      T      `json:"body"`
}

// VerifyOptions: Keys maps trusted key IDs to Ed25519 public keys (control-api:
// the license signing keyset; nodes: signer trust entries with Usage KeyUsage).
type VerifyOptions struct {
	Now                    time.Time
	ExpectedInstallationID string
	Keys                   map[string]ed25519.PublicKey
}

func (notice BanNotice) Validate() error {
	if notice.Schema != NoticeSchema || !validUUID(notice.InstallationID) || !validUUID(notice.CustomerID) ||
		!validUUID(notice.BanID) || !validRevision(notice.Revision) ||
		(notice.State != StateBanned && notice.State != StateLifted) ||
		!reasonCodePattern.MatchString(notice.ReasonCode) || !validReasonText(notice.ReasonText) ||
		!validTimestamp(notice.StartsAt) || !validTimestamp(notice.IssuedAt) ||
		(notice.Until != nil && (!validTimestamp(*notice.Until) || *notice.Until <= notice.StartsAt)) {
		return ErrInvalidDocument
	}
	return nil
}

func (ticket ServiceTicket) Validate() error {
	if ticket.Schema != TicketSchema || !validUUID(ticket.InstallationID) || !validUUID(ticket.CustomerID) ||
		!validUUID(ticket.LicenseID) || !validRevision(ticket.Revision) || !validTimestamp(ticket.IssuedAt) ||
		!validTimestamp(ticket.NotAfter) || ticket.NotAfter <= ticket.IssuedAt ||
		ticket.NotAfter-ticket.IssuedAt > int64(MaxTicketValidity/time.Second) {
		return ErrInvalidDocument
	}
	return nil
}

func SignNotice(ctx context.Context, notice BanNotice, signer Signer) ([]byte, error) {
	if err := notice.Validate(); err != nil {
		return nil, err
	}
	keyID, signature, err := sign(ctx, NoticeSignatureDomain, notice, signer)
	if err != nil {
		return nil, err
	}
	return encode(SignedNotice{Algorithm: Algorithm, KeyID: keyID, Body: notice, Signature: signature})
}

func SignTicket(ctx context.Context, ticket ServiceTicket, signer Signer) ([]byte, error) {
	if err := ticket.Validate(); err != nil {
		return nil, err
	}
	keyID, signature, err := sign(ctx, TicketSignatureDomain, ticket, signer)
	if err != nil {
		return nil, err
	}
	return encode(SignedTicket{Algorithm: Algorithm, KeyID: keyID, Body: ticket, Signature: signature})
}

// DecodeNotice strictly decodes canonical wire bytes without checking the signature.
func DecodeNotice(encoded []byte) (SignedNotice, error) {
	var signed SignedNotice
	if err := decodeCanonical(encoded, &signed); err != nil {
		return SignedNotice{}, err
	}
	if signed.Algorithm != Algorithm || !keyIDPattern.MatchString(signed.KeyID) || decodeSignature(signed.Signature) == nil {
		return SignedNotice{}, ErrInvalidDocument
	}
	if err := signed.Body.Validate(); err != nil {
		return SignedNotice{}, err
	}
	return signed, nil
}

// DecodeTicket strictly decodes canonical wire bytes without checking the signature.
func DecodeTicket(encoded []byte) (SignedTicket, error) {
	var signed SignedTicket
	if err := decodeCanonical(encoded, &signed); err != nil {
		return SignedTicket{}, err
	}
	if signed.Algorithm != Algorithm || !keyIDPattern.MatchString(signed.KeyID) || decodeSignature(signed.Signature) == nil {
		return SignedTicket{}, ErrInvalidDocument
	}
	if err := signed.Body.Validate(); err != nil {
		return SignedTicket{}, err
	}
	return signed, nil
}

// VerifyNotice checks the signature, the installation and that the notice is
// not issued in the future. A notice does not expire; whether a ban is still
// in effect is BanNotice.InEffect.
func VerifyNotice(encoded []byte, options VerifyOptions) (BanNotice, error) {
	signed, err := DecodeNotice(encoded)
	if err != nil {
		return BanNotice{}, err
	}
	if err := verifySignature(NoticeSignatureDomain, signed.KeyID, signed.Body, signed.Signature, options.Keys); err != nil {
		return BanNotice{}, err
	}
	if err := checkCommon(signed.Body.InstallationID, signed.Body.IssuedAt, options); err != nil {
		return BanNotice{}, err
	}
	return signed.Body, nil
}

// VerifyTicket checks the signature, the installation, issued_at and that the
// ticket has not expired at options.Now.
func VerifyTicket(encoded []byte, options VerifyOptions) (ServiceTicket, error) {
	signed, err := DecodeTicket(encoded)
	if err != nil {
		return ServiceTicket{}, err
	}
	if err := verifySignature(TicketSignatureDomain, signed.KeyID, signed.Body, signed.Signature, options.Keys); err != nil {
		return ServiceTicket{}, err
	}
	if err := checkCommon(signed.Body.InstallationID, signed.Body.IssuedAt, options); err != nil {
		return ServiceTicket{}, err
	}
	if options.Now.UTC().Unix() >= signed.Body.NotAfter {
		return ServiceTicket{}, ErrTicketExpired
	}
	return signed.Body, nil
}

// InEffect reports whether a verified notice bans the installation at now.
func (notice BanNotice) InEffect(now time.Time) bool {
	return notice.State == StateBanned && (notice.Until == nil || now.UTC().Unix() < *notice.Until)
}

// CheckRevision applies the shared per-installation revision rule: a document
// is accepted when its revision is higher than the accepted one, or equal with
// identical bytes (idempotent redelivery). digest is SHA-256 of the wire bytes.
func CheckRevision(acceptedRevision uint64, acceptedDigest [32]byte, revision uint64, digest [32]byte) error {
	switch {
	case revision < acceptedRevision:
		return ErrRevisionRollback
	case revision == acceptedRevision && digest != acceptedDigest:
		return ErrRevisionConflict
	}
	return nil
}

// CheckTicketClock decides expiry on a node whose wall clock may have been
// moved back. highWater is the latest wall-clock time the node has persisted
// (zero if none). A clock more than MaxClockSkew behind issued_at or behind
// highWater counts as expired, so turning the clock back never extends a ticket.
func CheckTicketClock(ticket ServiceTicket, now, highWater time.Time) error {
	unix := now.UTC().Unix()
	skew := int64(MaxClockSkew / time.Second)
	if unix >= ticket.NotAfter || unix+skew < ticket.IssuedAt ||
		(!highWater.IsZero() && unix+skew < highWater.UTC().Unix()) {
		return ErrTicketExpired
	}
	return nil
}

// Status is what a node or control-api derives from the latest accepted documents.
type Status string

const (
	StatusServing       Status = "serving"
	StatusBanned        Status = "banned"
	StatusTicketExpired Status = "service_ticket_expired"
	StatusNoTicket      Status = "no_ticket"
)

// StopsServing reports whether a node stops its existing traffic at status:
// only a signed ban in effect, and a node that never got
// its first ticket (PF09). An expired ticket or an unknown status does not.
func StopsServing(status Status) bool {
	return status == StatusBanned || status == StatusNoTicket
}

// Frozen reports whether a node refuses new publications, scaling and
// upgrades at status: anything but serving.
func Frozen(status Status) bool { return status != StatusServing }

// Evaluate combines the latest accepted notice and ticket (either may be nil).
// A ban in effect wins unless a ticket with a higher revision was issued after
// it (the license service only issues tickets to unbanned installations).
func Evaluate(notice *BanNotice, ticket *ServiceTicket, now, highWater time.Time) Status {
	if notice != nil && notice.InEffect(now) && (ticket == nil || ticket.Revision < notice.Revision) {
		return StatusBanned
	}
	if ticket == nil {
		return StatusNoTicket
	}
	if CheckTicketClock(*ticket, now, highWater) != nil {
		return StatusTicketExpired
	}
	return StatusServing
}

func sign[T any](ctx context.Context, domain string, body T, signer Signer) (string, string, error) {
	if signer == nil || !keyIDPattern.MatchString(signer.KeyID()) {
		return "", "", ErrInvalidSigner
	}
	payload, err := json.Marshal(signingDocument[T]{Domain: domain, Algorithm: Algorithm, KeyID: signer.KeyID(), Body: body})
	if err != nil {
		return "", "", fmt.Errorf("marshal installation ban signing document: %w", err)
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return "", "", fmt.Errorf("sign installation ban document: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return "", "", ErrInvalidSigner
	}
	return signer.KeyID(), base64.RawURLEncoding.EncodeToString(signature), nil
}

func verifySignature[T any](domain, keyID string, body T, signature string, keys map[string]ed25519.PublicKey) error {
	publicKey, found := keys[keyID]
	if !found || len(publicKey) != ed25519.PublicKeySize {
		return ErrUntrusted
	}
	payload, err := json.Marshal(signingDocument[T]{Domain: domain, Algorithm: Algorithm, KeyID: keyID, Body: body})
	if err != nil || !ed25519.Verify(publicKey, payload, decodeSignature(signature)) {
		return ErrUntrusted
	}
	return nil
}

func checkCommon(installationID string, issuedAt int64, options VerifyOptions) error {
	if options.Now.IsZero() || options.ExpectedInstallationID == "" {
		return ErrInvalidDocument
	}
	if installationID != options.ExpectedInstallationID {
		return ErrInstallationMatch
	}
	if options.Now.UTC().Unix()+int64(MaxClockSkew/time.Second) < issuedAt {
		return ErrNotYetValid
	}
	return nil
}

func encode(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxDocumentBytes {
		return nil, ErrInvalidDocument
	}
	return encoded, nil
}

func decodeCanonical(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > MaxDocumentBytes {
		return ErrInvalidDocument
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.More() {
		return ErrInvalidDocument
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalidDocument
	}
	return nil
}

// Digest is the SHA-256 of wire bytes, used with CheckRevision.
func Digest(encoded []byte) [32]byte { return sha256.Sum256(encoded) }

func decodeSignature(value string) []byte {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil
	}
	return decoded
}

func validUUID(value string) bool {
	return value != "00000000-0000-0000-0000-000000000000" && uuidPattern.MatchString(value)
}

func validRevision(value uint64) bool { return value > 0 && value <= math.MaxInt64 }

func validTimestamp(value int64) bool { return value > 0 && value <= maxUnixTimestamp }

func validReasonText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	count := utf8.RuneCountInString(value)
	return count >= 1 && count <= MaxReasonTextRune && strings.TrimSpace(value) == value
}
