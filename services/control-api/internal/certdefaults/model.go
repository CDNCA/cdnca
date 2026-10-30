package certdefaults

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid certificate defaults input")
	ErrPermissionDenied    = errors.New("certificate defaults permission denied")
	ErrNotFound            = errors.New("certificate defaults resource not found")
	ErrRevisionConflict    = errors.New("certificate defaults revision conflict")
	ErrIdempotencyConflict = errors.New("certificate defaults idempotency conflict")
	ErrProviderInvalid     = errors.New("certificate defaults DNS provider is invalid")
	// ErrIssuerUnavailable: the default names a CA that needs platform EAB
	// credentials the platform has not configured (the same rule an order
	// create applies, dnsacme.ErrIssuerUnavailable): refused when saved, not
	// first when an order falls back to it.
	ErrIssuerUnavailable = errors.New("certificate defaults issuer is not available")
)

const (
	CertificateTypeACME     = "acme"
	CertificateTypeUploaded = "uploaded"
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type Defaults struct {
	ScopeID         uuid.UUID  `json:"scope_id"`
	UserID          uuid.UUID  `json:"user_id"`
	CertificateType string     `json:"certificate_type"`
	DNSProviderID   *uuid.UUID `json:"dns_provider_id,omitempty"`
	// Issuer is the user's default CA for new requests; omitted when unset
	// (the platform default applies).
	Issuer    *string    `json:"issuer,omitempty"`
	Revision  int64      `json:"revision"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type Request struct {
	TargetScopeID uuid.UUID
	TargetUserID  uuid.UUID
}

type UpdateRequest struct {
	TargetScopeID    uuid.UUID
	TargetUserID     uuid.UUID
	CertificateType  string
	DNSProviderID    *uuid.UUID
	Issuer           *string
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}
