package dnsacme

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput          = errors.New("invalid dns or certificate input")
	ErrPermissionDenied      = errors.New("dns or certificate permission denied")
	ErrNotFound              = errors.New("dns or certificate resource not found")
	ErrConflict              = errors.New("dns or certificate resource conflict")
	ErrRevisionConflict      = errors.New("dns or certificate revision conflict")
	ErrIdempotencyConflict   = errors.New("dns or certificate idempotency conflict")
	ErrCredentialUnavailable = errors.New("dns credential encryption is unavailable")
	ErrInvalidTransition     = errors.New("invalid certificate order transition")
	// ErrIssuerUnavailable: the order's CA needs EAB credentials the
	// platform has not configured (CERT-04).
	ErrIssuerUnavailable = errors.New("certificate issuer is not available")
	// ErrOrderInFlight: the scope already has a pending/validating/issuing
	// order for the same domain set (refuse the new order so the
	// CA does not hand back the in-flight ACME order).
	ErrOrderInFlight                       = errors.New("a certificate order for these domains is in progress")
	ErrProviderVerificationUnsupported     = errors.New("dns provider verification is unsupported")
	ErrProviderDisabled                    = errors.New("dns provider is disabled")
	ErrProviderCredentialsInvalid          = errors.New("dns provider credentials are invalid")
	ErrProviderTokenInactive               = errors.New("dns provider token is inactive")
	ErrProviderCredentialsRejected         = errors.New("dns provider credentials were rejected")
	ErrProviderVerificationRateLimited     = errors.New("dns provider verification was rate limited")
	ErrProviderVerificationUnavailable     = errors.New("dns provider verification is unavailable")
	ErrProviderVerificationInvalidResponse = errors.New("dns provider returned an invalid verification response")
	ErrProviderVerificationTimeout         = errors.New("dns provider verification timed out")
	// ErrPlatformManagedProvider: the account is the platform DNS copy
	// (dns_providers.managed_by='platform', migration 569). It only serves
	// the CNAME records the platform allocated; a tenant cannot add zones,
	// order DNS-01 certificates, point site domains or edit it with it
	// (DNS-SEC-20261027-01).
	ErrPlatformManagedProvider = errors.New("the DNS account is managed by the platform")
	// ErrProviderReauthorizationRequired: disabling an account revoked its
	// credentials (migration 106); enabling it again needs new credentials
	// (DNS-UX-20261027-02), the revoked ones are never revived.
	ErrProviderReauthorizationRequired = errors.New("dns provider credentials were revoked; enter new credentials to enable it")
)

// ProviderManagedByTenant / ProviderManagedByPlatform are
// dns_providers.managed_by (migration 569).
const (
	ProviderManagedByTenant   = "tenant"
	ProviderManagedByPlatform = "platform"
)

const (
	DefaultProviderPageLimit = 20
	MaxProviderPageLimit     = 100
	MaxProviderCursorLength  = 4096

	ProviderStatusUnverified = "unverified"
	ProviderStatusVerified   = "verified"
	ProviderStatusDisabled   = "disabled"
	ResourceStatusDraft      = "draft"
	ResourceStatusFailed     = "failed"

	OrderPending    = "pending"
	OrderValidating = "validating"
	OrderIssuing    = "issuing"
	OrderIssued     = "issued"
	OrderDeploying  = "deploying"
	OrderActive     = "active"
	OrderRenewalDue = "renewal_due"
	OrderFailed     = "failed"
	OrderRevoked    = "revoked"
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type Provider struct {
	ID                    uuid.UUID `json:"id"`
	ScopeID               uuid.UUID `json:"scope_id"`
	Name                  string    `json:"name"`
	Remark                string    `json:"remark"`
	ProviderType          string    `json:"provider_type"`
	CredentialsConfigured bool      `json:"credentials_configured"`
	Status                string    `json:"status"`
	// ManagedBy: tenant (the account the tenant entered) or platform (the
	// read-only platform DNS copy).
	ManagedBy string    `json:"managed_by"`
	Revision  int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ProviderPageRequest struct {
	Limit  int
	Cursor string
}

type ProviderPage struct {
	Items      []Provider `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type providerPageCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

type Zone struct {
	ID         uuid.UUID `json:"id"`
	ScopeID    uuid.UUID `json:"scope_id"`
	ProviderID uuid.UUID `json:"provider_id"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Revision   int64     `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Record struct {
	ID        uuid.UUID `json:"id"`
	ScopeID   uuid.UUID `json:"scope_id"`
	ZoneID    uuid.UUID `json:"zone_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Content   string    `json:"content"`
	TTL       int       `json:"ttl"`
	Status    string    `json:"status"`
	Revision  int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CertificateOrder struct {
	ID            uuid.UUID  `json:"id"`
	ScopeID       uuid.UUID  `json:"scope_id"`
	DNSProviderID *uuid.UUID `json:"dns_provider_id,omitempty"`
	Domains       []string   `json:"domains"`
	ChallengeType string     `json:"challenge_type"`
	Status        string     `json:"status"`
	AutoRenew     bool       `json:"auto_renew"`
	// Issuer is the frozen CA; omitted for orders created before it was
	// recorded (they use the platform default issuer).
	Issuer           *string    `json:"issuer,omitempty"`
	Name             string     `json:"name"`
	Remark           string     `json:"remark"`
	RenewalOfOrderID *uuid.UUID `json:"renewal_of_order_id,omitempty"`
	NotAfter         *time.Time `json:"not_after,omitempty"`
	FailureCode      *string    `json:"failure_code,omitempty"`
	// FailureReason is the CA's redacted explanation (acmeworker.PublicReason,
	// at most 512 characters) beside FailureCode; absent when the CA gave none.
	FailureReason *string `json:"failure_reason,omitempty"`
	// RetryErrorCode is why the issuance is retrying (dns_acme_outbox), set
	// only while the order is still in progress (FX10). ListOrders only.
	RetryErrorCode         *string    `json:"retry_error_code,omitempty"`
	RetryErrorReason       *string    `json:"retry_error_reason,omitempty"`
	IssuedAssetID          *uuid.UUID `json:"issued_asset_id,omitempty"`
	IssuedVersionID        *uuid.UUID `json:"issued_version_id,omitempty"`
	IssuedAt               *time.Time `json:"issued_at,omitempty"`
	LeafFingerprint        []byte     `json:"-"`
	LeafSPKIDigest         []byte     `json:"-"`
	Revision               int64      `json:"version"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	acmeDirectoryURL       *string
	acmeAccountKeyRef      *string
	certificateKeyRef      *string
	externalOrderURL       *string
	authorizationURLDigest []byte
	certificateURL         *string
}

type CreateProviderRequest struct {
	TargetScopeID  uuid.UUID
	Name           string
	Remark         string
	ProviderType   string
	Credentials    map[string]string
	IdempotencyKey string
	RequestID      string
}

type UpdateProviderRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Name             string
	// Remark nil keeps the stored remark (clients from before migration 490).
	Remark         *string
	Status         string
	Credentials    map[string]string
	IdempotencyKey string
	RequestID      string
}

type VerifyProviderRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type CreateZoneRequest struct {
	TargetScopeID uuid.UUID
	ProviderID    uuid.UUID
	Name          string
	// ProviderZoneApex is set by the service from the provider's domain list.
	ProviderZoneApex string
	IdempotencyKey   string
	RequestID        string
}

type CreateRecordRequest struct {
	TargetScopeID  uuid.UUID
	ZoneID         uuid.UUID
	Name           string
	Type           string
	Content        string
	TTL            int
	IdempotencyKey string
	RequestID      string
}

type UpdateRecordRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Name             string
	Type             string
	Content          string
	TTL              int
	IdempotencyKey   string
	RequestID        string
}

type DeleteRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type CreateOrderRequest struct {
	TargetScopeID uuid.UUID
	DNSProviderID *uuid.UUID
	Domains       []string
	ChallengeType string
	AutoRenew     bool
	// Issuer is the CA (CertificateIssuers); "" uses the target user's
	// default issuer, then the platform's (CERT-04). The resolved issuer is
	// frozen on the order and its renewals.
	Issuer string
	// Name and Remark label the order and the certificate it issues.
	Name           string
	Remark         string
	IdempotencyKey string
	RequestID      string
}

// CertificateIssuers are the CAs an order may name (systemconfig
// CertificateIssuers).
var CertificateIssuers = []string{"lets_encrypt", "zerossl", "google_trust"}

type TransitionOrderRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	From             string
	To               string
	// Deprecated: the fail-closed legacy transition endpoint ignores this field.
	NotAfter       *time.Time
	FailureCode    string
	IdempotencyKey string
	RequestID      string
}

type CreateRenewalRequest struct {
	OrderID        uuid.UUID
	IdempotencyKey string
	RequestID      string
}
