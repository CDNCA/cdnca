package entitlementguard

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	FeatureSitesManage       = "sites.manage"
	QuotaDomainsCount        = "domains.count"
	FeatureNodesManage       = "nodes.manage"
	QuotaNodesCount          = "nodes.count"
	FeatureCertificatesIssue = "certificates.issue"

	FeatureExtensionsWebhooks    = entitlement.FeatureExtensionsWebhooks
	QuotaExtensionsWebhooksCount = entitlement.QuotaExtensionsWebhooksCount

	StatusUninstalled = "uninstalled"
	StatusInvalid     = "invalid"
)

var (
	ErrInvalidBundle        = errors.New("invalid entitlement install bundle")
	ErrInvalidTrustStore    = errors.New("invalid entitlement trust store")
	ErrTrustUnavailable     = errors.New("entitlement trust anchors unavailable")
	ErrUntrustedRevocations = errors.New("unsigned entitlement revocations are not accepted")
	ErrStaleLease           = errors.New("stale entitlement lease")
	ErrLeaseConflict        = errors.New("entitlement lease serial conflict")
	// ErrInstallOutcomeUnknown: COMMIT was sent but its answer was lost, so
	// the lease may be installed; re-read the current serial (LIC-REC-03).
	ErrInstallOutcomeUnknown = errors.New("entitlement install outcome unknown")
	ErrKeyConflict           = errors.New("entitlement verification key conflict")
	ErrKeyOutsideWindow      = errors.New("entitlement verification key is outside its trusted window")
	ErrUnavailable           = errors.New("local entitlement unavailable")
	ErrInvalid               = errors.New("local entitlement invalid")
	ErrStateDenied           = errors.New("entitlement state denied")
	ErrFeatureDenied         = errors.New("entitlement feature denied")
	ErrQuotaDenied           = errors.New("entitlement quota missing")
	ErrQuotaExceeded         = errors.New("entitlement quota exceeded")
)

type VerificationKey struct {
	KeyID       string
	PublicKey   ed25519.PublicKey
	NotBefore   time.Time
	SignUntil   *time.Time
	VerifyUntil *time.Time
}

type InstallBundle struct {
	InstallationID string
	RevokedSerials []uint64
	SignedLease    entitlement.SignedLease
}

type Snapshot struct {
	InstallationID string
	Serial         uint64
	KeyID          string
	Status         entitlement.Status
	VerifiedAt     time.Time
}

type SiteCheck struct {
	AuditScopeID   uuid.UUID
	ActorUserID    uuid.UUID
	ResourceID     uuid.UUID
	RequestID      string
	Operation      string
	Delta          int64
	ExpansionDelta int64
}

type NodeCheck struct {
	AuditScopeID uuid.UUID
	ActorUserID  uuid.UUID
	ResourceID   uuid.UUID
	RequestID    string
	Operation    string
}

type FeatureCheck struct {
	TargetScopeID uuid.UUID
	ActorScopeID  uuid.UUID
	ActorUserID   uuid.UUID
	ResourceType  string
	ResourceID    uuid.UUID
	RequestID     string
	Operation     string
	Feature       string
	Quota         string
	Count         func(context.Context, pgx.Tx) (int64, error)
}

// BuiltInNodeMonitoringCheck carries audit context, never a caller-selected
// feature or quota. Node monitoring still requires a valid signed license.
type BuiltInNodeMonitoringCheck struct {
	TargetScopeID uuid.UUID
	ActorScopeID  uuid.UUID
	ActorUserID   uuid.UUID
	ResourceType  string
	ResourceID    uuid.UUID
	RequestID     string
	Operation     string
}

type FeatureDecision struct {
	TargetScopeID       uuid.UUID
	ActorScopeID        uuid.UUID
	ActorUserID         uuid.UUID
	ResourceType        string
	ResourceID          uuid.UUID
	RequestID           string
	Operation           string
	Feature             string
	Quota               string
	LeaseSerial         uint64
	LeaseSHA256         [32]byte
	RevocationRevision  uint64
	RevocationSHA256    [32]byte
	RevocationKeyID     string
	RevocationIssuedAt  time.Time
	RevocationExpiresAt time.Time
	EvaluatedAt         time.Time
	NotBefore           time.Time
	ExpiresAt           time.Time
	GraceUntil          time.Time
	Current             int64
	Limit               int64
}

type VersionGrant struct {
	Serial     uint64
	Channel    string
	MinVersion string
	MaxVersion string
}

func (grant VersionGrant) AllowsVersion(channel, version string) bool {
	lease := entitlement.Lease{Version: entitlement.VersionRange{
		Channel: grant.Channel,
		Min:     grant.MinVersion,
		Max:     grant.MaxVersion,
	}}
	return lease.AllowsVersion(channel, version)
}

func IsDenial(err error) bool {
	return errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrStateDenied) ||
		errors.Is(err, ErrFeatureDenied) || errors.Is(err, ErrQuotaDenied) ||
		errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrRevocationUnavailable) ||
		errors.Is(err, ErrRevocationInvalid) || errors.Is(err, ErrRevocationExpired)
}
