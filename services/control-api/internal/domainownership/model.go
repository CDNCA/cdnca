// Package domainownership implements v6.1.0 #12: a tenant proves it controls
// an apex (eTLD+1) by a DNS TXT record or an HTTP file, the proof then stays
// valid until a platform administrator revokes it (no recheck, user decision
// 10-17), and a verified owner may claim a domain another tenant still
// serves, which disables that tenant's conflicting site until the domain is
// removed from it or a platform administrator releases the suspension.
package domainownership

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid domain ownership input")
	ErrNotFound            = errors.New("domain ownership not found")
	ErrPermissionDenied    = errors.New("domain ownership permission denied")
	ErrPolicyOff           = errors.New("domain ownership verification is turned off")
	ErrVerifiedByOther     = domaintrust.ErrDomainVerifiedByOther
	ErrNotVerified         = errors.New("domain apex is not verified by this account")
	ErrClaimRequiresTXT    = errors.New("claiming requires DNS TXT verification")
	ErrNoConflict          = errors.New("no claimable conflicting domain")
	ErrStillClaimed        = errors.New("domain is still held by the claimant")
	ErrRevisionConflict    = errors.New("domain ownership changed concurrently")
	ErrIdempotencyConflict = errors.New("domain ownership idempotency key reused with different input")
	ErrBlocked             = domaintrust.ErrDomainBlocked
	ErrUnavailable         = errors.New("domain ownership service unavailable")
)

const (
	MethodDNSTXT   = "dns_txt"
	MethodHTTPFile = "http_file"

	StatusPending  = "pending"
	StatusVerified = "verified"
	StatusExpired  = "expired"
	StatusRevoked  = "revoked"

	PermissionManage   = "domains.security.manage"
	TXTLabel           = "_cdnca-verify"
	HTTPPathPrefix     = "/.well-known/cdnca-verify/"
	maxClaimDomains    = 100
	maxListLimit       = 200
	operationClaim     = "domain_ownership.claim"
	failureSuperseded  = "superseded_by_dns_txt"
	templateSuspended  = "domain.claim.suspended.zh-cn"
	eventSuspended     = "domain.claim.suspended"
	verificationBudget = 20 * time.Second
)

type Actor struct {
	UserID, ScopeID uuid.UUID
	ScopeKind       string
}

type Ownership struct {
	ID              uuid.UUID  `json:"id"`
	ScopeID         uuid.UUID  `json:"scope_id"`
	Apex            string     `json:"apex"`
	Method          string     `json:"method"`
	Status          string     `json:"status"`
	Token           string     `json:"token,omitempty"`
	TXTName         string     `json:"txt_name,omitempty"`
	HTTPURL         string     `json:"http_url,omitempty"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	LastCheckedAt   *time.Time `json:"last_checked_at,omitempty"`
	LastFailureCode string     `json:"last_failure_code"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	Revision        int64      `json:"revision"`
}

// Conflict is a domain under the caller's verified apex that another account
// still serves. Other accounts' identities are not disclosed.
type Conflict struct {
	Domain    string `json:"domain"`
	SiteCount int    `json:"site_count"`
	Claimable bool   `json:"claimable"`
}

type ClaimRequest struct {
	Apex                      string
	Domains                   []string
	IdempotencyKey, RequestID string
}

type ClaimResult struct {
	Apex              string   `json:"apex"`
	Domains           []string `json:"domains"`
	SuspendedSites    int      `json:"suspended_sites"`
	NotificationsSent int      `json:"notifications_sent"`
	NotificationsLost int      `json:"notifications_failed"`
	Replayed          bool     `json:"-"`
}

type Suspension struct {
	ID              uuid.UUID  `json:"id"`
	ScopeID         uuid.UUID  `json:"scope_id"`
	SiteID          uuid.UUID  `json:"site_id"`
	Domain          string     `json:"domain"`
	ClaimantScopeID *uuid.UUID `json:"claimant_scope_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	ReleasedAt      *time.Time `json:"released_at,omitempty"`
	ReleaseReason   string     `json:"release_reason,omitempty"`
}

// Verifier proves control of an apex. A false result carries a stable failure
// code; an error means the check could not run (counted as a failure too).
type Verifier interface {
	VerifyTXT(ctx context.Context, name, token string) (bool, string, error)
	VerifyHTTP(ctx context.Context, apex, token string) (bool, string, error)
}

// Notifier is notification.Store; nil disables notifications.
type Notifier interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

type Auditor interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

func txtName(apex string) string { return TXTLabel + "." + apex }
func httpURL(apex, token string) string {
	return "http://" + apex + HTTPPathPrefix + token
}

func withChallenge(item Ownership) Ownership {
	item.TXTName = txtName(item.Apex)
	item.HTTPURL = httpURL(item.Apex, item.Token)
	return item
}
