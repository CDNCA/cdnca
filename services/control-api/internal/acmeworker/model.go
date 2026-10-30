package acmeworker

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type ErrorCode string

const (
	CodeInvalidInput                ErrorCode = "acme_invalid_input"
	CodeKeyUnavailable              ErrorCode = "acme_key_unavailable"
	CodeAccountUnavailable          ErrorCode = "acme_account_unavailable"
	CodeDirectoryUnavailable        ErrorCode = "acme_directory_unavailable"
	CodeRateLimited                 ErrorCode = "acme_rate_limited"
	CodeOrderRejected               ErrorCode = "acme_order_rejected"
	CodeOrderUncertain              ErrorCode = "acme_order_outcome_uncertain"
	CodeChallengeUnavailable        ErrorCode = "acme_challenge_unavailable"
	CodeHTTP01NodeAggregateRequired ErrorCode = "acme_http01_node_aggregate_required"
	// CodeHTTP01NodeUnsupported: a target node's agent cannot serve HTTP-01
	// tokens (no ACME_HTTP01_OVERLAY); upgrade the node or use DNS-01.
	CodeHTTP01NodeUnsupported ErrorCode = "acme_http01_node_unsupported"
	// CodeHTTP01NoServingNode: the domain is not a live site of the scope or
	// its line groups have no serving node.
	CodeHTTP01NoServingNode        ErrorCode = "acme_http01_no_serving_node"
	CodeChallengePublishFailed     ErrorCode = "acme_challenge_publish_failed"
	CodeChallengePropagationFailed ErrorCode = "acme_challenge_propagation_failed"
	CodeAuthorizationInvalid       ErrorCode = "acme_authorization_invalid"
	CodeChallengeCleanupFailed     ErrorCode = "acme_challenge_cleanup_failed"
	CodeFinalizeFailed             ErrorCode = "acme_finalize_failed"
	CodeCertificateInvalid         ErrorCode = "acme_certificate_invalid"
	CodeCertificateStoreFailed     ErrorCode = "acme_certificate_store_failed"
	CodeOperationBusy              ErrorCode = "acme_operation_busy"
	CodeOperationConflict          ErrorCode = "acme_operation_conflict"
	CodeLeaseLost                  ErrorCode = "acme_lease_lost"
	CodeOperationStoreFailed       ErrorCode = "acme_operation_store_failed"
	CodeRenewalClaimFailed         ErrorCode = "acme_renewal_claim_failed"
	CodeCancelled                  ErrorCode = "acme_cancelled"
	CodeTimeout                    ErrorCode = "acme_timeout"
	// CodeEABRequired: the CA requires External Account Binding and the
	// installation has no credentials for it (or the CA rejected them).
	CodeEABRequired ErrorCode = "acme_eab_required"
)

// Error exposes only a stable code: Error() never includes the cause. The
// cause is kept unexported (no Unwrap, so errors.Is/As see only the code)
// for FailureDetail, which reports only fields known to carry no secret.
type Error struct {
	Code       ErrorCode
	RetryAfter time.Duration
	Temporary  bool
	// Terminal: the operation is settled failed, so no retry of the same
	// operation can succeed (fix-certstuck).
	Terminal bool
	cause    error
}

// IsTerminal reports whether err settled its operation as failed.
func IsTerminal(err error) bool {
	var target *Error
	return errors.As(err, &target) && target.Terminal
}

func (e *Error) Error() string { return string(e.Code) }

func (e *Error) Is(target error) bool {
	switch target {
	case context.Canceled:
		return e.Code == CodeCancelled
	case context.DeadlineExceeded:
		return e.Code == CodeTimeout
	default:
		other, ok := target.(*Error)
		return ok && other.Code == e.Code
	}
}

func ErrorCodeOf(err error) ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

type ChallengeType string

const (
	ChallengeHTTP01 ChallengeType = "http-01"
	ChallengeDNS01  ChallengeType = "dns-01"
)

type Clock func() time.Time

type Config struct {
	DirectoryURL     string
	HTTPClient       *http.Client
	Clock            Clock
	OrderTimeout     time.Duration
	RequestTimeout   time.Duration
	ChallengeTimeout time.Duration
	// HTTP01PublishTimeout bounds an HTTP-01 Publish, which waits for every
	// target node to confirm the token (zero: ChallengeTimeout).
	HTTP01PublishTimeout time.Duration
	PropagationTimeout   time.Duration
	// PropagationPollInterval paces the authoritative TXT check (zero: 5s).
	PropagationPollInterval     time.Duration
	CleanupTimeout              time.Duration
	RetryBase                   time.Duration
	MaxRetryAfter               time.Duration
	MaxRetries                  int
	MaxConcurrentAuthorizations int
	LeaseDuration               time.Duration
	RetryDelay                  time.Duration
}

func DefaultConfig(directoryURL string) Config {
	return Config{
		DirectoryURL:                directoryURL,
		Clock:                       time.Now,
		OrderTimeout:                5 * time.Minute,
		RequestTimeout:              30 * time.Second,
		ChallengeTimeout:            30 * time.Second,
		PropagationTimeout:          2 * time.Minute,
		CleanupTimeout:              30 * time.Second,
		RetryBase:                   250 * time.Millisecond,
		MaxRetryAfter:               30 * time.Second,
		MaxRetries:                  5,
		MaxConcurrentAuthorizations: 4,
		LeaseDuration:               10 * time.Minute,
		RetryDelay:                  time.Minute,
	}
}

type SignerStore interface {
	Signer(ctx context.Context, keyRef string) (crypto.Signer, error)
}

type AccountRegistration struct {
	URI     string
	Contact []string
}

type AccountStore interface {
	LoadAccount(ctx context.Context, directoryURL, keyRef string) (AccountRegistration, bool, error)
	SaveAccount(ctx context.Context, directoryURL, keyRef string, account AccountRegistration) error
}

// HTTP01Provider publishes exactly one short-lived token response. Publish and
// Delete must both be idempotent for the same token and value.
type HTTP01Provider interface {
	Publish(ctx context.Context, challenge ChallengeIdentity) error
	Delete(ctx context.Context, challenge ChallengeIdentity) error
}

// DNS01Provider manages one TXT value without deleting unrelated values at the
// same owner name. The opaque handle returned by PresentTXT is the only remote
// identity ObserveTXT and DeleteTXT may use.
type DNS01Provider interface {
	PresentTXT(ctx context.Context, challenge ChallengeIdentity) (RemoteTXTHandle, error)
	ObserveTXT(ctx context.Context, challenge ChallengeIdentity) error
	DeleteTXT(ctx context.Context, challenge ChallengeIdentity) error
}

// DNS01RecoveryProvider is an optional exact lookup used only to reconcile an
// uncertain PresentTXT outcome. It must not create, update, or delete records.
type DNS01RecoveryProvider interface {
	RecoverTXT(ctx context.Context, challenge ChallengeIdentity) (RemoteTXTHandle, bool, error)
}

type RemoteTXTHandle struct {
	ProviderRef string
	RecordRef   string
}

type ChallengeIdentity struct {
	TenantID         uuid.UUID
	ScopeID          uuid.UUID
	ProviderID       uuid.UUID
	ZoneID           uuid.UUID
	OperationID      string
	AttemptID        uuid.UUID
	ProviderRef      string
	AuthorizationURL string
	ChallengeURL     string
	ChallengeType    ChallengeType
	Identifier       string
	Wildcard         bool
	RecordName       string
	Token            string
	ExactValue       string
	TXTHandle        RemoteTXTHandle
	// ZeroMatchCleanupClaimed is derived from the latest persisted event. It is
	// not part of the challenge or remote-record identity.
	ZeroMatchCleanupClaimed bool
}

type IssuedCertificate struct {
	RequestDigest       string
	CertificateKeyRef   string
	PublicKeySPKISHA256 string
	LeafDER             []byte
	ChainDER            [][]byte
	CertificatePEM      []byte
	SerialNumber        string
	DNSNames            []string
	NotBefore           time.Time
	NotAfter            time.Time
	CertificateURL      string
	LeafFingerprint     string
}

// CertificateStore must make Save idempotent for the lease operation. A
// production adapter must lock the current ACME operation in the same database
// transaction as the asset write, fence revision/token/active expiry using the
// database clock, and accept replay only for identical request, key, order,
// account, and certificate provenance. Load is checked before ACME activity.
type CertificateStore interface {
	Load(ctx context.Context, tenantID uuid.UUID, operationID string) (IssuedCertificate, bool, error)
	Save(ctx context.Context, lease OperationLease, certificate IssuedCertificate) error
}

type IssueRequest struct {
	TenantID           uuid.UUID
	ScopeID            uuid.UUID
	OperationID        string
	CertificateOrderID uuid.UUID
	ActorUserID        uuid.UUID
	ProviderID         uuid.UUID
	ZoneID             uuid.UUID
	ProviderRef        string
	DirectoryURL       string
	AccountKeyRef      string
	CertificateKeyRef  string
	Contacts           []string
	AcceptTerms        bool
	Domains            []string
	ChallengeType      ChallengeType
}

type AuthorizationProgress struct {
	URL              string
	Identifier       string
	Wildcard         bool
	ChallengeType    ChallengeType
	Status           string
	ErrorCode        ErrorCode
	CleanupErrorCode ErrorCode
}

type IssueResult struct {
	AccountURI     string
	OrderURI       string
	Authorizations []AuthorizationProgress
	Certificate    IssuedCertificate
	Reused         bool
}

type Dependencies struct {
	Signers      SignerStore
	Accounts     AccountStore
	HTTP01       HTTP01Provider
	DNS01        DNS01Provider
	Certificates CertificateStore
	Operations   OperationStore
	// AuthoritativeTXT is optional. When set, DNS-01 waits until every
	// authoritative name server of the zone serves the TXT value before the
	// CA is asked to validate it.
	AuthoritativeTXT AuthoritativeTXTChecker
	// EAB is optional: the External Account Binding a new account on the
	// directory registers with (RFC 8555 §7.3.4; ZeroSSL, Google Trust
	// Services). A directory that requires one and has none fails with
	// CodeEABRequired.
	EAB EABSource
}

// EABSource returns a directory's External Account Binding (key ID and
// HMAC key); found is false when the directory has none.
type EABSource interface {
	ExternalAccountBinding(ctx context.Context, directoryURL string) (keyID string, key []byte, found bool, err error)
}

// AuthoritativeTXTChecker reports whether all authoritative name servers of
// the zone holding name answer value in its TXT RRset.
type AuthoritativeTXTChecker interface {
	TXTVisible(ctx context.Context, name, value string) (bool, error)
}

type OperationPhase string

const (
	PhaseClaimed          OperationPhase = "claimed"
	PhaseOrdered          OperationPhase = "ordered"
	PhaseAuthorizing      OperationPhase = "authorizing"
	PhaseReady            OperationPhase = "ready"
	PhaseFinalizing       OperationPhase = "finalizing"
	PhaseCertificateSaved OperationPhase = "certificate_saved"
	PhaseCompleted        OperationPhase = "completed"
)

type OperationStatus string

const (
	OperationActive    OperationStatus = "active"
	OperationRetryWait OperationStatus = "retry_wait"
	OperationCompleted OperationStatus = "completed"
	OperationFailed    OperationStatus = "failed"
)

type OperationState struct {
	Phase                 OperationPhase
	Status                OperationStatus
	OrderIntentPending    bool
	AccountURI            string
	OrderURL              string
	FinalizeURL           string
	AuthorizationURLs     []string
	CertificateURL        string
	CertificateSPKIDigest string
	LeafFingerprint       string
	FailureCode           ErrorCode
}

type OperationLease struct {
	TenantID    uuid.UUID
	ScopeID     uuid.UUID
	OperationID string
	Token       uuid.UUID
	ExpiresAt   time.Time
	Revision    int64
	Request     IssueRequest
	Digest      string
	State       OperationState
}

type OperationClaimState string

const (
	OperationClaimed  OperationClaimState = "claimed"
	OperationBusy     OperationClaimState = "busy"
	OperationDone     OperationClaimState = "completed"
	OperationTerminal OperationClaimState = "failed"
)

type OperationClaim struct {
	State OperationClaimState
	Lease OperationLease
}

type ChallengeCleanupClaim interface {
	// Complete records the exact provider result in a fresh short transaction.
	Complete(ctx context.Context, now time.Time) error
	// Abort closes the local claim handle; the committed claim remains recoverable.
	Abort(ctx context.Context) error
}

// TerminalChallengeCleanupLease authorizes deletion of one exact persisted
// challenge artifact after its certificate authority became terminal. It does
// not authorize any issuance state transition.
type TerminalChallengeCleanupLease struct {
	Token           uuid.UUID
	Revision        int64
	ExpiresAt       time.Time
	Request         IssueRequest
	RequestDigest   string
	Challenge       ChallengeIdentity
	ChallengeSHA256 [sha256.Size]byte
}

// TerminalChallengeCleanupStore is deliberately separate from OperationStore:
// issuance recovery remains fenced to non-terminal certificate authorities.
type TerminalChallengeCleanupStore interface {
	ClaimTerminalChallengeCleanup(context.Context) (TerminalChallengeCleanupLease, bool, error)
	FenceTerminalChallengeCleanup(context.Context, TerminalChallengeCleanupLease) error
	CompleteTerminalChallengeCleanup(context.Context, TerminalChallengeCleanupLease) error
}

func terminalChallengeCleanupDigest(challenge ChallengeIdentity) [sha256.Size]byte {
	encoded, err := json.Marshal(struct {
		TenantID         uuid.UUID     `json:"tenant_id"`
		ScopeID          uuid.UUID     `json:"scope_id"`
		ProviderID       uuid.UUID     `json:"provider_id"`
		ZoneID           uuid.UUID     `json:"zone_id"`
		OperationID      string        `json:"operation_id"`
		AttemptID        uuid.UUID     `json:"attempt_id"`
		ProviderRef      string        `json:"provider_ref"`
		AuthorizationURL string        `json:"authorization_url"`
		ChallengeURL     string        `json:"challenge_url"`
		ChallengeType    ChallengeType `json:"challenge_type"`
		Identifier       string        `json:"identifier"`
		Wildcard         bool          `json:"wildcard"`
		RecordName       string        `json:"record_name"`
		Token            string        `json:"token"`
		ExactValue       string        `json:"exact_value"`
		TXTProviderRef   string        `json:"txt_provider_ref"`
		TXTRecordRef     string        `json:"txt_record_ref"`
	}{
		TenantID: challenge.TenantID, ScopeID: challenge.ScopeID,
		ProviderID: challenge.ProviderID, ZoneID: challenge.ZoneID,
		OperationID: challenge.OperationID, AttemptID: challenge.AttemptID,
		ProviderRef: challenge.ProviderRef, AuthorizationURL: challenge.AuthorizationURL,
		ChallengeURL: challenge.ChallengeURL, ChallengeType: challenge.ChallengeType,
		Identifier: challenge.Identifier, Wildcard: challenge.Wildcard,
		RecordName: challenge.RecordName, Token: challenge.Token, ExactValue: challenge.ExactValue,
		TXTProviderRef: challenge.TXTHandle.ProviderRef, TXTRecordRef: challenge.TXTHandle.RecordRef,
	})
	if err != nil {
		return [sha256.Size]byte{}
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return digest
}

type OperationStore interface {
	Claim(ctx context.Context, request IssueRequest, digest string, now, leaseUntil time.Time) (OperationClaim, error)
	Advance(ctx context.Context, lease OperationLease, eventType string, next OperationState, now time.Time) (OperationLease, error)
	Release(ctx context.Context, lease OperationLease, code ErrorCode, retry bool, now, retryAt time.Time) error
	PrepareChallenge(ctx context.Context, lease OperationLease, challenge ChallengeIdentity, now time.Time) (ChallengeIdentity, error)
	// MarkChallenge accepts only "published"; cleanup facts are owned by the cleanup claim.
	MarkChallenge(ctx context.Context, lease OperationLease, challenge ChallengeIdentity, state string, now time.Time) error
	ClaimChallengeCleanup(ctx context.Context, lease OperationLease, challenge ChallengeIdentity, now time.Time) (ChallengeCleanupClaim, error)
	OutstandingChallenges(ctx context.Context, lease OperationLease, now time.Time) ([]ChallengeIdentity, error)
	Recoverable(ctx context.Context, now time.Time, limit int) ([]IssueRequest, error)
}

type ClaimState string

const (
	ClaimAcquired  ClaimState = "acquired"
	ClaimBusy      ClaimState = "busy"
	ClaimCompleted ClaimState = "completed"
)

type RenewalClaimRequest struct {
	Key           string
	CertificateID string
	CurrentExpiry time.Time
	ClaimedAt     time.Time
	LeaseUntil    time.Time
}

type RenewalClaim struct {
	State ClaimState
	Token string
}

type RenewalClaimStore interface {
	Claim(ctx context.Context, request RenewalClaimRequest) (RenewalClaim, error)
	Complete(ctx context.Context, key, token, leafFingerprint string) error
	Release(ctx context.Context, key, token string, code ErrorCode) error
}

type CertificateIssuer interface {
	Issue(ctx context.Context, request IssueRequest) (IssueResult, error)
}

type RenewalConfig struct {
	Clock         Clock
	RenewBefore   time.Duration
	LeaseDuration time.Duration
	MaxConcurrent int
}

func DefaultRenewalConfig() RenewalConfig {
	return RenewalConfig{
		Clock:         time.Now,
		RenewBefore:   30 * 24 * time.Hour,
		LeaseDuration: 10 * time.Minute,
		MaxConcurrent: 4,
	}
}

type RenewalCandidate struct {
	CertificateID string
	CurrentExpiry time.Time
	AutoRenew     bool
	IssueRequest  IssueRequest
}

type RenewalResult struct {
	ClaimKey string
	State    ClaimState
	Issue    IssueResult
	Error    error
}

func RenewalClaimKey(certificateID string, currentExpiry time.Time) string {
	digest := sha256.Sum256([]byte(certificateID + "\x00" + currentExpiry.UTC().Format(time.RFC3339Nano)))
	return "acme-renewal:" + hex.EncodeToString(digest[:])
}
