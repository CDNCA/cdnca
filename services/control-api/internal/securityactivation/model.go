package securityactivation

import (
	"crypto/sha256"
	"errors"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput           = errors.New("invalid security activation input")
	ErrPermissionDenied       = errors.New("security activation permission denied")
	ErrNotFound               = errors.New("security activation not found")
	ErrConflict               = errors.New("security activation conflict")
	ErrSiteLocked             = errors.New("security activation site is locked")
	ErrIdempotencyConflict    = errors.New("security activation idempotency conflict")
	ErrNotHealthy             = errors.New("security activation is not healthy")
	ErrSourceRevisionConflict = errors.New("security activation source revision conflict")
	ErrUnavailable            = errors.New("security activation runtime unavailable")
	// ErrPolicyDeleted (sec-rebind): a deleted library cannot be bound again.
	ErrPolicyDeleted = errors.New("security activation policy is deleted")
)

type Config struct {
	ReconcileInterval     time.Duration
	CandidateTTL          time.Duration
	HealthCheck           time.Duration
	ObservationWindow     time.Duration
	RequiredSuccesses     uint32
	MaxAttempts           uint32
	RequiredWAFAPIVersion uint32
	RequiredCCAPIVersion  uint32
}

func DefaultConfig() Config {
	return Config{
		ReconcileInterval: 2 * time.Second, CandidateTTL: 15 * time.Minute,
		HealthCheck: 30 * time.Second, ObservationWindow: 10 * time.Second,
		RequiredSuccesses: 3, MaxAttempts: 3,
		RequiredWAFAPIVersion: 1, RequiredCCAPIVersion: 2,
	}
}

func (config Config) validate() error {
	if config.ReconcileInterval < 100*time.Millisecond || config.ReconcileInterval > time.Minute ||
		config.CandidateTTL < time.Minute || config.CandidateTTL > 24*time.Hour ||
		config.HealthCheck < time.Second || config.HealthCheck > 10*time.Minute ||
		config.ObservationWindow < time.Second || config.ObservationWindow > 10*time.Minute ||
		config.RequiredSuccesses < 1 || config.RequiredSuccesses > 100 ||
		config.MaxAttempts < 1 || config.MaxAttempts > 10 ||
		config.RequiredWAFAPIVersion != 1 || config.RequiredCCAPIVersion != 2 {
		return ErrInvalidInput
	}
	return nil
}

type CandidateStatus string

const (
	StatusClaimed   CandidateStatus = "claimed"
	StatusCanary    CandidateStatus = "canary"
	StatusExpanding CandidateStatus = "expanding"
	StatusHealthy   CandidateStatus = "healthy"
	StatusFailed    CandidateStatus = "failed"
	StatusCancelled CandidateStatus = "cancelled"
	StatusExpired   CandidateStatus = "expired"
	StatusPromoted  CandidateStatus = "promoted"
)

type Candidate struct {
	ID                          uuid.UUID             `json:"id"`
	TenantScopeID               uuid.UUID             `json:"tenant_scope_id"`
	SiteID                      uuid.UUID             `json:"site_id"`
	BindingID                   uuid.UUID             `json:"binding_id"`
	BindingRevision             int64                 `json:"binding_revision"`
	LastBundleID                uuid.UUID             `json:"last_bundle_id"`
	LastClaimedPolicyVersion    int64                 `json:"last_claimed_policy_version"`
	ExpectedActivePolicyVersion int64                 `json:"expected_active_policy_version"`
	CandidateSourceRevision     int64                 `json:"candidate_source_revision"`
	CandidateConfigVersionID    uuid.UUID             `json:"candidate_config_version_id"`
	CandidateArtifactSHA256     [sha256.Size]byte     `json:"candidate_artifact_sha256"`
	TargetSnapshotSHA256        [sha256.Size]byte     `json:"target_snapshot_sha256"`
	RequiredCapabilities        []*agentv1.Capability `json:"required_capabilities"`
	Status                      CandidateStatus       `json:"candidate_status"`
	CanaryNodeIDs               []uuid.UUID           `json:"canary_node_ids"`
	ExpandNodeIDs               []uuid.UUID           `json:"expand_node_ids"`
	ExpiresAt                   time.Time             `json:"expires_at"`
	CreatedAt                   time.Time             `json:"created_at"`
	UpdatedAt                   time.Time             `json:"updated_at"`
	RecoveredAt                 *time.Time            `json:"recovered_at,omitempty"`
}

const (
	OperationActivation = "activation"
	OperationRollback   = "rollback"

	RecoveryOperationCIDRUnlock          = "cidr_unlock"
	RecoveryReasonFalsePositiveConfirmed = "false_positive_confirmed"
	RecoveryResultClaimed                = "recovery_claimed"
	RecoveryResultReplayed               = "recovery_replayed"
)

type CIDRRecoveryIntent struct {
	Operation  string   `json:"operation"`
	ReasonCode string   `json:"reason_code"`
	CIDRs      []string `json:"cidrs"`
}

type Binding struct {
	ID                       uuid.UUID `json:"id"`
	PolicyID                 uuid.UUID `json:"policy_id"`
	BindingRevision          int64     `json:"binding_revision"`
	ActivePolicyVersion      int64     `json:"active_policy_version"`
	LastClaimedPolicyVersion int64     `json:"last_claimed_policy_version"`
}

type StatusResult struct {
	Binding         *Binding   `json:"binding"`
	LatestCandidate *Candidate `json:"latest_candidate"`
	Operation       *string    `json:"operation"`
	// CapabilityWait: an activation refused for node capability that is
	// published automatically once the nodes are upgraded.
	CapabilityWait *CapabilityWait `json:"capability_wait,omitempty"`
	// FailureReasons (P11): the nodes' failure texts when the latest
	// candidate failed (empty otherwise).
	FailureReasons []FailureReason `json:"failure_reasons,omitempty"`
	// LatestDetach: the latest candidate withdraws the kind (sec-rebind).
	LatestDetach bool `json:"latest_detach"`
	// Rollback (sec-rebind): whether the panel can roll the latest
	// candidate back, to what, or why not.
	Rollback *RollbackAvailability `json:"rollback,omitempty"`
}

// Rollback reasons (RollbackAvailability.Reason).
const (
	RollbackReasonNoCandidate   = "no_candidate"
	RollbackReasonInFlight      = "in_flight"
	RollbackReasonNoPrevious    = "no_previous"
	RollbackReasonPolicyDeleted = "previous_policy_deleted"
)

// RollbackAvailability: a promoted candidate can be rolled back to what was
// active before it (another library after a rebind, the withdrawn library
// after a detach, the previous version otherwise). Reason says why not.
// CandidateID/SourcePolicyVersion are RollbackInput's: the promoted
// candidate that last activated that library version.
type RollbackAvailability struct {
	Available           bool       `json:"available"`
	Reason              string     `json:"reason,omitempty"`
	CandidateID         *uuid.UUID `json:"candidate_id,omitempty"`
	PolicyID            *uuid.UUID `json:"policy_id,omitempty"`
	SourcePolicyVersion int64      `json:"source_policy_version,omitempty"`
}

type ClaimInput struct {
	TenantScopeID               uuid.UUID
	SiteID                      uuid.UUID
	BindingID                   uuid.UUID
	BindingRevision             int64
	LastBundleID                uuid.UUID
	LastClaimedPolicyVersion    int64
	ExpectedActivePolicyVersion int64
	CandidateSourceRevision     int64
	CandidateConfigVersionID    uuid.UUID
	CandidateArtifactSHA256     [sha256.Size]byte
	TargetSnapshotSHA256        [sha256.Size]byte
	RequiredCapabilities        []*agentv1.Capability
	CanaryNodeIDs               []uuid.UUID
	ExpandNodeIDs               []uuid.UUID
	IdempotencyKey              string
	RequestID                   string
	CorrelationID               string
	Traceparent                 string
	TaskID                      *string
	ExpiresAt                   time.Time
}

type ClaimResult struct {
	Candidate Candidate `json:"candidate"`
	Replayed  bool      `json:"replayed,omitempty"`
}

type PromoteResult struct {
	Candidate
	Replayed bool `json:"replayed,omitempty"`
}

type PromotionCAS struct {
	TenantScopeID               uuid.UUID         `json:"tenant_scope_id"`
	BindingID                   uuid.UUID         `json:"binding_id"`
	BindingRevision             int64             `json:"binding_revision"`
	LastBundleID                uuid.UUID         `json:"last_bundle_id"`
	LastClaimedPolicyVersion    int64             `json:"last_claimed_policy_version"`
	ExpectedActivePolicyVersion int64             `json:"expected_active_policy_version"`
	CandidateSourceRevision     int64             `json:"candidate_source_revision"`
	CandidateConfigVersionID    uuid.UUID         `json:"candidate_config_version_id"`
	CandidateArtifactSHA256     [sha256.Size]byte `json:"candidate_artifact_sha256"`
	TargetSnapshotSHA256        [sha256.Size]byte `json:"target_snapshot_sha256"`
}

func (candidate Candidate) PromotionCAS() PromotionCAS {
	return PromotionCAS{
		TenantScopeID: candidate.TenantScopeID, BindingID: candidate.BindingID,
		BindingRevision: candidate.BindingRevision, LastBundleID: candidate.LastBundleID,
		LastClaimedPolicyVersion:    candidate.LastClaimedPolicyVersion,
		ExpectedActivePolicyVersion: candidate.ExpectedActivePolicyVersion,
		CandidateSourceRevision:     candidate.CandidateSourceRevision,
		CandidateConfigVersionID:    candidate.CandidateConfigVersionID,
		CandidateArtifactSHA256:     candidate.CandidateArtifactSHA256,
		TargetSnapshotSHA256:        candidate.TargetSnapshotSHA256,
	}
}

func (value PromotionCAS) validate() error {
	if value.TenantScopeID == uuid.Nil || value.BindingID == uuid.Nil || value.BindingRevision < 1 ||
		value.LastBundleID == uuid.Nil || value.LastClaimedPolicyVersion < 1 ||
		value.ExpectedActivePolicyVersion < 0 || value.CandidateSourceRevision < 2 ||
		value.CandidateConfigVersionID == uuid.Nil ||
		value.CandidateArtifactSHA256 == ([sha256.Size]byte{}) ||
		value.TargetSnapshotSHA256 == ([sha256.Size]byte{}) {
		return ErrInvalidInput
	}
	return nil
}

type PhaseIdentity struct {
	CandidateID          uuid.UUID
	RolloutID            uuid.UUID
	Phase                string
	ConfigVersionID      uuid.UUID
	ArtifactSHA256       [sha256.Size]byte
	TargetSnapshotSHA256 [sha256.Size]byte
}

type ReceiptFact struct {
	RolloutID          uuid.UUID
	DeploymentID       uuid.UUID
	Phase              string
	Action             string
	NodeID             uuid.UUID
	Attempt            int64
	TransitionSequence int64
	State              string
	// Superseded: the deployment failed as an ignored old release
	// (edgedeployment.SupersededDeploymentSQL; fix-cfgflow3).
	Superseded      bool
	ConfigVersionID uuid.UUID
	ArtifactSHA256  [sha256.Size]byte
}

type StartInput struct {
	TenantScopeID               uuid.UUID
	SiteID                      uuid.UUID
	PolicyID                    uuid.UUID
	PolicyVersion               int64
	ExpectedBindingRevision     int64
	ExpectedActivePolicyVersion int64
	TargetNodeIDs               []uuid.UUID
	CanarySize                  int
	IdempotencyKey              string
	RequestID                   string
	CorrelationID               string
	Traceparent                 string
	TaskID                      *string
	ExpiresAt                   time.Time
	Recovery                    *CIDRRecoveryIntent
	// Detach (sec-rebind): withdraw the site's active library of the kind;
	// PolicyID/PolicyVersion must be the binding's active ones. Part of the
	// request digest only when set.
	Detach bool
	// SiteRuntimeSchema: the site runtime the candidate is built for
	// (cdnca.edge.site-runtime/v2, the only one). Empty chooses as every
	// other release does (edgepublish.DefaultSiteRuntimeSchema). Part of the
	// request digest only when set.
	SiteRuntimeSchema string
	// resumeWaitID: the capability wait this start resumes (worker only); not
	// part of the request digest.
	resumeWaitID uuid.UUID
}

type StartResult struct {
	Candidate  Candidate `json:"candidate"`
	Replayed   bool      `json:"replayed,omitempty"`
	ReasonCode string    `json:"reason_code,omitempty"`
}

type ReconcileInput struct {
	CandidateID    uuid.UUID
	PromotionCAS   PromotionCAS
	IdempotencyKey string
	RequestID      string
	CorrelationID  string
	Traceparent    string
	TaskID         *string
}

type ReconcileResult struct {
	Candidate Candidate `json:"candidate"`
	Action    string    `json:"action"`
	Replayed  bool      `json:"replayed,omitempty"`
}

type RollbackInput struct {
	CandidateID                 uuid.UUID
	SourcePolicyVersion         int64
	ExpectedBindingRevision     int64
	ExpectedActivePolicyVersion int64
	TargetNodeIDs               []uuid.UUID
	CanarySize                  int
	IdempotencyKey              string
	RequestID                   string
	CorrelationID               string
	Traceparent                 string
	TaskID                      *string
	ExpiresAt                   time.Time
	// SiteRuntimeSchema is StartInput.SiteRuntimeSchema for the restored
	// version (empty: the default). Part of the request digest only when set.
	SiteRuntimeSchema string
}
