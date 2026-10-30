package edgedeployment

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var (
	ErrInvalidInput               = errors.New("invalid edge deployment input")
	ErrConfigNotFound             = errors.New("edge config version not found")
	ErrConfigNotReleasable        = errors.New("edge config version is not releasable")
	ErrIdempotencyConflict        = errors.New("edge deployment idempotency conflict")
	ErrSigningKeyConflict         = errors.New("artifact signing key conflicts with persisted key")
	ErrNodeNotFound               = errors.New("edge deployment node not found")
	ErrConfigurationScopeConflict = errors.New("node configuration scope conflict")
	ErrNodeDeploymentActive       = errors.New("node already has an active deployment")
	ErrRollbackStateConflict      = errors.New("node rollback state does not match requested target")
	ErrNodeReconciliationRequired = errors.New("node configuration reconciliation is required")
	ErrReconciliationNotRequired  = errors.New("node configuration reconciliation is not required")
	ErrReconciliationSource       = errors.New("node configuration reconciliation source conflict")
	ErrPermissionDenied           = errors.New("edge deployment permission denied")
	ErrUnauthenticated            = errors.New("edge deployment authentication required")
	ErrNotFound                   = errors.New("edge deployment not found")
	ErrInvalidTransition          = errors.New("invalid edge rollout transition")
	ErrRevisionConflict           = errors.New("edge rollout revision conflict")
	ErrRetriesExhausted           = errors.New("edge rollout retries exhausted")
	ErrDeadlineExpired            = errors.New("edge rollout deadline expired")
	ErrUnavailable                = errors.New("edge deployment unavailable")
)

const (
	ScopeKindPlatform         = "platform"
	ScopeKindTenant           = "tenant"
	PermissionRead            = "edge_publications.read"
	PermissionManage          = "edge_publications.manage"
	RolloutStateQueued        = "queued"
	RolloutStateRunning       = "running"
	RolloutStatePaused        = "paused"
	RolloutStateSucceeded     = "succeeded"
	RolloutStatePartialFailed = "partial_failed"
	RolloutStateFailed        = "failed"
	RolloutStateCancelled     = "cancelled"
)

const RolloutStrategyCanary = "canary"

type RolloutPolicy struct {
	Strategy         string
	CanarySize       uint32
	BatchSize        uint32
	FailureThreshold uint32
	AutoStart        bool
	CohortCount      int
}

type ReconciliationResolution string

const (
	ReconciliationAgentObserved     ReconciliationResolution = "agent_observed"
	ReconciliationOperatorConfirmed ReconciliationResolution = "operator_confirmed"
)

type ArtifactInput struct {
	ID           uuid.UUID
	Kind         agentv1.ArtifactKind
	WireBytes    []byte
	SizeBytes    uint64
	SHA256       []byte
	Signature    []byte
	SigningKeyID string
	// SigningPublicKey is trusted control-plane signer material. HTTP and site
	// payloads must never populate or expose it.
	SigningPublicKey    ed25519.PublicKey
	SignatureAlgorithm  agentv1.ArtifactSignatureAlgorithm
	Compression         agentv1.ArtifactCompression
	MediaType           string
	EncryptionAlgorithm agentv1.ArtifactEncryptionAlgorithm
	RecipientKeyID      *string
}

type PersistConfigRequest struct {
	ConfigurationScopeID uuid.UUID
	CanonicalSnapshot    []byte
	GeneratorName        string
	GeneratorVersion     string
	Artifacts            []ArtifactInput
	IdempotencyKey       string
}

type ConfigVersion struct {
	ID                      uuid.UUID
	ConfigurationScopeID    uuid.UUID
	CanonicalSnapshotSHA256 [32]byte
	GeneratorName           string
	GeneratorVersion        string
	Artifacts               []*agentv1.ArtifactDescriptor
	CreatedAt               time.Time
	PublishedAt             time.Time
}

type PersistConfigResult struct {
	ConfigVersion ConfigVersion
	Replayed      bool
}

type HealthCheckPolicy struct {
	ActivationTimeout            time.Duration
	ObservationWindow            time.Duration
	RequiredConsecutiveSuccesses uint32
}

type NodeArtifactBinding struct {
	NodeID          uuid.UUID
	DeploymentID    uuid.UUID
	EventID         uuid.UUID
	Attempt         uint32
	ConfigVersionID uuid.UUID
	ArtifactID      uuid.UUID
	RecipientKeyID  string
}

type CreateRolloutRequest struct {
	ConfigurationScopeID uuid.UUID
	ConfigVersionID      uuid.UUID
	Action               agentv1.DeploymentAction
	NodeIDs              []uuid.UUID
	NodeArtifactBindings []NodeArtifactBinding
	RequiredCapabilities []*agentv1.Capability
	HealthCheck          HealthCheckPolicy
	Deadline             time.Time
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	Traceparent          string
	TaskID               *string
	MaxAttempts          uint32
	ContractVersion      int16
	Rollout              RolloutPolicy
}

type Deployment struct {
	ID           uuid.UUID
	NodeID       uuid.UUID
	Subject      string
	CommandBytes []byte
	Command      *agentv1.DeploymentCommand
}

type Rollout struct {
	ID                   uuid.UUID
	ConfigurationScopeID uuid.UUID
	ConfigVersionID      uuid.UUID
	Action               agentv1.DeploymentAction
	Deployments          []Deployment
	CreatedAt            time.Time
	QueuedAt             time.Time
	Revision             int64
	MaxAttempts          uint32
	Policy               RolloutPolicy
}

type CreateRolloutResult struct {
	Rollout  Rollout
	Replayed bool
}

type actorCredential struct {
	raw string
}

type Actor struct {
	UserID     uuid.UUID
	ScopeID    uuid.UUID
	ScopeKind  string
	SessionID  uuid.UUID
	credential *actorCredential
}

const redactedActor = "edgedeployment.Actor{session:redacted}"

func NewSessionActor(userID, scopeID uuid.UUID, scopeKind string, sessionID uuid.UUID, rawToken string) (Actor, error) {
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: scopeKind, SessionID: sessionID}
	if !validActor(actor) || rawToken == "" || len(rawToken) > 8192 ||
		strings.TrimSpace(rawToken) != rawToken || strings.ContainsAny(rawToken, " \t\r\n") {
		return Actor{}, ErrInvalidInput
	}
	actor.credential = &actorCredential{raw: rawToken}
	return actor, nil
}

func (actor Actor) rawSession() string {
	if actor.credential == nil {
		return ""
	}
	return actor.credential.raw
}

func (Actor) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(redactedActor)) }
func (Actor) String() string                 { return redactedActor }
func (Actor) GoString() string               { return redactedActor }

func (Actor) MarshalJSON() ([]byte, error) {
	return []byte(`"edgedeployment.Actor{session:redacted}"`), nil
}

type RolloutProgress struct {
	Total     int
	Pending   int
	Running   int
	Succeeded int
	Failed    int
	Cancelled int
	// Superseded: nodes that ignored this old release because they already
	// run a newer one (or it was rolled back); not a failure (fix-cfgflow2).
	Superseded int
	// Frozen: nodes that refused this release while frozen (expired service
	// ticket); waiting for redelivery, not a failure (fix-stoppolicy2).
	Frozen int
}

type DeploymentSnapshot struct {
	ID          uuid.UUID
	NodeID      uuid.UUID
	Attempt     uint32
	MaxAttempts uint32
	State       string
	ErrorCode   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	CanRetry    bool
	Cohort      int
	Released    bool
	// Superseded: the node ignored this old release (DeploymentSuperseded).
	Superseded bool
	// Frozen: the node refused it while frozen; redelivered once it unfreezes.
	Frozen bool
	// Warnings are the faults the node reported with a successful terminal
	// status (DeploymentWarnings): the release runs, something beside it
	// did not work.
	Warnings []string
}

// Deployment warnings.
const (
	// WarningPostActivationMaintenance: the release was activated, the
	// node's bookkeeping afterwards (state save, retention) failed (PJ-E02).
	WarningPostActivationMaintenance = "post_activation_maintenance_failed"
	// WarningDDoSProtection: the node DDoS protection table failed to apply
	// or the node cannot run one (PJ-E03/E04).
	WarningDDoSProtection = "ddos_protection_fault"
)

// Protocol error codes of an APPLY the node refused before activation, its
// running configuration unchanged: it already runs a newer revision
// (STALE_ATTEMPT) or this release was rolled back (REVOKED).
const (
	ErrorCodeStaleAttempt = "ERROR_CODE_STALE_ATTEMPT"
	ErrorCodeRevoked      = "ERROR_CODE_REVOKED"
)

// DeploymentSuperseded reports a deployment the node ignored as an old
// release (fix-cfgflow2 §1): failed before activation, running configuration
// unchanged, with a stale or rolled-back code. It does not count as a failure
// for the rollout, its failure threshold, retries or automatic publication.
// The same rule is in SQL as SupersededDeploymentSQL.
func DeploymentSuperseded(state, errorCode string, runningConfigUnchanged bool) bool {
	return state == "failed" && runningConfigUnchanged &&
		(errorCode == ErrorCodeStaleAttempt || errorCode == ErrorCodeRevoked)
}

// SupersededDeploymentSQL is DeploymentSuperseded over the row aliased
// `deployment` (node_deployments): its terminal status event carries the code
// (migration 564); the status validator requires running_config_unchanged on
// every failed status after delivery, so the code decides.
//
// A frozen node's refusal (migration 608 node_deployment_frozen_refusals,
// fix-stoppolicy2) is not a failure either: it counts for no failure
// threshold, retry or automatic outcome, waiting for (or after) redelivery.
const SupersededDeploymentSQL = `(deployment.state='failed' AND (EXISTS (
	SELECT 1 FROM deployment_status_events superseding
	WHERE superseding.deployment_id=deployment.id AND superseding.attempt=deployment.attempt
	  AND superseding.state='failed' AND superseding.error_code IN ('ERROR_CODE_STALE_ATTEMPT','ERROR_CODE_REVOKED'))
	OR EXISTS (SELECT 1 FROM node_deployment_frozen_refusals frozen_refusal
	WHERE frozen_refusal.deployment_id=deployment.id AND frozen_refusal.attempt=deployment.attempt)))`

// InstallationFrozenReason prefixes the message of an APPLY a frozen node
// refused (agent gatewayclient.InstallationFrozenReason:
// an expired service ticket keeps existing sites serving, nothing new lands).
const InstallationFrozenReason = "installation_frozen"

// FrozenRefusal reports a frozen node's refusal of an APPLY before
// activation: failed, running configuration unchanged, a precondition error
// whose message starts with installation_frozen.
func FrozenRefusal(action string, status *agentv1.DeploymentStatus) bool {
	return action == "apply" && status.GetState() == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED &&
		status.GetRunningConfigUnchanged() && status.GetError().GetCode().String() == "ERROR_CODE_FAILED_PRECONDITION" &&
		strings.HasPrefix(status.GetError().GetMessage(), InstallationFrozenReason)
}

// Frozen refusal marks of a deployment, as FrozenMarkSQL reads them.
const (
	FrozenMarkNone        = ""
	FrozenMarkPending     = "pending"     // 冻结中待补发: waiting for the node to unfreeze
	FrozenMarkRedelivered = "redelivered" // the scope was republished to the node after it unfroze
)

// FrozenMarkSQL is the FrozenMark* of the deployment row aliased `latest`.
const FrozenMarkSQL = `COALESCE((SELECT CASE WHEN mark.redelivered_at IS NULL THEN 'pending' ELSE 'redelivered' END
	FROM node_deployment_frozen_refusals mark WHERE mark.deployment_id=latest.id AND mark.attempt=latest.attempt),'')`

// ApplyFrozenMark folds a deployment's frozen mark into its snapshot: pending
// is Frozen, redelivered reads as Superseded; neither is a failure or can be
// retried by hand (the redelivery is the system's).
func ApplyFrozenMark(item *DeploymentSnapshot, mark string) {
	if item.State != "failed" || mark == FrozenMarkNone {
		return
	}
	item.Frozen = mark == FrozenMarkPending
	item.Superseded = mark == FrozenMarkRedelivered
	item.CanRetry = false
}

// DeploymentStatusError is the protocol error code and running-config flag of
// a deployment status payload ("" without an error or for an undecodable one).
func DeploymentStatusError(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	status := new(agentv1.DeploymentStatus)
	if err := proto.Unmarshal(payload, status); err != nil || status.Error == nil {
		return "", false
	}
	return status.Error.Code.String(), status.RunningConfigUnchanged
}

// deploymentWarningChecks maps the failed agent checks to warnings.
var deploymentWarningChecks = map[string]string{
	"edge_post_activation_maintenance": WarningPostActivationMaintenance,
	"edge_ddos_protection":             WarningDDoSProtection,
}

// DeploymentWarnings are the warnings of a deployment status payload (a
// DeploymentStatus), sorted; none for an undecodable payload.
func DeploymentWarnings(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	status := new(agentv1.DeploymentStatus)
	if err := proto.Unmarshal(payload, status); err != nil {
		return nil
	}
	var warnings []string
	for _, check := range status.Checks {
		if warning, ok := deploymentWarningChecks[check.GetName()]; ok && !check.GetSucceeded() && !slices.Contains(warnings, warning) {
			warnings = append(warnings, warning)
		}
	}
	slices.Sort(warnings)
	return warnings
}

type RolloutSnapshot struct {
	ID                   uuid.UUID
	ConfigurationScopeID uuid.UUID
	ConfigVersionID      uuid.UUID
	Action               string
	State                string
	Revision             int64
	MaxAttempts          uint32
	Progress             RolloutProgress
	CanCancel            bool
	CanRetry             bool
	CanStart             bool
	CanPause             bool
	CanResume            bool
	Policy               RolloutPolicy
	ReleasedCohort       int
	PauseReason          string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type DeploymentPageRequest struct {
	Limit  int
	Cursor string
}

type RolloutPageRequest struct {
	Limit  int
	Cursor string
}

type RolloutPage struct {
	Items      []RolloutSnapshot
	NextCursor string
}

type DeploymentPage struct {
	Items      []DeploymentSnapshot
	NextCursor string
}

type RolloutCommandRequest struct {
	Actor                Actor
	ConfigurationScopeID uuid.UUID
	RolloutID            uuid.UUID
	ExpectedRevision     int64
	IdempotencyKey       string
	RequestID            string
	CorrelationID        string
	Traceparent          string
	TaskID               *string
}

type RolloutCommandResult struct {
	Rollout  RolloutSnapshot
	Replayed bool
}

type ReconcileNodeConfigRequest struct {
	RequestID               uuid.UUID
	NodeID                  uuid.UUID
	ConfigurationScopeID    uuid.UUID
	SourceDeploymentID      uuid.UUID
	SourceDeploymentAttempt int32
	ObservedConfigVersionID *uuid.UUID
	Resolution              ReconciliationResolution
	Evidence                string
}

type NodeConfigReconciliation struct {
	ID                      uuid.UUID
	RequestID               uuid.UUID
	NodeID                  uuid.UUID
	ConfigurationScopeID    uuid.UUID
	SourceDeploymentID      uuid.UUID
	SourceDeploymentAttempt int32
	PreviousConfigVersionID *uuid.UUID
	ObservedConfigVersionID *uuid.UUID
	Resolution              ReconciliationResolution
	ReconciledAt            time.Time
}

type ReconcileNodeConfigResult struct {
	Reconciliation NodeConfigReconciliation
	Replayed       bool
}
