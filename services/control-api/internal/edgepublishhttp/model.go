package edgepublishhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var (
	ErrInvalidRequest        = errors.New("invalid site publication HTTP request")
	ErrUnauthenticated       = errors.New("site publication authentication required")
	ErrPermissionDenied      = errors.New("site publication HTTP permission denied")
	ErrInvalidResponse       = errors.New("invalid site publication domain response")
	ErrInvalidRuntimeConfig  = errors.New("invalid site publication runtime configuration")
	ErrUnsafeRolloutCommands = errors.New("site rollout commands require transactional IAM authorization")
)

const (
	AudiencePlatform  = "platform"
	AudienceTenant    = "tenant"
	TargetNodes       = "nodes"
	TargetLineGroup   = "line_group_snapshot"
	credentialSession = "session"
	credentialAPIKey  = "api_key"
)

type AuthenticateFunc func(*http.Request) (identity.Principal, error)

type authenticatedSessionCredential struct {
	raw string
}

type AuthenticatedSession struct {
	Principal  identity.Principal
	SessionID  uuid.UUID
	credential *authenticatedSessionCredential
	kind       string
}

const redactedAuthenticatedSession = "edgepublishhttp.AuthenticatedSession{token:redacted}"

func newAuthenticatedSession(principal identity.Principal, sessionID uuid.UUID, rawToken string) (AuthenticatedSession, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil || sessionID == uuid.Nil || rawToken == "" ||
		len(rawToken) > 8192 || strings.ContainsAny(rawToken, " \t\r\n") {
		return AuthenticatedSession{}, ErrUnauthenticated
	}
	return AuthenticatedSession{
		Principal: principal, SessionID: sessionID,
		credential: &authenticatedSessionCredential{raw: rawToken}, kind: credentialSession,
	}, nil
}

func newAuthenticatedAPIKey(principal identity.Principal, rawToken string) (AuthenticatedSession, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil || principal.ScopeKind != AudienceTenant ||
		principal.TenantID == nil || *principal.TenantID == uuid.Nil || rawToken == "" ||
		len(rawToken) > 8192 || strings.ContainsAny(rawToken, " \t\r\n") {
		return AuthenticatedSession{}, ErrUnauthenticated
	}
	return AuthenticatedSession{
		Principal: principal, credential: &authenticatedSessionCredential{raw: rawToken}, kind: credentialAPIKey,
	}, nil
}

func (session AuthenticatedSession) rawToken() string {
	if session.credential == nil {
		return ""
	}
	return session.credential.raw
}

func (AuthenticatedSession) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedAuthenticatedSession))
}
func (AuthenticatedSession) String() string   { return redactedAuthenticatedSession }
func (AuthenticatedSession) GoString() string { return redactedAuthenticatedSession }

func (AuthenticatedSession) MarshalJSON() ([]byte, error) {
	return []byte(`"edgepublishhttp.AuthenticatedSession{token:redacted}"`), nil
}

type AuthenticateSessionFunc func(*http.Request) (AuthenticatedSession, error)

type PublicationDomain interface {
	Publish(context.Context, edgepublish.PublishRequest) (edgepublish.PublishResult, error)
	Rollback(context.Context, edgepublish.RollbackRequest) (edgepublish.RollbackResult, error)
	GetPublication(context.Context, edgepublish.Actor, uuid.UUID, uuid.UUID) (edgepublish.PublishResult, error)
	ListPublications(context.Context, edgepublish.Actor, uuid.UUID, edgepublish.PublicationPageRequest) (edgepublish.PublicationPage, error)
}

type RolloutDomain interface {
	GetRollout(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID) (edgedeployment.RolloutSnapshot, error)
	ListRollouts(context.Context, edgedeployment.Actor, uuid.UUID, edgedeployment.RolloutPageRequest) (edgedeployment.RolloutPage, error)
	ListDeployments(context.Context, edgedeployment.Actor, uuid.UUID, uuid.UUID, edgedeployment.DeploymentPageRequest) (edgedeployment.DeploymentPage, error)
}

type RolloutCommandDomain interface {
	StartRollout(context.Context, edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error)
	PauseRollout(context.Context, edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error)
	ResumeRollout(context.Context, edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error)
	CancelRollout(context.Context, edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error)
	RetryRollout(context.Context, edgedeployment.RolloutCommandRequest) (edgedeployment.RolloutCommandResult, error)
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
	CorrelationID  string
	Traceparent    string
	TaskID         *string
}

type PublishInput struct {
	ConfigurationScopeID   uuid.UUID
	ExpectedSourceRevision int64
	TargetKind             string
	NodeIDs                []uuid.UUID
	TargetSnapshot         *edgepublish.TargetSnapshotReference
	HealthCheck            edgedeployment.HealthCheckPolicy
	MaxAttempts            uint32
	Deadline               time.Time
	Rollout                edgedeployment.RolloutPolicy
}

type RollbackInput struct {
	ConfigurationScopeID uuid.UUID
	PublicationID        uuid.UUID
	TargetKind           string
	NodeIDs              []uuid.UUID
	TargetSnapshot       *edgepublish.TargetSnapshotReference
	HealthCheck          edgedeployment.HealthCheckPolicy
	MaxAttempts          uint32
	Deadline             time.Time
	Rollout              edgedeployment.RolloutPolicy
}

type RolloutCommandInput struct {
	ConfigurationScopeID uuid.UUID
	RolloutID            uuid.UUID
	ExpectedRevision     int64
}

type TargetView struct {
	Kind           string     `json:"kind"`
	SnapshotID     *uuid.UUID `json:"snapshot_id,omitempty"`
	Revision       *int64     `json:"revision,omitempty"`
	ResolverSHA256 *string    `json:"resolver_sha256,omitempty"`
	ResolvedSHA256 *string    `json:"resolved_sha256,omitempty"`
}

type PublicationView struct {
	ID                    uuid.UUID  `json:"id"`
	ConfigurationScopeID  *uuid.UUID `json:"configuration_scope_id,omitempty"`
	SourceRevision        int64      `json:"source_revision"`
	ConfigVersionID       uuid.UUID  `json:"config_version_id"`
	RolloutID             uuid.UUID  `json:"rollout_id"`
	CanonicalSourceSHA256 *string    `json:"canonical_source_sha256,omitempty"`
	ArtifactSHA256        *string    `json:"artifact_sha256,omitempty"`
	Target                TargetView `json:"target"`
	NodeCount             int        `json:"node_count"`
	CreatedAt             string     `json:"created_at"`
	Replayed              bool       `json:"replayed,omitempty"`
}

type PublicationPageView struct {
	Items                 []PublicationView `json:"items"`
	NextCursor            string            `json:"next_cursor,omitempty"`
	CurrentSourceRevision int64             `json:"current_source_revision"`
	// PendingModules lists the revoked modules the scope's published release
	// uses (pending republication); omitted when none.
	PendingModules []PendingModuleView `json:"pending_modules,omitempty"`
	// AutomaticFailure: the latest automatic publication published nothing
	// (no node serves the scope, or none can take the release); omitted
	// otherwise.
	AutomaticFailure *AutomaticFailureView `json:"automatic_failure,omitempty"`
}

type AutomaticFailureView struct {
	Reason         string `json:"reason"`
	SourceRevision int64  `json:"source_revision"`
	FailedAt       string `json:"failed_at"`
	// ArtifactSync: for node_artifacts_syncing, the refused nodes' node
	// artifact sync progress; omitted before any node has a set.
	ArtifactSync *ArtifactSyncView `json:"artifact_sync,omitempty"`
}

type ArtifactSyncView struct {
	ReceivedSegments int `json:"received_segments"`
	TotalSegments    int `json:"total_segments"`
	RemainingMinutes int `json:"remaining_minutes"`
}

type PendingModuleView struct {
	Module         string `json:"module"`
	SourceRevision int64  `json:"source_revision"`
}

type RollbackView struct {
	PublicationID        uuid.UUID  `json:"publication_id"`
	ConfigurationScopeID uuid.UUID  `json:"configuration_scope_id"`
	ConfigVersionID      uuid.UUID  `json:"config_version_id"`
	RolloutID            uuid.UUID  `json:"rollout_id"`
	Action               string     `json:"action"`
	Target               TargetView `json:"target"`
	NodeCount            int        `json:"node_count"`
	CreatedAt            string     `json:"created_at"`
	Replayed             bool       `json:"replayed,omitempty"`
}

type RolloutProgressView struct {
	Total     int `json:"total"`
	Pending   int `json:"pending"`
	Running   int `json:"running"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
	// Superseded: nodes that ignored this old release (they run a newer
	// one); not a failure (fix-cfgflow2 §1).
	Superseded int `json:"superseded"`
	// Frozen: nodes that refused it while frozen (expired service ticket),
	// waiting for redelivery; not a failure (fix-stoppolicy2).
	Frozen int `json:"frozen"`
}

type RolloutView struct {
	ID                   uuid.UUID           `json:"id"`
	ConfigurationScopeID *uuid.UUID          `json:"configuration_scope_id,omitempty"`
	ConfigVersionID      uuid.UUID           `json:"config_version_id"`
	Action               string              `json:"action"`
	State                string              `json:"state"`
	Revision             int64               `json:"revision"`
	MaxAttempts          uint32              `json:"max_attempts"`
	Progress             RolloutProgressView `json:"progress"`
	CanCancel            bool                `json:"can_cancel"`
	CanRetry             bool                `json:"can_retry"`
	CanStart             bool                `json:"can_start"`
	CanPause             bool                `json:"can_pause"`
	CanResume            bool                `json:"can_resume"`
	Rollout              *RolloutPolicyView  `json:"rollout,omitempty"`
	PauseReason          string              `json:"pause_reason"`
	CreatedAt            string              `json:"created_at"`
	UpdatedAt            string              `json:"updated_at"`
	Replayed             bool                `json:"replayed,omitempty"`
}

type RolloutPolicyView struct {
	Strategy         string `json:"strategy"`
	CanarySize       uint32 `json:"canary_size"`
	BatchSize        uint32 `json:"batch_size"`
	FailureThreshold uint32 `json:"failure_threshold"`
	CohortCount      int    `json:"cohort_count"`
	ReleasedCohort   int    `json:"released_cohort"`
}

type RolloutPageView struct {
	Items      []RolloutView `json:"items"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

type DeploymentView struct {
	ID          uuid.UUID  `json:"id"`
	NodeID      *uuid.UUID `json:"node_id,omitempty"`
	Attempt     uint32     `json:"attempt"`
	MaxAttempts uint32     `json:"max_attempts"`
	State       string     `json:"state"`
	ErrorCode   string     `json:"error_code,omitempty"`
	CreatedAt   string     `json:"created_at"`
	UpdatedAt   string     `json:"updated_at"`
	CanRetry    bool       `json:"can_retry"`
	Cohort      *int       `json:"cohort,omitempty"`
	Released    *bool      `json:"released,omitempty"`
	// Superseded: the node ignored this old release, it already runs a newer
	// one or this release was rolled back (fix-cfgflow2 §1). Not a failure.
	Superseded bool `json:"superseded,omitempty"`
	// Frozen: the node refused it while frozen; the system redelivers it
	// once the node unfreezes ("冻结中待补发", fix-stoppolicy2). Not a failure.
	Frozen bool `json:"frozen,omitempty"`
	// Warnings: faults the node reported with a successful deployment
	// (edgedeployment.Warning*).
	Warnings []string `json:"warnings,omitempty"`
}

type DeploymentPageView struct {
	Items      []DeploymentView `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}
