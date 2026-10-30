package nodeisolationhttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeisolation"
	"github.com/google/uuid"
)

const (
	PermissionRead    = "nodes.read"
	PermissionReport  = "node_isolation.report"
	ScopeKindPlatform = "platform"
)

var (
	ErrInvalidConfig             = errors.New("invalid node isolation HTTP configuration")
	ErrInvalidRequest            = errors.New("invalid node isolation HTTP request")
	ErrUnauthenticated           = errors.New("node isolation authentication required")
	ErrPermissionDenied          = errors.New("node isolation permission denied")
	ErrAuthenticationUnavailable = errors.New("node isolation authentication unavailable")
)

type Principal struct {
	SubjectID   uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	SessionID   uuid.UUID
	Permissions []string
}

type WorkloadPrincipal struct {
	WorkloadID  string
	ScopeID     uuid.UUID
	NodeID      uuid.UUID
	Permissions []string
}

type SessionAuthenticator interface {
	Authenticate(*http.Request) (Principal, error)
}

type WorkloadAuthenticator interface {
	Authenticate(*http.Request) (WorkloadPrincipal, error)
}

type Service interface {
	RecordSyncResult(context.Context, nodeisolation.SyncResult) (nodeisolation.Result, error)
	ListIsolationStates(context.Context, uuid.UUID, []uuid.UUID) ([]nodeisolation.State, error)
}

type Dependencies struct {
	Service   Service
	Sessions  SessionAuthenticator
	Workloads WorkloadAuthenticator
}

type Config struct {
	MaxRequestBytes int64
	Timeout         time.Duration
}

type identityDTO struct {
	Schema          uint32 `json:"schema"`
	ConfigVersionID string `json:"config_version_id"`
	ArtifactSHA256  string `json:"artifact_sha256"`
}

type healthDTO struct {
	SessionEpoch uint64      `json:"session_epoch"`
	Sequence     uint64      `json:"sequence"`
	ObservedAt   time.Time   `json:"observed_at"`
	Active       identityDTO `json:"active"`
}

type reportBody struct {
	ReportID  string       `json:"report_id"`
	Desired   *identityDTO `json:"desired"`
	Outcome   string       `json:"outcome"`
	ErrorCode string       `json:"error_code"`
	Health    *healthDTO   `json:"health"`
}

type stateDTO struct {
	ScopeID             string      `json:"scope_id"`
	NodeID              string      `json:"node_id"`
	Status              string      `json:"status"`
	Desired             identityDTO `json:"desired"`
	ConsecutiveFailures uint32      `json:"consecutive_failures"`
	ConsecutiveHealthy  uint32      `json:"consecutive_healthy"`
	LastSessionEpoch    uint64      `json:"last_session_epoch"`
	LastHealthSequence  uint64      `json:"last_health_sequence"`
	LastReportID        string      `json:"last_report_id"`
	LastOutcome         string      `json:"last_outcome"`
	LastErrorCode       string      `json:"last_error_code"`
	ReasonCode          string      `json:"reason_code"`
	Revision            uint64      `json:"revision"`
	IsolatedAt          *time.Time  `json:"isolated_at"`
	RecoveredAt         *time.Time  `json:"recovered_at"`
	UpdatedAt           time.Time   `json:"updated_at"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}
