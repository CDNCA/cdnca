package drainruntime

import (
	"errors"
	"time"
)

const SchemaVersionV1 = "cdnca.edge.drain/v1"

const (
	maxListeners            = 2000
	maxHealthChecks         = 128
	maxIdentifierBytes      = 64
	maxProbeBytes           = 1024
	maxReasonBytes          = 256
	maxHealthTimeoutSeconds = 300
	maxDrainTimeoutSeconds  = 86400
)

var (
	ErrInvalidPlan            = errors.New("invalid drain plan")
	ErrInvalidPath            = errors.New("invalid drain runtime path")
	ErrConflict               = errors.New("drain plan conflicts with recorded revision")
	ErrStaleRevision          = errors.New("drain plan revision is stale")
	ErrCorruptState           = errors.New("corrupt drain runtime state")
	ErrHealthPending          = errors.New("new version health gate is pending")
	ErrDrainInProgress        = errors.New("old version connections are draining")
	ErrDrainObservationFailed = errors.New("old version generation observation failed")
	ErrDrainDeadlineExceeded  = errors.New("old version drain deadline exceeded")
	ErrRollbackFailed         = errors.New("drain rollback failed")
)

type Phase string

const (
	PhasePrecheck    Phase = "precheck"
	PhaseActivateNew Phase = "activate-new"
	PhaseHealthGate  Phase = "health-gate"
	PhaseDrainingOld Phase = "draining-old"
	PhaseCompleted   Phase = "completed"
	PhaseRolledBack  Phase = "rolled-back"
)

type Protocol string

const (
	ProtocolHTTP Protocol = "http"
	ProtocolTCP  Protocol = "tcp"
)

type ForceTerminationPolicy string

const (
	ForceNever         ForceTerminationPolicy = "never"
	ForceAfterDeadline ForceTerminationPolicy = "after-deadline"
)

type Listener struct {
	ID              string   `json:"id"`
	Protocol        Protocol `json:"protocol"`
	Address         string   `json:"address"`
	Port            int      `json:"port"`
	UpstreamAddress string   `json:"upstream_address"`
	UpstreamPort    int      `json:"upstream_port"`
}

type Version struct {
	VersionID string     `json:"version_id"`
	Listeners []Listener `json:"listeners"`
}

type HealthCheck struct {
	ListenerID         string `json:"listener_id"`
	Path               string `json:"path,omitempty"`
	ExpectedStatus     int    `json:"expected_status,omitempty"`
	Payload            string `json:"payload,omitempty"`
	ExpectedBodyPrefix string `json:"expected_body_prefix"`
}

type DrainPolicy struct {
	MaxDrainSeconds int                    `json:"max_drain_seconds"`
	Force           ForceTerminationPolicy `json:"force"`
	ForceReason     string                 `json:"force_reason,omitempty"`
}

type Plan struct {
	SchemaVersion        string        `json:"schema_version"`
	PlanID               string        `json:"plan_id"`
	Revision             uint64        `json:"revision"`
	Old                  Version       `json:"old"`
	New                  Version       `json:"new"`
	HealthTimeoutSeconds int           `json:"health_timeout_seconds"`
	HealthChecks         []HealthCheck `json:"health_checks"`
	Drain                DrainPolicy   `json:"drain"`
}

type CompiledPlan struct {
	Plan           Plan
	Digest         string
	CanonicalJSON  []byte
	CandidateNginx []byte
	DrainingNginx  []byte
	RollbackNginx  []byte
}

type Artifacts struct {
	PlanPath      string
	CandidatePath string
	DrainingPath  string
	RollbackPath  string
	Digest        string
	Revision      uint64
}

type Transition struct {
	Sequence  uint64    `json:"sequence"`
	Phase     Phase     `json:"phase"`
	At        time.Time `json:"at"`
	ErrorCode string    `json:"error_code,omitempty"`
	Summary   string    `json:"summary,omitempty"`
}

type Result struct {
	PlanID              string       `json:"plan_id"`
	Revision            uint64       `json:"revision"`
	Digest              string       `json:"digest"`
	Phase               Phase        `json:"phase"`
	HealthDeadline      time.Time    `json:"health_deadline,omitempty"`
	DrainDeadline       time.Time    `json:"drain_deadline,omitempty"`
	RemainingOldWorkers int          `json:"remaining_old_workers,omitempty"`
	ForcedTermination   bool         `json:"forced_termination,omitempty"`
	RollbackPending     bool         `json:"rollback_pending,omitempty"`
	Transitions         []Transition `json:"transitions"`
}
