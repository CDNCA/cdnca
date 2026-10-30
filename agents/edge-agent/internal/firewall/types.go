package firewall

import (
	"context"
	"errors"
	"time"
)

const (
	TableFamily = "inet"
	TableName   = "cdnca_firewall"
)

var (
	ErrInvalidVersion          = errors.New("invalid firewall version")
	ErrInvalidPath             = errors.New("invalid firewall state path")
	ErrConflict                = errors.New("firewall idempotency conflict")
	ErrActiveVersionConflict   = errors.New("firewall active policy version conflict")
	ErrPolicyVersionRegression = errors.New("firewall policy version must advance")
	ErrCorruptState            = errors.New("corrupt firewall state")
	ErrExpiredEntry            = errors.New("firewall version contains an expired entry")
	ErrNoActiveVersion         = errors.New("no active firewall version")
	ErrNoExpiredEntry          = errors.New("active firewall version has no expired entry")
	ErrOwnerPurgeFailed        = errors.New("firewall could not remove host rules of scopes that do not own the node")
	ErrUnhealthy               = errors.New("firewall runtime is unhealthy")
	ErrUnsupported             = errors.New("firewall runtime is unsupported on this platform")
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

type Protocol string

const (
	ProtocolAny  Protocol = ""
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
)

type Entry struct {
	TenantID  string     `json:"tenant_id,omitempty"`
	SiteID    string     `json:"site_id,omitempty"`
	Action    Action     `json:"action"`
	Network   string     `json:"network"`
	Protocol  Protocol   `json:"protocol,omitempty"`
	PortStart uint16     `json:"port_start,omitempty"`
	PortEnd   uint16     `json:"port_end,omitempty"`
	Source    string     `json:"source"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type Operation string

const (
	OperationApply   Operation = "apply"
	OperationRecover Operation = "recover"
)

type RecoveryReason string

const (
	RecoveryReasonNotApplicable    RecoveryReason = "not_applicable"
	RecoveryReasonFalsePositive    RecoveryReason = "false_positive"
	RecoveryReasonPolicyRegression RecoveryReason = "policy_regression"
	RecoveryReasonHealthFailure    RecoveryReason = "health_failure"
	RecoveryReasonOperatorRequest  RecoveryReason = "operator_request"
)

type FirewallVersion struct {
	TaskID                      string         `json:"task_id"`
	TaskRevision                uint64         `json:"task_revision,omitempty"`
	IdempotencyKey              string         `json:"idempotency_key,omitempty"`
	TenantID                    string         `json:"tenant_id,omitempty"`
	SiteID                      string         `json:"site_id,omitempty"`
	PolicyKind                  string         `json:"policy_kind,omitempty"`
	PolicyID                    string         `json:"policy_id,omitempty"`
	PolicyVersion               uint64         `json:"policy_version,omitempty"`
	ExpectedActivePolicyVersion uint64         `json:"expected_active_policy_version,omitempty"`
	Operation                   Operation      `json:"operation,omitempty"`
	RecoveryReason              RecoveryReason `json:"recovery_reason,omitempty"`
	CommandDigest               string         `json:"command_digest,omitempty"`
	VersionID                   string         `json:"version_id"`
	Entries                     []Entry        `json:"entries"`
	Aggregate                   bool           `json:"aggregate,omitempty"`
}

type CompiledVersion struct {
	Version FirewallVersion
	Digest  string
	Batch   []byte
}

type ApplyState string

const (
	StateApplied        ApplyState = "applied"
	StateFailed         ApplyState = "failed"
	StateRolledBack     ApplyState = "rolled_back"
	StateRollbackFailed ApplyState = "rollback_failed"
)

type Result struct {
	TaskID                      string     `json:"task_id"`
	TaskRevision                uint64     `json:"task_revision,omitempty"`
	IdempotencyKey              string     `json:"idempotency_key,omitempty"`
	TenantID                    string     `json:"tenant_id,omitempty"`
	SiteID                      string     `json:"site_id,omitempty"`
	PolicyVersion               uint64     `json:"policy_version,omitempty"`
	ExpectedActivePolicyVersion uint64     `json:"expected_active_policy_version,omitempty"`
	VersionID                   string     `json:"version_id"`
	Digest                      string     `json:"digest"`
	State                       ApplyState `json:"state"`
	ActiveVersionID             string     `json:"active_version_id,omitempty"`
	ActivePolicyVersion         uint64     `json:"active_policy_version,omitempty"`
	ErrorCode                   string     `json:"error_code,omitempty"`
	RunningVersionUnchanged     bool       `json:"running_version_unchanged"`
	AppliedAt                   time.Time  `json:"applied_at,omitempty"`
}

type ScopeStatus struct {
	TenantID      string
	SiteID        string
	PolicyKind    string
	PolicyID      string
	PolicyVersion uint64
	TaskRevision  uint64
	EntryCount    int
}

type Status struct {
	Active     bool      `json:"active"`
	Healthy    bool      `json:"healthy"`
	VersionID  string    `json:"version_id,omitempty"`
	TaskID     string    `json:"task_id,omitempty"`
	Digest     string    `json:"digest,omitempty"`
	AppliedAt  time.Time `json:"applied_at,omitempty"`
	EntryCount int       `json:"entry_count"`
}

type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}
