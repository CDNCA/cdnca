package firewallcontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	PermissionRead   = "firewall.read"
	PermissionManage = "firewall.manage"

	ScopeTenant       = "tenant"
	ScopePlatform     = "platform"
	CredentialSession = "session"
	CredentialAPIKey  = "api_key"

	ActionAllow = "allow"
	ActionDeny  = "deny"

	ProtocolAny  = "any"
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolICMP = "icmp"

	RecoveryFalsePositive = "false_positive"
	RecoveryHealthFailure = "health_failure"
	RecoveryOperator      = "operator_request"

	DeploymentPending    = "pending"
	DeploymentCanary     = "canary"
	DeploymentActive     = "active"
	DeploymentPartial    = "partial"
	DeploymentFailed     = "failed"
	DeploymentRolledBack = "rolled_back"
)

var (
	ErrUnauthenticated     = errors.New("firewall authentication required")
	ErrPermissionDenied    = errors.New("firewall permission denied")
	ErrNotFound            = errors.New("firewall policy not found")
	ErrInvalidInput        = errors.New("invalid firewall input")
	ErrRevisionConflict    = errors.New("firewall revision conflict")
	ErrIdempotencyConflict = errors.New("firewall idempotency conflict")
	ErrUnavailable         = errors.New("firewall control unavailable")
	ErrOutcomeUnknown      = errors.New("firewall write outcome unknown")
	// ErrSharedNodeOnly: the scope owns no active node. Host rules reach only
	// owned nodes; a tenant on shared platform nodes uses site access control.
	ErrSharedNodeOnly = errors.New("shared nodes do not accept tenant host firewall rules")
)

type Actor struct {
	UserID         uuid.UUID
	ScopeID        uuid.UUID
	ScopeKind      string
	Permissions    []string
	credentialKind string
	credentialID   uuid.UUID
	rawCredential  string
	tenantID       *uuid.UUID
}

func (Actor) String() string   { return "firewallcontrol.Actor{credential:redacted}" }
func (Actor) GoString() string { return "firewallcontrol.Actor{credential:redacted}" }
func (Actor) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("firewallcontrol.Actor{credential:redacted}"))
}

func (actor Actor) WithCredential(kind string, credentialID uuid.UUID, raw string, tenantID *uuid.UUID) Actor {
	actor.credentialKind, actor.credentialID, actor.rawCredential = kind, credentialID, raw
	if tenantID != nil {
		value := *tenantID
		actor.tenantID = &value
	}
	return actor
}

type RuleInput struct {
	ID        uuid.UUID   `json:"id,omitempty"`
	Priority  int         `json:"priority"`
	Action    string      `json:"action"`
	CIDRs     []string    `json:"cidrs"`
	Protocol  string      `json:"protocol"`
	PortStart uint16      `json:"port_start,omitempty"`
	PortEnd   uint16      `json:"port_end,omitempty"`
	SiteIDs   []uuid.UUID `json:"site_ids"`
	ExpiresAt *time.Time  `json:"expires_at,omitempty"`
}

type PolicyInput struct {
	Enabled       bool        `json:"enabled"`
	DefaultAction string      `json:"default_action"`
	Rules         []RuleInput `json:"rules"`
}

type Policy struct {
	ID            uuid.UUID `json:"id"`
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	PolicyInput
	Revision        int64     `json:"revision"`
	ActiveRevision  int64     `json:"active_revision"`
	DeploymentState string    `json:"deployment_state"`
	ActiveSHA256    string    `json:"active_sha256,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type PutRequest struct {
	Actor            Actor
	TargetScopeID    uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	Policy           PolicyInput
	RequestSHA256    [32]byte
	DocumentSHA256   [32]byte
}

type ReadRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
}

type RecoverRequest struct {
	Actor            Actor
	TargetScopeID    uuid.UUID
	ExpectedRevision int64
	RecoverRevision  int64
	Reason           string
	IdempotencyKey   string
	RequestID        string
}

type WriteResult struct {
	Policy   Policy `json:"policy"`
	Replayed bool   `json:"replayed"`
}

type Hit struct {
	ID              string    `json:"id"`
	OccurredAt      time.Time `json:"occurred_at"`
	TenantScopeID   uuid.UUID `json:"tenant_scope_id"`
	SiteID          uuid.UUID `json:"site_id,omitempty"`
	NodeID          uuid.UUID `json:"node_id"`
	RuleID          uuid.UUID `json:"rule_id,omitempty"`
	ClientIP        string    `json:"client_ip"`
	Protocol        string    `json:"protocol"`
	DestinationPort uint16    `json:"destination_port,omitempty"`
	Action          string    `json:"action"`
	ReasonCode      string    `json:"reason_code"`
}

type HitFilter struct {
	Actor         Actor
	TargetScopeID uuid.UUID
	SiteID        uuid.UUID
	Limit         int
	Cursor        string
}

type HitPage struct {
	Items      []Hit  `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type storePort interface {
	Put(context.Context, PutRequest) (WriteResult, error)
	Get(context.Context, ReadRequest) (Policy, error)
	Recover(context.Context, RecoverRequest) (WriteResult, error)
	ListHits(context.Context, HitFilter) (HitPage, error)
}
