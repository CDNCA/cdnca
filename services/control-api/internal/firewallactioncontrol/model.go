package firewallactioncontrol

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
)

const (
	SchemaVersion = "cdnca.edge.firewall-action/v1"

	PermissionRead   = firewallcontrol.PermissionRead
	PermissionManage = firewallcontrol.PermissionManage
	ScopeTenant      = firewallcontrol.ScopeTenant
	ScopePlatform    = firewallcontrol.ScopePlatform

	ActionDisconnect = "disconnect"
	ActionReturnPage = "return_page"
	ActionNFTables   = "nftables"

	StatePending = "pending"
	StateActive  = "active"
	StateFailed  = "failed"
)

var (
	ErrUnauthenticated     = errors.New("firewall action authentication required")
	ErrPermissionDenied    = errors.New("firewall action permission denied")
	ErrNotFound            = errors.New("firewall action policy not found")
	ErrNoLKG               = errors.New("firewall action policy has no last known good revision")
	ErrInvalidInput        = errors.New("invalid firewall action input")
	ErrRevisionConflict    = errors.New("firewall action revision conflict")
	ErrIdempotencyConflict = errors.New("firewall action idempotency conflict")
	ErrUnavailable         = errors.New("firewall action control unavailable")
)

type Actor = firewallcontrol.Actor

type ReturnPage struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

type TrustedCrawler struct {
	Name              string   `json:"name"`
	Networks          []string `json:"networks"`
	UserAgentPrefixes []string `json:"user_agent_prefixes"`
}

type PolicyInput struct {
	NormalAction     string           `json:"normal_action"`
	EscalatedAction  string           `json:"escalated_action"`
	EngageThreshold  uint64           `json:"engage_threshold"`
	RecoverThreshold uint64           `json:"recover_threshold"`
	RecoveryWindows  uint32           `json:"recovery_windows"`
	BlockNetworks    []string         `json:"block_networks"`
	TrustedProxies   []string         `json:"trusted_proxies"`
	TrustedCrawlers  []TrustedCrawler `json:"trusted_crawlers"`
	ReturnPage       ReturnPage       `json:"return_page"`
}

type EdgePolicy struct {
	SchemaVersion               string           `json:"schema_version"`
	PolicyVersion               uint64           `json:"policy_version"`
	TenantID                    string           `json:"tenant_id"`
	SiteID                      string           `json:"site_id"`
	PolicyID                    string           `json:"policy_id"`
	ExpectedActivePolicyVersion uint64           `json:"expected_active_policy_version"`
	NormalAction                string           `json:"normal_action"`
	EscalatedAction             string           `json:"escalated_action"`
	EngageThreshold             uint64           `json:"engage_threshold"`
	RecoverThreshold            uint64           `json:"recover_threshold"`
	RecoveryWindows             uint32           `json:"recovery_windows"`
	BlockNetworks               []string         `json:"block_networks"`
	TrustedProxies              []string         `json:"trusted_proxies"`
	TrustedCrawlers             []TrustedCrawler `json:"trusted_crawlers"`
	ReturnPage                  ReturnPage       `json:"return_page"`
}

type Policy struct {
	ID            uuid.UUID `json:"id"`
	TenantScopeID uuid.UUID `json:"tenant_scope_id"`
	SiteID        uuid.UUID `json:"site_id"`
	PolicyInput
	Revision        int64     `json:"revision"`
	ActiveRevision  int64     `json:"active_revision"`
	LKGRevision     int64     `json:"lkg_revision"`
	DeploymentState string    `json:"deployment_state"`
	DocumentSHA256  string    `json:"document_sha256"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	// HostEscalation says where the nftables escalation runs (A08): "owned"
	// when the scope owns an active node, "shared_unsupported" when it has
	// only shared platform nodes there the escalation stays in OpenResty
	// (the site's own block and disconnect). Not part of the document.
	HostEscalation string `json:"host_escalation"`
}

const (
	HostEscalationOwned             = "owned"
	HostEscalationSharedUnsupported = "shared_unsupported"
)

type PutRequest struct {
	Actor            Actor
	TargetScopeID    uuid.UUID
	SiteID           uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	Policy           PolicyInput
	Document         EdgePolicy
	RequestSHA256    [32]byte
	DocumentSHA256   [32]byte
}

type ReadRequest struct {
	Actor         Actor
	TargetScopeID uuid.UUID
	SiteID        uuid.UUID
}

type RecoverRequest struct {
	Actor            Actor
	TargetScopeID    uuid.UUID
	SiteID           uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	RequestSHA256    [32]byte
}

type WriteResult struct {
	Policy   Policy `json:"policy"`
	Replayed bool   `json:"replayed"`
}

type OutcomeRequest struct {
	TargetScopeID  uuid.UUID
	SiteID         uuid.UUID
	Revision       int64
	DocumentSHA256 [32]byte
	Applied        bool
	ReasonCode     string
}

type Publication struct {
	ID             uuid.UUID
	TargetScopeID  uuid.UUID
	SiteID         uuid.UUID
	PolicyID       uuid.UUID
	Revision       int64
	Document       json.RawMessage
	DocumentSHA256 [32]byte
	Attempt        int
}

type ProjectionResult struct {
	PublicationID  uuid.UUID
	DocumentSHA256 [32]byte
	Attempt        int
	Published      bool
	ReasonCode     string
	RetryAt        time.Time
}

type storePort interface {
	Put(context.Context, PutRequest) (WriteResult, error)
	Get(context.Context, ReadRequest) (Policy, error)
	Recover(context.Context, RecoverRequest) (WriteResult, error)
}
