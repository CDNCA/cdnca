package cachecontrol

import (
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid cache control input")
	ErrPermissionDenied    = errors.New("cache control permission denied")
	ErrNotFound            = errors.New("cache control resource not found")
	ErrRevisionConflict    = errors.New("cache policy revision conflict")
	ErrIdempotencyConflict = errors.New("cache control idempotency conflict")
	ErrInvalidTransition   = errors.New("invalid cache operation transition")
	ErrRetriesExhausted    = errors.New("cache operation retries exhausted")
	ErrClaimLost           = errors.New("cache operation claim lost")
	ErrReportConflict      = errors.New("cache operation report conflict")
	ErrEntitlementDenied   = errors.New("cache operation entitlement denied")
	ErrSiteLocked          = errors.New("cache policy site is locked")
	// ErrWildcardTargetHost: a target URL names a wildcard ("*.a.com")
	// instead of one concrete host under it. It is an ErrInvalidInput.
	ErrWildcardTargetHost = fmt.Errorf("%w: target host must be a concrete name, not a wildcard", ErrInvalidInput)
	// ErrWildcardPurgeUnsupported: a purge names a "*." host but a target
	// node does not declare CACHE_WILDCARD_PURGE (upgrade the node).
	ErrWildcardPurgeUnsupported = errors.New("a target node does not support wildcard purge")
	// ErrDailyLimitExceeded: the operation would exceed the platform's daily
	// URL purge, directory purge or prewarm limit for the site (system
	// settings, resource limits).
	ErrDailyLimitExceeded = errors.New("cache operation daily limit exceeded")
	// ErrNoCarryingNode: no node carries the site's configuration yet, and
	// the request named no nodes.
	ErrNoCarryingNode = errors.New("no node carries the site yet")
	// ErrTargetNodeUnavailable: the site is the caller's, but a named node is
	// unknown or does not serve it (fix-cacheflow2 P2-11). One error for both,
	// so a refusal never tells whether another tenant's node exists.
	ErrTargetNodeUnavailable = errors.New("a named node is not available for the site")
)

type State = jobstate.State

const (
	StateQueued        = jobstate.StateQueued
	StateRunning       = jobstate.StateRunning
	StateSucceeded     = jobstate.StateSucceeded
	StatePartialFailed = jobstate.StatePartialFailed
	StateFailed        = jobstate.StateFailed
	StateCancelled     = jobstate.StateCancelled
)

type Actor struct {
	UserID       uuid.UUID
	ScopeID      uuid.UUID
	ActorScopeID uuid.UUID
}

type PolicyMode string

const (
	PolicyDisabled     PolicyMode = "disabled"
	PolicyFollowOrigin PolicyMode = "follow_origin"
	PolicyOverride     PolicyMode = "override"
)

type BindingMode string

const (
	BindingInherit  BindingMode = "inherit"
	BindingOverride BindingMode = "override"
)

type QueryMode string

const (
	QueryPreserve QueryMode = "preserve"
	QueryIgnore   QueryMode = "ignore"
	QueryInclude  QueryMode = "include"
	QueryExclude  QueryMode = "exclude"
)

const (
	PolicySchemaV1 = 1
	PolicySchemaV2 = 2
)

type RuleAction string

const (
	RuleActionCache   RuleAction = "cache"
	RuleActionNoCache RuleAction = "no_cache"
)

type Rule struct {
	Order             int        `json:"order"`
	Extensions        []string   `json:"extensions,omitempty"`
	PathPrefix        string     `json:"path_prefix,omitempty"`
	StatusCodes       []int      `json:"status_codes,omitempty"`
	Action            RuleAction `json:"action,omitempty"`
	TTLSeconds        int64      `json:"ttl_seconds"`
	BrowserTTLSeconds int64      `json:"browser_ttl_seconds,omitempty"`
	// PathRegex / ContentTypes (schema v2, ge36): edgeconfig.CacheRuleDocument;
	// a release with either needs the node capability CACHE_RULE_MATCH.
	PathRegex    string   `json:"path_regex,omitempty"`
	ContentTypes []string `json:"content_types,omitempty"`
	// CacheRuleExtras (schema v2 only): 单个路径, 忽略 URL
	// 参数, 分片回源, 强制 CDN 缓存, 忽略 Vary, 不缓存条件
	// (edgeconfig.CacheRuleExtras).
	edgeconfig.CacheRuleExtras

	actionExplicit     bool
	browserTTLExplicit bool
}

type PolicyDocument struct {
	SchemaVersion  int        `json:"schema_version,omitempty"`
	Mode           PolicyMode `json:"mode"`
	Rules          []Rule     `json:"rules"`
	QueryMode      QueryMode  `json:"query_mode"`
	QueryNames     []string   `json:"query_names"`
	VaryHeaders    []string   `json:"vary_headers"`
	DiskQuotaBytes int64      `json:"disk_quota_bytes"`
	// Extensions (ge-cache): stale-if-error, background update, stored object
	// size bounds and slice size; edgeconfig.CachePolicyDocument documents
	// their semantics. The zero value is none.
	Extensions PolicyExtensions `json:"-"`

	schemaVersionExplicit bool
}

// PolicyExtensions are the cache policy's site runtime v2 extensions
// (stored as cache_policy_*_revisions.extensions; omitted when zero).
type PolicyExtensions struct {
	StaleIfError     bool  `json:"stale_if_error,omitempty"`
	BackgroundUpdate bool  `json:"background_update,omitempty"`
	MinObjectBytes   int64 `json:"min_object_bytes,omitempty"`
	MaxObjectBytes   int64 `json:"max_object_bytes,omitempty"`
	SliceBytes       int64 `json:"slice_bytes,omitempty"`
}

type PolicyRevision struct {
	SiteID             uuid.UUID      `json:"site_id"`
	ScopeID            uuid.UUID      `json:"scope_id"`
	TenantID           uuid.UUID      `json:"tenant_id"`
	Revision           int64          `json:"revision"`
	BindingMode        BindingMode    `json:"binding_mode"`
	DefinitionID       uuid.UUID      `json:"definition_id"`
	DefinitionRevision int64          `json:"definition_revision"`
	Document           PolicyDocument `json:"document"`
	CreatedByUserID    uuid.UUID      `json:"created_by_user_id"`
	RequestID          string         `json:"request_id"`
	CreatedAt          time.Time      `json:"created_at"`
}

type PublishPolicyRequest struct {
	SiteID                     uuid.UUID
	ExpectedRevision           int64
	BindingMode                BindingMode
	DefinitionID               uuid.UUID
	DefinitionRevision         int64
	ExpectedDefinitionRevision *int64
	Document                   PolicyDocument
	IdempotencyKey             string
	RequestID                  string
}

type PolicyWriteResult struct {
	Policy   PolicyRevision
	Replayed bool
}

type RequestFacts struct {
	Path       string
	StatusCode int
	// ContentType is the response's Content-Type header (content_types rules).
	ContentType string
}

type Action string

const (
	ActionPurge   Action = "purge"
	ActionPrewarm Action = "prewarm"
)

type TargetType string

const (
	TargetExactURL        TargetType = "exact_url"
	TargetDirectoryPrefix TargetType = "directory_prefix"
	TargetWholeSite       TargetType = "whole_site"
)

type ItemState string

const (
	ItemQueued    ItemState = "queued"
	ItemRunning   ItemState = "running"
	ItemSucceeded ItemState = "succeeded"
	ItemFailed    ItemState = "failed"
	ItemCancelled ItemState = "cancelled"
)

type Target struct {
	Ordinal       int    `json:"ordinal"`
	CanonicalURL  string `json:"canonical_url"`
	CanonicalPath string `json:"canonical_path"`
}

type TargetProjection struct {
	TargetOrdinal int       `json:"target_ordinal"`
	State         ItemState `json:"state"`
	Attempt       uint32    `json:"attempt"`
	Sequence      uint64    `json:"sequence"`
	ErrorCode     string    `json:"error_code,omitempty"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
}

type Progress struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Cancelled int `json:"cancelled"`
}

type NodeProjection struct {
	NodeID        uuid.UUID          `json:"node_id"`
	NodeDisplayID string             `json:"node_display_id"`
	State         State              `json:"state"`
	Attempt       uint32             `json:"attempt"`
	Progress      Progress           `json:"progress"`
	LastErrorCode string             `json:"last_error_code,omitempty"`
	Targets       []TargetProjection `json:"targets"`
	UpdatedAt     time.Time          `json:"updated_at"`
	CompletedAt   time.Time          `json:"completed_at,omitempty"`
	// CancelConfirmation is the node's answer to the operation's cancel when
	// it was running there (CACHE-ADD-07); empty when no cancel reached it.
	CancelConfirmation CancelConfirmation `json:"cancel_confirmation,omitempty"`
}

type Operation struct {
	ID                uuid.UUID        `json:"id"`
	DisplayID         string           `json:"display_id"`
	ScopeID           uuid.UUID        `json:"scope_id"`
	TenantID          uuid.UUID        `json:"tenant_id"`
	SiteID            uuid.UUID        `json:"site_id"`
	SiteDisplayID     string           `json:"site_display_id"`
	Action            Action           `json:"action"`
	TargetType        TargetType       `json:"target_type"`
	IdempotencyKey    string           `json:"idempotency_key"`
	State             State            `json:"state"`
	MaxAttempts       uint32           `json:"max_attempts"`
	Progress          Progress         `json:"progress"`
	Targets           []Target         `json:"targets"`
	Nodes             []NodeProjection `json:"nodes"`
	CancelRequestedAt time.Time        `json:"cancel_requested_at,omitempty"`
	CreatedAt         time.Time        `json:"created_at"`
	StartedAt         time.Time        `json:"started_at,omitempty"`
	UpdatedAt         time.Time        `json:"updated_at"`
	CompletedAt       time.Time        `json:"completed_at,omitempty"`
	// AutoNodes: created without node_ids (every carrying node); otherwise
	// Nodes are exactly the nodes the request named.
	AutoNodes bool `json:"auto_nodes"`
	// ParentOperationID: the user's operation this one follows up on a node
	// that started carrying the site (SyncCarryingNodes); nil for an
	// operation a user created (CACHE-ADD-09b).
	ParentOperationID *uuid.UUID `json:"parent_operation_id,omitempty"`
}

type CreateOperationRequest struct {
	SiteID     uuid.UUID
	Action     Action
	TargetType TargetType
	Targets    []string
	// NodeIDs: empty runs the operation on every node that carries the
	// site's configuration now (ge-cache I); a node that starts carrying it
	// while the operation is open is added (SyncCarryingNodes).
	NodeIDs        []uuid.UUID
	MaxRetries     uint32
	IdempotencyKey string
	RequestID      string
}

type OperationWriteResult struct {
	Operation Operation
	Replayed  bool
}

type ClaimRequest struct {
	ScopeID             uuid.UUID
	WorkerID            string
	OnlineNodeIDs       []uuid.UUID
	Limit               int
	LeaseDuration       time.Duration
	RequestID           string
	RequireActiveConfig bool
}

type Claim struct {
	OperationID     uuid.UUID  `json:"operation_id"`
	ScopeID         uuid.UUID  `json:"scope_id"`
	TenantID        uuid.UUID  `json:"tenant_id"`
	SiteID          uuid.UUID  `json:"site_id"`
	Action          Action     `json:"action"`
	TargetType      TargetType `json:"target_type"`
	NodeID          uuid.UUID  `json:"node_id"`
	Attempt         uint32     `json:"attempt"`
	LeaseID         uuid.UUID  `json:"lease_id"`
	WorkerID        string     `json:"worker_id"`
	ClaimedAt       time.Time  `json:"claimed_at"`
	LeaseExpiresAt  time.Time  `json:"lease_expires_at"`
	RequestDigest   [32]byte   `json:"request_digest"`
	Priority        string     `json:"priority"`
	ConfigVersionID uuid.UUID  `json:"config_version_id"`
	ConfigRevision  uint64     `json:"config_revision"`
	Targets         []Target   `json:"targets"`
}

type OpenClaimsRequest struct {
	WorkerID string
	Limit    int
}

type ClaimIdentity struct {
	ScopeID     uuid.UUID
	OperationID uuid.UUID
	NodeID      uuid.UUID
	LeaseID     uuid.UUID
	Attempt     uint32
}

type TargetResult struct {
	TargetOrdinal int
	State         ItemState
	ErrorCode     string
}

type ReportRequest struct {
	ScopeID     uuid.UUID
	OperationID uuid.UUID
	NodeID      uuid.UUID
	WorkerID    string
	LeaseID     uuid.UUID
	Attempt     uint32
	Sequence    uint64
	Results     []TargetResult
	RequestID   string
}

type ReportResult struct {
	Operation Operation
	Applied   bool
	Replayed  bool
}

// ResubmitRequest re-submits an operation as a new one with its action,
// target type, targets, retry budget and node scope (the nodes it named, or
// every carrying node now when it named none). BatchKey (the caller's
// Idempotency-Key, shared by one "re-submit selected") with the operation ID
// is the new operation's idempotency key.
type ResubmitRequest struct {
	OperationID uuid.UUID
	BatchKey    string
	RequestID   string
}

type RetryRequest struct {
	OperationID    uuid.UUID
	IdempotencyKey string
	RequestID      string
}

type CancelRequest struct {
	OperationID    uuid.UUID
	IdempotencyKey string
	RequestID      string
}
