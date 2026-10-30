package cachecontrolhttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

var (
	ErrInvalidRequest = errors.New("invalid cache control HTTP request")
	// ErrWildcardTargetHost: a target names "*.a.com" instead of a concrete host.
	ErrWildcardTargetHost    = fmt.Errorf("%w: wildcard target host", ErrInvalidRequest)
	ErrUnauthenticated       = errors.New("cache control authentication required")
	ErrPermissionDenied      = errors.New("cache control HTTP permission denied")
	ErrNotFound              = errors.New("cache control HTTP resource not found")
	ErrRevisionConflict      = errors.New("cache policy revision conflict")
	ErrIdempotencyConflict   = errors.New("cache control idempotency conflict")
	ErrInvalidTransition     = errors.New("cache operation transition conflict")
	ErrRetriesExhausted      = errors.New("cache operation retries exhausted")
	ErrEntitlementDenied     = errors.New("cache operation entitlement denied")
	ErrSiteLocked            = errors.New("cache policy site is locked")
	ErrDailyLimitExceeded    = errors.New("cache operation daily limit exceeded")
	ErrNoCarryingNode        = errors.New("no node carries the site yet")
	ErrTargetNodeUnavailable = errors.New("a named node is not available for the site")
	// ErrWildcardPurgeUnsupported: a "*." purge targets a node that does not
	// declare CACHE_WILDCARD_PURGE.
	ErrWildcardPurgeUnsupported = errors.New("a target node does not support wildcard purge")
	ErrStoreUnavailable         = errors.New("cache control store unavailable")
	ErrInvalidStoreResponse     = errors.New("cache control store returned invalid facts")
	ErrResponseTooLarge         = errors.New("cache control HTTP response too large")
)

const (
	PermissionPoliciesRead     = "sites.read"
	PermissionPoliciesManage   = "sites.manage"
	PermissionOperationsRead   = "sites.read"
	PermissionOperationsManage = "sites.manage"
	// PermissionAccountQuotaManage: setting an account's own daily limits is
	// user management (fix-cachequota).
	PermissionAccountQuotaManage          = "identity.users.manage"
	AudienceTenant               Audience = "tenant"
	AudiencePlatform             Audience = "platform"
)

type Audience string

type AuthenticateFunc func(*http.Request) (identity.Principal, error)

type ControlStore interface {
	PublishPolicy(context.Context, cachecontrol.Actor, cachecontrol.PublishPolicyRequest) (cachecontrol.PolicyWriteResult, error)
	GetPolicy(context.Context, cachecontrol.Actor, uuid.UUID, int64) (cachecontrol.PolicyRevision, error)
	CreateOperation(context.Context, cachecontrol.Actor, cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error)
	GetOperation(context.Context, cachecontrol.Actor, uuid.UUID) (cachecontrol.Operation, error)
	Retry(context.Context, cachecontrol.Actor, cachecontrol.RetryRequest) (cachecontrol.OperationWriteResult, error)
	Resubmit(context.Context, cachecontrol.Actor, cachecontrol.ResubmitRequest) (cachecontrol.OperationWriteResult, error)
	Cancel(context.Context, cachecontrol.Actor, cachecontrol.CancelRequest) (cachecontrol.OperationWriteResult, error)
	DailyUsage(context.Context, cachecontrol.Actor) (cachecontrol.DailyUsage, error)
	SetAccountLimits(context.Context, cachecontrol.Actor, cachecontrol.SetAccountLimitsRequest) (cachecontrol.DailyUsage, error)
	// fix-cachedlg: target URLs grouped by the sites serving their hosts, and
	// the nodes an automatic operation of the scope runs on.
	ResolveTargetSites(context.Context, cachecontrol.Actor, bool, cachecontrol.ResolveTargetSitesRequest) (cachecontrol.TargetSiteGrouping, error)
	CarryingNodes(context.Context, cachecontrol.Actor) ([]cachecontrol.CarryingNode, error)
	// fix-cacheflow5: the receipt of a write by its idempotency key.
	WriteReceipt(context.Context, cachecontrol.Actor, cachecontrol.WriteReceiptRequest) (cachecontrol.WriteReceipt, error)
}

// WriteReceiptView answers GET .../cache-operation-requests/{idempotency_key}:
// accepted with the operation (the new one of a create or re-submit), or
// rejected with the code (and target details) the write was refused with.
type WriteReceiptView struct {
	Status    string              `json:"status"`
	DecidedAt time.Time           `json:"decided_at"`
	Operation *OperationView      `json:"operation,omitempty"`
	Rejection *WriteRejectionView `json:"rejection,omitempty"`
}

type WriteRejectionView struct {
	Code    string           `json:"code"`
	Details *TargetRejection `json:"details,omitempty"`
}

// TargetSitesView answers POST .../cache-operations/target-sites.
type TargetSitesView struct {
	Groups    []TargetSiteGroupView `json:"groups"`
	Unmatched []UnmatchedTargetView `json:"unmatched"`
}

type TargetSiteGroupView struct {
	SiteID         uuid.UUID `json:"site_id"`
	ScopeID        uuid.UUID `json:"scope_id"`
	SiteDisplayID  string    `json:"site_display_id"`
	Domain         string    `json:"domain"`
	TargetOrdinals []int     `json:"target_ordinals"`
}

type UnmatchedTargetView struct {
	TargetOrdinal int    `json:"target_ordinal"`
	Reason        string `json:"reason"`
}

// CarryingNodeView is one choice of the create dialog's node picker.
type CarryingNodeView struct {
	ID        uuid.UUID `json:"id"`
	DisplayID string    `json:"display_id"`
	Name      string    `json:"name"`
	IPv4      string    `json:"ipv4,omitempty"`
	IPv6      string    `json:"ipv6,omitempty"`
}

type CarryingNodesView struct {
	Items []CarryingNodeView `json:"items"`
}

type ReadStore interface {
	ListPolicyRevisions(context.Context, cachecontrol.Actor, uuid.UUID, PolicyPageQuery) (PolicyReadPage, error)
	ListOperations(context.Context, cachecontrol.Actor, OperationPageQuery) (OperationReadPage, error)
}

type PolicyPageQuery struct {
	SnapshotRevision int64
	BeforeRevision   int64
	Limit            int
}

type PolicyReadPage struct {
	Items            []cachecontrol.PolicyRevision
	SnapshotRevision int64
	HasMore          bool
}

type OperationFilters struct {
	Search        string
	SiteID        *uuid.UUID
	SiteDisplayID string
	Action        cachecontrol.Action
	TargetType    cachecontrol.TargetType
	// States: any of these (状态胶囊多选); empty is every state.
	States []cachecontrol.State
}

type OperationPageQuery struct {
	Filters          OperationFilters
	SnapshotPosition int64
	BeforeCreated    *time.Time
	BeforeID         *uuid.UUID
	Limit            int
}

type OperationSummary struct {
	ID            uuid.UUID               `json:"id"`
	DisplayID     string                  `json:"display_id"`
	SiteID        uuid.UUID               `json:"site_id"`
	SiteDisplayID string                  `json:"site_display_id"`
	Action        cachecontrol.Action     `json:"action"`
	TargetType    cachecontrol.TargetType `json:"target_type"`
	State         cachecontrol.State      `json:"state"`
	MaxAttempts   uint32                  `json:"max_attempts"`
	TargetCount   int                     `json:"target_count"`
	NodeCount     int                     `json:"node_count"`
	// FirstTarget: the first target as the detail shows it (query redacted),
	// so the list needs no detail read per row.
	FirstTarget TargetView `json:"first_target"`
	AutoNodes   bool       `json:"auto_nodes"`
	// ParentOperationID: set on a system follow-up of a user's operation
	// (CACHE-ADD-09b); the history page folds it under its parent.
	ParentOperationID *uuid.UUID            `json:"parent_operation_id,omitempty"`
	Progress          cachecontrol.Progress `json:"progress"`
	CreatedAt         time.Time             `json:"created_at"`
	UpdatedAt         time.Time             `json:"updated_at"`
	CompletedAt       *time.Time            `json:"completed_at,omitempty"`
}

// StateCounts: operations per state under the page's other filters (all
// but states), read on the first page only.
type StateCounts map[cachecontrol.State]int64

type OperationReadPage struct {
	Items            []OperationSummary
	SnapshotPosition int64
	HasMore          bool
	StateCounts      StateCounts
}

type PolicyView struct {
	SiteID             uuid.UUID                   `json:"site_id"`
	Revision           int64                       `json:"revision"`
	BindingMode        cachecontrol.BindingMode    `json:"binding_mode"`
	DefinitionID       uuid.UUID                   `json:"definition_id"`
	DefinitionRevision int64                       `json:"definition_revision"`
	Document           cachecontrol.PolicyDocument `json:"document"`
	CreatedByUserID    uuid.UUID                   `json:"created_by_user_id"`
	RequestID          string                      `json:"request_id"`
	CreatedAt          time.Time                   `json:"created_at"`
}

type PolicyPage struct {
	Items      []PolicyView `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

type TargetView struct {
	Ordinal       int    `json:"ordinal"`
	DisplayURL    string `json:"display_url"`
	CanonicalPath string `json:"canonical_path"`
	TargetSHA256  string `json:"target_sha256"`
	QueryRedacted bool   `json:"query_redacted"`
}

type TargetProjectionView struct {
	TargetOrdinal int                    `json:"target_ordinal"`
	State         cachecontrol.ItemState `json:"state"`
	Attempt       uint32                 `json:"attempt"`
	Sequence      uint64                 `json:"sequence"`
	ErrorCode     string                 `json:"error_code,omitempty"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty"`
}

type NodeProjectionView struct {
	NodeID        uuid.UUID              `json:"node_id"`
	NodeDisplayID string                 `json:"node_display_id"`
	State         cachecontrol.State     `json:"state"`
	Attempt       uint32                 `json:"attempt"`
	Progress      cachecontrol.Progress  `json:"progress"`
	LastErrorCode string                 `json:"last_error_code,omitempty"`
	Targets       []TargetProjectionView `json:"targets"`
	UpdatedAt     time.Time              `json:"updated_at"`
	CompletedAt   *time.Time             `json:"completed_at,omitempty"`
	// CancelConfirmation: pending / cancelled / completed / unresponsive /
	// unsupported, set when the operation was cancelled while the node ran it.
	CancelConfirmation cachecontrol.CancelConfirmation `json:"cancel_confirmation,omitempty"`
}

type OperationView struct {
	ID                uuid.UUID               `json:"id"`
	DisplayID         string                  `json:"display_id"`
	SiteID            uuid.UUID               `json:"site_id"`
	SiteDisplayID     string                  `json:"site_display_id"`
	Action            cachecontrol.Action     `json:"action"`
	TargetType        cachecontrol.TargetType `json:"target_type"`
	State             cachecontrol.State      `json:"state"`
	MaxAttempts       uint32                  `json:"max_attempts"`
	Progress          cachecontrol.Progress   `json:"progress"`
	AutoNodes         bool                    `json:"auto_nodes"`
	ParentOperationID *uuid.UUID              `json:"parent_operation_id,omitempty"`
	Targets           []TargetView            `json:"targets"`
	Nodes             []NodeProjectionView    `json:"nodes"`
	CancelRequestedAt *time.Time              `json:"cancel_requested_at,omitempty"`
	CreatedAt         time.Time               `json:"created_at"`
	StartedAt         *time.Time              `json:"started_at,omitempty"`
	UpdatedAt         time.Time               `json:"updated_at"`
	CompletedAt       *time.Time              `json:"completed_at,omitempty"`
}

type OperationPage struct {
	Items       []OperationSummary `json:"items"`
	NextCursor  string             `json:"next_cursor,omitempty"`
	StateCounts StateCounts        `json:"state_counts,omitempty"`
}

type WriteResult[T any] struct {
	Value    T
	Replayed bool
}

// TargetRejection is a create refused for one target (ADD-10): the error
// envelope carries it as details so the console can point at the line.
// DailyLimitDetails is error.details of a daily_limit_exceeded refusal
// (fix-cachequota): which account quota, its limit, today's use and the
// targets the create asked for.
type DailyLimitDetails struct {
	Field     string `json:"field"`
	Reason    string `json:"reason"`
	Quota     string `json:"quota"`
	Limit     int    `json:"limit"`
	Used      int    `json:"used"`
	Requested int    `json:"requested"`
}

type TargetRejection struct {
	Field         string `json:"field"`
	TargetOrdinal int    `json:"target_ordinal"`
	Stage         string `json:"stage"`
	Reason        string `json:"reason"`
}

func (rejection *TargetRejection) Error() string {
	return "cache operation target rejected: " + rejection.Reason
}
func (rejection *TargetRejection) Unwrap() error { return ErrInvalidRequest }
