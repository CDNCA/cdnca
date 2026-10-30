package qualitydiagnostics

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/google/uuid"
)

const (
	DefaultLimit = uint16(50)
	MaxLimit     = uint16(100)
)

var (
	ErrInvalidConfiguration = errors.New("quality diagnostics configuration invalid")
	ErrInvalidRequest       = errors.New("quality diagnostics request invalid")
	ErrInvalidCursor        = errors.New("quality diagnostics cursor invalid")
	ErrInvalidSnapshot      = errors.New("quality diagnostics snapshot invalid")
	ErrInvalidResponse      = errors.New("quality diagnostics response invalid")
	ErrPermissionDenied     = errors.New("quality diagnostics permission denied")
	ErrScopeForbidden       = errors.New("quality diagnostics scope forbidden")
	ErrUnavailable          = errors.New("quality diagnostics unavailable")
)

type Audience string

const (
	AudienceTenant   Audience = "tenant"
	AudiencePlatform Audience = "platform"
)

type Category string

const (
	CategoryUpstream5xx    Category = "upstream_5xx"
	CategoryEdge530        Category = "edge_530"
	CategoryNoHost         Category = "no_host"
	CategoryConfigMismatch Category = "config_mismatch"
)

type CauseCode string

const (
	CauseUpstreamFailure CauseCode = "upstream_failure"
	CauseUpstreamEmpty   CauseCode = "upstream_result_empty"
	CauseUpstreamUnknown CauseCode = "upstream_result_unknown"
	CauseStatus530       CauseCode = "edge_status_530"
	CauseUpstreamNoHost  CauseCode = "upstream_reported_no_host"
	CauseHostMissing     CauseCode = "host_missing"
	CauseConfigMismatch  CauseCode = "upstream_reported_config_mismatch"
)

type ActionCode string

const (
	ActionInspectUpstream ActionCode = "inspect_upstream"
	ActionInspectEdge     ActionCode = "inspect_edge_route"
	ActionConfigureHost   ActionCode = "configure_host"
	ActionReconcileConfig ActionCode = "reconcile_config"
)

type Actor struct {
	ScopeKind   string
	TenantID    uuid.UUID
	Permissions []string
}

type Query struct {
	Audience Audience
	TenantID uuid.UUID
	From     time.Time
	To       time.Time
	SiteID   uuid.UUID
	NodeID   uuid.UUID
	Category Category
	Limit    uint16
	Cursor   string
}

type Scope struct {
	TenantID uuid.UUID
}

type Filter struct {
	From     time.Time
	To       time.Time
	SiteID   uuid.UUID
	NodeID   uuid.UUID
	Category Category
}

type ReadRequest struct {
	Scope        Scope
	Filter       Filter
	Limit        uint16
	SourceCursor string
	Snapshot     *analyticsrealtime.Snapshot
}

type ScopedAccessFact struct {
	TenantID uuid.UUID
	Log      analyticslog.AccessLog
}

type ReadPage struct {
	Facts            []ScopedAccessFact
	NextSourceCursor string
	Snapshot         analyticsrealtime.Snapshot
}

// FinalizedLatestStateReader must resolve the page and its snapshot atomically.
// When request.Snapshot is non-nil, implementations must read that exact snapshot.
type FinalizedLatestStateReader interface {
	ReadFinalizedLatest(context.Context, ReadRequest) (ReadPage, error)
}

type Item struct {
	EventID         string     `json:"event_id"`
	OccurredAt      time.Time  `json:"occurred_at"`
	SiteID          string     `json:"site_id"`
	NodeID          string     `json:"node_id"`
	Category        Category   `json:"category"`
	CauseCode       CauseCode  `json:"cause_code"`
	ActionCode      ActionCode `json:"action_code"`
	StatusCode      uint16     `json:"status_code"`
	ConfigVersionID string     `json:"config_version_id"`
	InstallationID  string     `json:"installation_id"`
	RequestID       string     `json:"request_id"`
	TaskID          *string    `json:"task_id"`
	TraceID         string     `json:"trace_id"`
}

type Response struct {
	Items             []Item                     `json:"items"`
	NextCursor        *string                    `json:"next_cursor"`
	Snapshot          analyticsrealtime.Snapshot `json:"snapshot"`
	EffectiveTenantID *string                    `json:"effective_tenant_id,omitempty"`
}

type Config struct {
	Now       func() time.Time
	CursorKey []byte
}

type Reader interface {
	Read(context.Context, Actor, Query) (Response, error)
}
