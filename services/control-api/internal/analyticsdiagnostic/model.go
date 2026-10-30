package analyticsdiagnostic

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

const (
	DefaultLimit = uint16(20)
	MaxLimit     = uint16(100)
)

var (
	ErrInvalidConfiguration = errors.New("invalid analytics diagnostic configuration")
	ErrInvalidInput         = errors.New("invalid analytics diagnostic input")
	ErrPermissionDenied     = errors.New("analytics diagnostic permission denied")
	ErrScopeForbidden       = errors.New("analytics diagnostic scope forbidden")
	ErrEvidenceUnavailable  = errors.New("analytics diagnostic evidence unavailable")
	ErrInvalidResponse      = errors.New("invalid analytics diagnostic response")
)

type Actor = analyticslog.Actor
type Audience = analyticslog.Audience

const (
	AudiencePlatform = analyticslog.AudiencePlatform
	AudienceTenant   = analyticslog.AudienceTenant
)

type Category string

const (
	CategoryUpstream5xx    Category = "upstream_5xx"
	CategoryConfigMismatch Category = "config_mismatch"
	CategoryNoHost         Category = "no_host"
	CategoryUnknown        Category = "unknown"
)

type ReasonCode string

const (
	ReasonUpstreamNoHost         ReasonCode = "upstream_reported_no_host"
	ReasonHostMissing            ReasonCode = "host_missing"
	ReasonUpstreamConfigMismatch ReasonCode = "upstream_reported_config_mismatch"
	ReasonStatus530              ReasonCode = "status_530"
	ReasonStatus5xxWithUpstream  ReasonCode = "status_5xx_with_upstream_result"
	ReasonStatus5xxUnclassified  ReasonCode = "status_5xx_unclassified"
)

type QueryRequest struct {
	Audience Audience
	TenantID string
	From     time.Time
	To       time.Time
	SiteID   string
	NodeID   string
	Limit    uint16
	Cursor   string
}

type Item struct {
	EventID         string     `json:"event_id"`
	OccurredAt      time.Time  `json:"occurred_at"`
	SiteID          string     `json:"site_id"`
	NodeID          string     `json:"node_id"`
	RequestID       string     `json:"request_id"`
	TraceID         string     `json:"trace_id"`
	ConfigVersionID string     `json:"config_version_id"`
	Host            string     `json:"host"`
	URIPath         string     `json:"uri_path"`
	StatusCode      uint16     `json:"status_code"`
	Category        Category   `json:"category"`
	ReasonCode      ReasonCode `json:"reason_code"`
}

type Page struct {
	Items      []Item     `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
	SnapshotAt *time.Time `json:"snapshot_at"`
}

type AccessSource interface {
	ReadAccess(context.Context, Actor, QueryRequest) (analyticslog.AccessPage, error)
}
