package observabilitylog

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidConfig    = errors.New("observability log configuration is invalid")
	ErrInvalidInput     = errors.New("observability log input is invalid")
	ErrInvalidCursor    = errors.New("observability log cursor is invalid")
	ErrPermissionDenied = errors.New("observability log permission denied")
	ErrUnsafeFact       = errors.New("observability log fact is unsafe")
	ErrUnavailable      = errors.New("observability log dependency is unavailable")
)

const (
	ScopeTenant   = "tenant"
	ScopePlatform = "platform"
)

type Kind string

const (
	KindLogin        Kind = "login"
	KindOperation    Kind = "operation"
	KindNotification Kind = "notification"
	KindFrontend     Kind = "frontend"
)

type Actor struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	SessionID   uuid.UUID
	Permissions []string
	RequestID   string
	SourceIP    string
}

type Query struct {
	TargetScopeID        *uuid.UUID
	AuditActorUserID     *uuid.UUID
	CaptureAuditBoundary bool
	AfterAuditBoundary   string
	Kinds                []Kind
	ResultCodes          []string
	Action               string
	ActionVerb           string
	ActorUserDisplayID   string
	Category             string
	ResourceType         string
	ResourceID           string
	Change               string
	SourceIP             string
	From                 time.Time
	To                   time.Time
	Limit                int
	Cursor               string
}

// Fact.Category is the audit catalog category of an audit row (empty for
// notification facts); Query.Category filters on it (the log page's 类别).
type Fact struct {
	ID                 string     `json:"event_id"`
	ScopeID            uuid.UUID  `json:"scope_id,omitempty"`
	Kind               Kind       `json:"kind"`
	ActorUserID        *uuid.UUID `json:"actor_user_id,omitempty"`
	ActorUserDisplayID string     `json:"actor_user_display_id,omitempty"`
	SubjectUserID      string     `json:"subject_user_id,omitempty"`
	Action             string     `json:"action"`
	ReasonCode         string     `json:"reason_code"`
	ResultCode         string     `json:"result_code"`
	ResourceType       string     `json:"resource_type,omitempty"`
	ResourceID         string     `json:"resource_id,omitempty"`
	// ResourceName is the object's current name (site domain, node name, ...)
	// looked up at query time; ResourceDeleted marks a nameable object that no
	// longer exists in the row's scope (tp-b6b). Both empty: the resource type
	// has no name lookup, show resource_id.
	ResourceName    string `json:"resource_name,omitempty"`
	ResourceDeleted bool   `json:"resource_deleted,omitempty"`
	UserAgent          string     `json:"user_agent,omitempty"`
	ChangeSummary      string     `json:"change_summary,omitempty"`
	RequestID          string     `json:"request_id,omitempty"`
	SourceIP           string     `json:"source_ip"`
	GeoCode            string     `json:"geo_code"`
	GeoRegion          string     `json:"geo_region,omitempty"`
	GeoCity            string     `json:"geo_city,omitempty"`
	GeoResolution      string     `json:"geo_resolution,omitempty"`
	OccurredAt         time.Time  `json:"occurred_at"`
	Category           string     `json:"category,omitempty"`
	TotalCount         int64      `json:"-"`
}

type Page struct {
	Items         []Fact    `json:"items"`
	NextCursor    string    `json:"next_cursor,omitempty"`
	SnapshotAt    time.Time `json:"snapshot_at"`
	TotalCount    int64     `json:"total_count"`
	AuditBoundary string    `json:"audit_boundary,omitempty"`
}

type AuditBoundary struct {
	Token      string
	SnapshotAt time.Time
}

type ExportArtifact struct {
	Content []byte
	SHA256  string
}

type FrontendInput struct {
	EventCode  string `json:"event_code"`
	Route      string `json:"route"`
	ReasonCode string `json:"reason_code"`
	ResultCode string `json:"result_code"`
	Release    string `json:"release"`
}

type FrontendFact struct {
	ScopeID    uuid.UUID
	ActorID    uuid.UUID
	RequestID  string
	SourceIP   string
	EventCode  string
	Route      string
	ReasonCode string
	ResultCode string
	Release    string
}

type StoreQuery struct {
	ScopeID              uuid.UUID
	ActorUserID          *uuid.UUID
	ExactActorUserID     *uuid.UUID
	ActorUserDisplayID   string
	AuditBound           bool
	AuditAfterPosition   int64
	AuditThroughPosition int64
	Kinds                []Kind
	ResultCodes          []string
	Action               string
	ActionVerb           string
	Category             string
	ResourceType         string
	ResourceID           string
	Change               string
	SourceIP             string
	From                 time.Time
	To                   time.Time
	SnapshotAt           time.Time
	BeforeTime           time.Time
	BeforeID             string
	Limit                int
}

type Repository interface {
	ListFacts(context.Context, StoreQuery) ([]Fact, error)
	AuditHead(context.Context, uuid.UUID) (int64, error)
	AppendFrontend(context.Context, FrontendFact) error
}

// ResourceRef is one nameable object a log page references.
type ResourceRef struct {
	Type string
	ID   uuid.UUID
}

// ResourceNamer is an optional Repository capability: the names of refs that
// still exist in scopeID, in one query per page. Missing keys = deleted.
type ResourceNamer interface {
	ResourceNames(ctx context.Context, scopeID uuid.UUID, refs []ResourceRef) (map[ResourceRef]string, error)
}

type Domain interface {
	CaptureAuditBoundary(context.Context, Actor, uuid.UUID) (AuditBoundary, error)
	List(context.Context, Actor, Query) (Page, error)
	Export(context.Context, Actor, Query) (ExportArtifact, error)
	RecordFrontend(context.Context, Actor, FrontendInput) error
}
