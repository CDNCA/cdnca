package announcement

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid announcement input")
	ErrInvalidContent      = errors.New("invalid announcement content")
	ErrInvalidAudience     = errors.New("invalid announcement audience")
	ErrInvalidCursor       = errors.New("invalid announcement cursor")
	ErrInvalidStore        = errors.New("invalid announcement store")
	ErrPermissionDenied    = errors.New("announcement permission denied")
	ErrAudienceScopeDenied = errors.New("announcement audience scope denied")
	ErrEmptyAudience       = errors.New("announcement audience resolves to no active users")
	ErrNotFound            = errors.New("announcement not found")
	ErrRevisionConflict    = errors.New("announcement revision conflict")
	ErrInvalidTransition   = errors.New("invalid announcement transition")
	ErrIdempotencyConflict = errors.New("announcement idempotency conflict")
)

const (
	MaxTitleRunes           = 160
	MaxBodyBytes            = 64 * 1024
	MaxAudienceTargets      = 10_000
	MaxPageSize             = 100
	DefaultPageSize         = 20
	StatusDraft             = "draft"
	StatusScheduled         = "scheduled"
	StatusPublished         = "published"
	StatusWithdrawn         = "withdrawn"
	StatusArchived          = "archived"
	VisibilityRetain        = "retain"
	VisibilityHide          = "hide"
	permissionManage        = "announcements.manage"
	permissionRead          = "announcements.read"
	operationCreate         = "announcement.create"
	operationUpdate         = "announcement.update"
	operationSchedule       = "announcement.schedule"
	operationPublish        = "announcement.publish"
	operationRevise         = "announcement.revise"
	operationWithdraw       = "announcement.withdraw"
	operationArchive        = "announcement.archive"
	operationRestore        = "announcement.restore"
	operationDeliver        = "announcement.deliver"
	operationRead           = "announcement.read"
	operationGlobalCreate   = "announcement.global.create"
	operationGlobalUpdate   = "announcement.global.update"
	operationGlobalPublish  = "announcement.global.publish"
	operationGlobalWithdraw = "announcement.global.withdraw"
	operationGlobalArchive  = "announcement.global.archive"
	operationGlobalRestore  = "announcement.global.restore"
)

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

// PublicationOutbox is the transactional integration boundary. An adapter may
// bridge this notice to migration 029; this package does not duplicate its facts.
type PublicationOutbox interface {
	EnqueuePublication(context.Context, pgx.Tx, PublicationNotice) error
}

type NoopPublicationOutbox struct{}

func (NoopPublicationOutbox) EnqueuePublication(context.Context, pgx.Tx, PublicationNotice) error {
	return nil
}

type PublicationNotice struct {
	ScopeID        uuid.UUID
	AnnouncementID uuid.UUID
	Version        int64
	Title          string
	Body           string
	PublishedAt    time.Time
	RecipientIDs   []uuid.UUID
	InboxEventIDs  []uuid.UUID
}

type Actor struct {
	ScopeID   uuid.UUID
	UserID    uuid.UUID
	SessionID uuid.UUID
}

// TxAuthorizer is the narrow IAM boundary for announcement operations. The
// implementation owns session, tenant, membership, role and permission locks;
// announcement code only supplies the authenticated actor and required grant.
type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, string) error
}

type Content struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// Presentation is the CDNCA-compatible announcement display configuration.
type Presentation struct {
	Format    string `json:"format"`
	LinkURL   string `json:"link_url"`
	SortOrder int64  `json:"sort_order"`
	Visible   bool   `json:"visible"`
	Popup     bool   `json:"popup"`
	Red       bool   `json:"red"`
	Bold      bool   `json:"bold"`
}

type Audience struct {
	All      bool        `json:"all"`
	UserIDs  []uuid.UUID `json:"user_ids,omitempty"`
	GroupIDs []uuid.UUID `json:"group_ids,omitempty"`
}

type GlobalRoleTarget struct {
	ScopeID uuid.UUID `json:"scope_id"`
	RoleID  uuid.UUID `json:"role_id"`
}

type GlobalUserTarget struct {
	ScopeID uuid.UUID `json:"scope_id"`
	UserID  uuid.UUID `json:"user_id"`
}

type GlobalAudience struct {
	AllTenants     bool               `json:"all_tenants"`
	TenantScopeIDs []uuid.UUID        `json:"tenant_scope_ids"`
	RoleTargets    []GlobalRoleTarget `json:"role_targets"`
	UserTargets    []GlobalUserTarget `json:"user_targets"`
}

type GlobalAnnouncement struct {
	ID                   uuid.UUID      `json:"id"`
	PlatformScopeID      uuid.UUID      `json:"platform_scope_id"`
	Version              int64          `json:"version"`
	Revision             int64          `json:"revision"`
	Status               string         `json:"status"`
	Title                string         `json:"title"`
	Body                 string         `json:"body"`
	Format               string         `json:"format"`
	LinkURL              string         `json:"link_url,omitempty"`
	SortOrder            int64          `json:"sort_order"`
	Visible              bool           `json:"visible"`
	Popup                bool           `json:"popup"`
	Red                  bool           `json:"red"`
	Bold                 bool           `json:"bold"`
	Audience             GlobalAudience `json:"audience"`
	WithdrawalVisibility string         `json:"withdrawal_visibility"`
	RecipientCount       int64          `json:"recipient_count"`
	PublishedAt          *time.Time     `json:"published_at,omitempty"`
	WithdrawnAt          *time.Time     `json:"withdrawn_at,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	StateChangedAt       time.Time      `json:"state_changed_at"`
	Archived             bool           `json:"archived"`
	LifecycleRevision    int64          `json:"lifecycle_revision"`
	ArchivedAt           *time.Time     `json:"archived_at,omitempty"`
	Replayed             bool           `json:"replayed,omitempty"`
}

type CreateGlobalDraftRequest struct {
	Content
	Presentation
	Audience             GlobalAudience `json:"audience"`
	WithdrawalVisibility string         `json:"withdrawal_visibility"`
	IdempotencyKey       string         `json:"idempotency_key"`
	RequestID            string         `json:"request_id"`
}

type UpdateGlobalDraftRequest struct {
	AnnouncementID   uuid.UUID `json:"announcement_id"`
	ExpectedRevision int64     `json:"expected_revision"`
	Content
	Presentation
	Audience             GlobalAudience `json:"audience"`
	WithdrawalVisibility string         `json:"withdrawal_visibility"`
	IdempotencyKey       string         `json:"idempotency_key"`
	RequestID            string         `json:"request_id"`
}

type GlobalTransitionRequest struct {
	AnnouncementID   uuid.UUID `json:"announcement_id"`
	ExpectedRevision int64     `json:"expected_revision"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestID        string    `json:"request_id"`
}

type GlobalAnnouncementPage struct {
	Items      []GlobalAnnouncement `json:"items"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

type Announcement struct {
	ID                   uuid.UUID  `json:"id"`
	ScopeID              uuid.UUID  `json:"scope_id"`
	Version              int64      `json:"version"`
	HeadVersion          int64      `json:"head_version"`
	Revision             int64      `json:"revision"`
	Status               string     `json:"status"`
	Title                string     `json:"title"`
	Body                 string     `json:"body"`
	Format               string     `json:"format"`
	LinkURL              string     `json:"link_url,omitempty"`
	SortOrder            int64      `json:"sort_order"`
	Visible              bool       `json:"visible"`
	Popup                bool       `json:"popup"`
	Red                  bool       `json:"red"`
	Bold                 bool       `json:"bold"`
	Audience             Audience   `json:"audience"`
	WithdrawalVisibility string     `json:"withdrawal_visibility"`
	ScheduledAt          *time.Time `json:"scheduled_at,omitempty"`
	PublishedAt          *time.Time `json:"published_at,omitempty"`
	WithdrawnAt          *time.Time `json:"withdrawn_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	StateChangedAt       time.Time  `json:"state_changed_at"`
	Archived             bool       `json:"archived"`
	LifecycleRevision    int64      `json:"lifecycle_revision"`
	ArchivedAt           *time.Time `json:"archived_at,omitempty"`
	Replayed             bool       `json:"replayed,omitempty"`
}

type CreateDraftRequest struct {
	Content
	Presentation
	Audience
	WithdrawalVisibility string `json:"withdrawal_visibility"`
	IdempotencyKey       string `json:"idempotency_key"`
	RequestID            string `json:"request_id"`
}

type UpdateDraftRequest struct {
	AnnouncementID   uuid.UUID `json:"announcement_id"`
	Version          int64     `json:"version"`
	ExpectedRevision int64     `json:"expected_revision"`
	Content
	Presentation
	Audience
	WithdrawalVisibility string `json:"withdrawal_visibility"`
	IdempotencyKey       string `json:"idempotency_key"`
	RequestID            string `json:"request_id"`
}

type ScheduleRequest struct {
	AnnouncementID   uuid.UUID `json:"announcement_id"`
	Version          int64     `json:"version"`
	ExpectedRevision int64     `json:"expected_revision"`
	PublishAt        time.Time `json:"publish_at"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestID        string    `json:"request_id"`
}

type PublishRequest struct {
	AnnouncementID   uuid.UUID `json:"announcement_id"`
	Version          int64     `json:"version"`
	ExpectedRevision int64     `json:"expected_revision"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestID        string    `json:"request_id"`
}

type ReviseRequest struct {
	AnnouncementID      uuid.UUID `json:"announcement_id"`
	ExpectedHeadVersion int64     `json:"expected_head_version"`
	Content
	Presentation
	Audience
	WithdrawalVisibility string `json:"withdrawal_visibility"`
	IdempotencyKey       string `json:"idempotency_key"`
	RequestID            string `json:"request_id"`
}

type WithdrawRequest struct {
	AnnouncementID   uuid.UUID `json:"announcement_id"`
	Version          int64     `json:"version"`
	ExpectedRevision int64     `json:"expected_revision"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestID        string    `json:"request_id"`
}

type ArchiveRequest struct {
	AnnouncementID            uuid.UUID `json:"announcement_id"`
	ExpectedLifecycleRevision int64     `json:"expected_lifecycle_revision"`
	IdempotencyKey            string    `json:"idempotency_key"`
	RequestID                 string    `json:"request_id"`
}

type RestoreRequest struct {
	AnnouncementID            uuid.UUID `json:"announcement_id"`
	ExpectedLifecycleRevision int64     `json:"expected_lifecycle_revision"`
	IdempotencyKey            string    `json:"idempotency_key"`
	RequestID                 string    `json:"request_id"`
}

type StateRequest struct {
	EventID          uuid.UUID `json:"event_id"`
	ExpectedRevision int64     `json:"expected_revision"`
	IdempotencyKey   string    `json:"idempotency_key"`
	RequestID        string    `json:"request_id"`
}

type InboxState struct {
	EventID     uuid.UUID  `json:"event_id"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	ReadAt      *time.Time `json:"read_at,omitempty"`
	Revision    int64      `json:"revision"`
	Replayed    bool       `json:"replayed,omitempty"`
}

type InboxMessage struct {
	ID                  uuid.UUID  `json:"id"`
	AnnouncementID      uuid.UUID  `json:"announcement_id"`
	AnnouncementVersion int64      `json:"announcement_version"`
	Title               string     `json:"title"`
	Body                string     `json:"body"`
	Format              string     `json:"format"`
	LinkURL             string     `json:"link_url,omitempty"`
	SortOrder           int64      `json:"sort_order"`
	Visible             bool       `json:"visible"`
	Popup               bool       `json:"popup"`
	Red                 bool       `json:"red"`
	Bold                bool       `json:"bold"`
	PublishedAt         time.Time  `json:"published_at"`
	DeliveredAt         *time.Time `json:"delivered_at,omitempty"`
	ReadAt              *time.Time `json:"read_at,omitempty"`
	StateRevision       int64      `json:"state_revision"`
}

type ListRequest struct {
	Limit  int
	Cursor string
	// Offset pages by position (tp-b7 页码分页); it cannot be combined with
	// Cursor and is capped at MaxInboxOffset.
	Offset int
	// ReadFilter: "", "unread", "read" or "popup" (unread popup announcements).
	ReadFilter string
}

// MaxInboxOffset bounds page-number access to the inbox.
const MaxInboxOffset = 10000

type InboxPage struct {
	Items      []InboxMessage `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
	// Total counts every message matching the filter; it is only returned
	// for a first page or an offset page (never alongside a cursor).
	Total *int `json:"total,omitempty"`
}

type AnnouncementListRequest struct {
	Limit  int
	Cursor string
	Status string
}

type AnnouncementPage struct {
	Items      []Announcement `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}
