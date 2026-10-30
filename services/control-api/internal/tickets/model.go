// Package tickets is the support ticket system (1.0.35 G6 #9, migration
// 302_tickets). Customers file tickets in their tenant scope and only ever
// see their own; platform staff with tickets.read / tickets.manage see and
// work all of them. Customer-visible events (created, staff reply, status
// change) go through the notification outbox under the existing event
// policies and the customer's own subscriptions.
package tickets

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	PermissionRead   = "tickets.read"
	PermissionManage = "tickets.manage"

	EventCreated       = "ticket.created"
	EventReplied       = "ticket.replied"
	EventStatusChanged = "ticket.status_changed"
	// Operator side: platform members holding tickets.manage.
	EventStaffCreated = "ticket.staff.created"
	EventStaffReplied = "ticket.staff.replied"
	// EventStaffOverdue (546): no staff reply within ResponseSLA.
	EventStaffOverdue = "ticket.staff.overdue"

	StatusOpen            = "open"
	StatusProcessing      = "processing"
	StatusPendingCustomer = "pending_customer"
	StatusResolved        = "resolved"
	StatusClosed          = "closed"

	AuthorCustomer = "customer"
	AuthorStaff    = "staff"

	// Ticket event kinds (migration 543): system lines in the detail.
	EventKindStatus   = "status"
	EventKindPriority = "priority"
	EventKindAssignee = "assignee" // staff only
	EventKindClosed   = "closed"
	EventKindReopened = "reopened"

	MaxSubjectRunes   = 200
	MaxBodyRunes      = 20000
	MaxAttachments    = 5
	MaxAttachmentSize = 1 << 20
	// MaxPendingUploads caps unbound uploads per user within PendingUploadWindow.
	MaxPendingUploads   = 20
	PendingUploadWindow = 24 * time.Hour
	// ReopenWindow is how long a customer may reopen a resolved or closed ticket.
	ReopenWindow = 7 * 24 * time.Hour
	// ResponseSLA flags tickets still waiting for the first staff reply.
	ResponseSLA = 24 * time.Hour

	DefaultPageSize = 20
	MaxPageSize     = 100
)

var (
	Statuses   = []string{StatusOpen, StatusProcessing, StatusPendingCustomer, StatusResolved, StatusClosed}
	Categories = []string{"technical", "billing", "account", "abuse", "other"}
	Priorities = []string{"low", "normal", "high", "urgent"}

	// AttachmentTypes are the accepted MIME types; the body must sniff as the
	// declared type.
	AttachmentTypes = []string{"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain"}

	statusLabels = map[string]string{StatusOpen: "待处理", StatusProcessing: "处理中",
		StatusPendingCustomer: "待用户回复", StatusResolved: "已解决", StatusClosed: "已关闭"}
)

var (
	ErrInvalidInput        = errors.New("ticket invalid input")
	ErrNotFound            = errors.New("ticket not found")
	ErrUnauthenticated     = errors.New("ticket authentication required")
	ErrPermissionDenied    = errors.New("ticket permission denied")
	ErrRevisionConflict    = errors.New("ticket revision conflict")
	ErrIdempotency         = errors.New("ticket idempotency key reused with a different request")
	ErrInvalidState        = errors.New("ticket state does not allow this action")
	ErrReopenExpired       = errors.New("ticket reopen window has passed")
	ErrAttachmentsDisabled = errors.New("ticket attachments are not configured")
	ErrAttachmentRejected  = errors.New("ticket attachment rejected")
	ErrAttachmentTooLarge  = errors.New("ticket attachment too large")
	ErrAttachmentType      = errors.New("ticket attachment type is not allowed")
	ErrUploadLimit         = errors.New("too many pending ticket attachments")
	ErrUnavailable         = errors.New("ticket service unavailable")
)

// Actor is the authenticated caller. Staff are platform-scope sessions; the
// handler decides which surface (customer or admin) a request uses.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
}

type Ticket struct {
	ID             string    `json:"id"`
	TicketNo       int64     `json:"ticket_no"`
	TenantScopeID  string    `json:"tenant_scope_id,omitempty"`
	UserID         string    `json:"user_id,omitempty"`
	Username       string    `json:"username,omitempty"`
	Category       string    `json:"category"`
	Subject        string    `json:"subject"`
	Priority       string    `json:"priority"`
	Status         string    `json:"status"`
	AssigneeUserID string    `json:"assignee_user_id,omitempty"`
	AssigneeName   string    `json:"assignee_name,omitempty"`
	SiteID         string    `json:"site_id,omitempty"`
	SiteDomain     string    `json:"site_domain,omitempty"`
	OrderID        string    `json:"order_id,omitempty"`
	Unread         bool      `json:"unread"`
	SLABreached    bool      `json:"sla_breached,omitempty"`
	Revision       int64     `json:"revision"`
	LastMessageAt  time.Time `json:"last_message_at"`
	// LastReplyAuthor / LastReplyAuthorKind: display name and kind (customer
	// / staff) of the newest message the viewer can see; list only.
	LastReplyAuthor     string     `json:"last_reply_author,omitempty"`
	LastReplyAuthorKind string     `json:"last_reply_author_kind,omitempty"`
	FirstResponseAt     *time.Time `json:"first_response_at,omitempty"`
	ResolvedAt          *time.Time `json:"resolved_at,omitempty"`
	ClosedAt            *time.Time `json:"closed_at,omitempty"`
	ReopenableUntil     *time.Time `json:"reopenable_until,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type Message struct {
	ID          string       `json:"id"`
	AuthorKind  string       `json:"author_kind"`
	AuthorName  string       `json:"author_name"`
	Body        string       `json:"body"`
	Internal    bool         `json:"internal,omitempty"`
	Attachments []Attachment `json:"attachments"`
	CreatedAt   time.Time    `json:"created_at"`
}

// Attachment never carries the object key or storage token.
type Attachment struct {
	ID        string    `json:"id"`
	FileName  string    `json:"file_name"`
	MIMEType  string    `json:"mime_type"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// Event is one change of a ticket (migration 543), shown as a centered
// system line. For assignee events From / To are the assignee names ("" =
// none); otherwise they are the status or priority values.
type Event struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	ActorKind string    `json:"actor_kind"`
	ActorName string    `json:"actor_name"`
	CreatedAt time.Time `json:"created_at"`
}

type Detail struct {
	Ticket   Ticket    `json:"ticket"`
	Messages []Message `json:"messages"`
	Events   []Event   `json:"events"`
}

type Page struct {
	Items  []Ticket `json:"items"`
	Total  int64    `json:"total"`
	Limit  int      `json:"limit"`
	Offset int      `json:"offset"`
}

type CreateInput struct {
	Category      string   `json:"category"`
	Subject       string   `json:"subject"`
	Body          string   `json:"body"`
	Priority      string   `json:"priority,omitempty"`
	SiteID        string   `json:"site_id,omitempty"`
	OrderID       string   `json:"order_id,omitempty"`
	AttachmentIDs []string `json:"attachment_ids,omitempty"`
}

// StaffCreateInput (fix-ticket2) is a ticket staff open on a user's behalf;
// Body is the first staff message, AssigneeUserID an optional handler
// (defaults to the creating staff member).
type StaffCreateInput struct {
	UserID         string `json:"user_id"`
	Category       string `json:"category"`
	Subject        string `json:"subject"`
	Body           string `json:"body"`
	Priority       string `json:"priority,omitempty"`
	AssigneeUserID string `json:"assignee_user_id,omitempty"`
}

type ReplyInput struct {
	Body          string   `json:"body"`
	AttachmentIDs []string `json:"attachment_ids,omitempty"`
	// Internal (staff only) records a note the customer never sees.
	Internal bool `json:"internal,omitempty"`
}

// UpdateInput is the staff PATCH. AssigneeUserID "" unassigns.
type UpdateInput struct {
	ExpectedRevision int64   `json:"expected_revision"`
	Status           *string `json:"status,omitempty"`
	Priority         *string `json:"priority,omitempty"`
	AssigneeUserID   *string `json:"assignee_user_id,omitempty"`
}

type Filter struct {
	Status         string
	Category       string
	Priority       string
	AssigneeUserID string // user id, "me" or "none"
	UserID         string
	Query          string // ticket number or subject substring
	SLABreached    bool
	Limit          int
	Offset         int
}

type Summary struct {
	Unread int64 `json:"unread"`
	// Staff only.
	Pending     int64 `json:"pending,omitempty"`
	Mine        int64 `json:"mine,omitempty"`
	SLABreached int64 `json:"sla_breached,omitempty"`
}

type Assignee struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type UploadInput struct {
	FileName string
	MIMEType string
	Body     []byte
}

// ObjectStore keeps attachment bodies. Keys are only ever built here.
type ObjectStore interface {
	Put(ctx context.Context, scopeID uuid.UUID, key string, body []byte, mimeType string) (immutableToken string, err error)
	Open(ctx context.Context, scopeID uuid.UUID, key, immutableToken string) (io.ReadCloser, error)
	// Delete removes the object; a missing object is not an error.
	Delete(ctx context.Context, scopeID uuid.UUID, key string) error
}

// Scanner rejects malicious attachments (ClamAV in production). A rejection
// must wrap ErrAttachmentRejected; any other error means the scan could not run.
type Scanner interface {
	Scan(ctx context.Context, body []byte) error
}

// Notifier is notification.Store.
type Notifier interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

type Download struct {
	Attachment
	Body io.ReadCloser
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
