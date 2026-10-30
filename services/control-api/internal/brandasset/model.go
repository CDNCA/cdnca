package brandasset

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const schema = "cdnca.platform-brand-asset/v1"

type Slot string

const (
	SlotFavicon Slot = "favicon"
	SlotLogo    Slot = "logo"
	SlotLoginAd Slot = "login_ad"
	// ADR 0007 §7.2 theme brand slots.
	SlotLogoDark        Slot = "logo_dark"
	SlotLoginBackground Slot = "login_background"
	SlotAppIcon         Slot = "app_icon"
)

// Slots lists every brand slot in display order.
var Slots = []Slot{SlotFavicon, SlotLogo, SlotLoginAd, SlotLogoDark, SlotLoginBackground, SlotAppIcon}

func (slot Slot) Valid() bool {
	for _, known := range Slots {
		if slot == known {
			return true
		}
	}
	return false
}

type Clock func() time.Time

var (
	ErrInvalidInput        = errors.New("invalid platform brand asset input")
	ErrInvalidStore        = errors.New("invalid platform brand asset store")
	ErrPermissionDenied    = errors.New("platform brand asset permission denied")
	ErrRevisionConflict    = errors.New("platform brand asset revision conflict")
	ErrIdempotencyConflict = errors.New("platform brand asset idempotency conflict")
	ErrNotFound            = errors.New("platform brand asset not found")
	ErrUnavailable         = errors.New("platform brand asset unavailable")
	ErrUnsupportedMedia    = errors.New("platform brand asset media type is unsupported")
	ErrUnsafeContent       = errors.New("platform brand asset content is unsafe")
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type ObjectInfo struct {
	Size           int64
	SHA256         string
	ImmutableToken string
}

// ObjectStore is deliberately narrower than the edge-resource store. Brand
// assets are tiny, immutable objects and are only referenced after a
// successful database binding.
type ObjectStore interface {
	Put(context.Context, uuid.UUID, string, []byte, string) (ObjectInfo, error)
	Open(context.Context, uuid.UUID, string, string) (io.ReadCloser, error)
	Delete(context.Context, uuid.UUID, string) error
}

type PublicAsset struct {
	Asset
	Body io.ReadCloser
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Asset struct {
	Schema    string    `json:"schema"`
	Slot      Slot      `json:"slot"`
	Revision  int64     `json:"revision"`
	Reference string    `json:"reference,omitempty"`
	MIMEType  string    `json:"mime_type,omitempty"`
	SizeBytes int64     `json:"size_bytes,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type UploadRequest struct {
	ExpectedRevision int64
	Slot             Slot
	MIMEType         string
	Body             []byte
	IdempotencyKey   string
	RequestID        string
}

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	objects ObjectStore
	now     Clock
}

func Schema() string { return schema }
