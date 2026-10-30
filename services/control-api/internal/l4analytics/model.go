package l4analytics

import (
	"context"
	"errors"
	"time"
)

const (
	Version        = "l4-realtime/v1"
	ReadPermission = "sites.read"
)

var (
	ErrInvalidConfig         = errors.New("L4 analytics configuration invalid")
	ErrInvalidRequest        = errors.New("L4 analytics request invalid")
	ErrInvalidCursor         = errors.New("L4 analytics cursor invalid")
	ErrPermissionDenied      = errors.New("L4 analytics permission denied")
	ErrDependencyUnavailable = errors.New("L4 analytics dependency unavailable")
	ErrInvalidResponse       = errors.New("L4 analytics response invalid")
)

type Audience string

const (
	AudienceTenant   Audience = "tenant"
	AudiencePlatform Audience = "platform"
)

type Actor struct {
	ScopeKind   string
	TenantID    string
	Permissions []string
}

type Query struct {
	Audience   Audience
	TenantID   string
	Range      string
	From       time.Time
	To         time.Time
	Timezone   string
	SiteID     string
	StreamID   string
	NodeID     string
	Protocol   string
	ListenPort uint16
	Limit      uint16
	Cursor     string
}

type Scope struct {
	TenantID string
}

type Snapshot struct {
	At               time.Time `json:"at"`
	SourceWatermark  uint64    `json:"source_watermark"`
	FinalizedThrough time.Time `json:"finalized_through"`
}

type After struct {
	Bucket     time.Time
	NodeID     string
	SiteID     string
	StreamID   string
	ListenerID string
}

type Filter struct {
	From       time.Time
	To         time.Time
	Timezone   string
	SiteID     string
	StreamID   string
	NodeID     string
	Protocol   string
	ListenPort uint16
	Limit      uint16
	Snapshot   Snapshot
	After      *After
}

type Row struct {
	Bucket     time.Time `json:"bucket"`
	NodeID     string    `json:"node_id"`
	SiteID     string    `json:"site_id"`
	StreamID   string    `json:"stream_id"`
	ListenerID string    `json:"listener_id"`
	Protocol   string    `json:"protocol"`
	ListenPort uint16    `json:"listen_port"`
	Sessions   uint64    `json:"sessions"`
	BytesUp    uint64    `json:"bytes_up"`
	BytesDown  uint64    `json:"bytes_down"`
	Errors     uint64    `json:"errors"`
}

type Page struct {
	Snapshot Snapshot
	Rows     []Row
	HasMore  bool
}

type Totals struct {
	Sessions  uint64 `json:"sessions"`
	BytesUp   uint64 `json:"bytes_up"`
	BytesDown uint64 `json:"bytes_down"`
	Errors    uint64 `json:"errors"`
}

type Meta struct {
	Range    string    `json:"range"`
	Timezone string    `json:"timezone"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Snapshot Snapshot  `json:"snapshot"`
}

type Response struct {
	Version    string `json:"version"`
	Meta       Meta   `json:"meta"`
	Totals     Totals `json:"totals"`
	Rows       []Row  `json:"rows"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type Source interface {
	Read(context.Context, Scope, Filter) (Page, error)
}

type Reader interface {
	Read(context.Context, Actor, Query) (Response, error)
}

type Config struct {
	Now       func() time.Time
	CursorKey []byte
}
