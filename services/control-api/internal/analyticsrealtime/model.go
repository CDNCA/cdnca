package analyticsrealtime

import (
	"context"
	"errors"
	"time"
)

const (
	Version        = "site-monitoring/v2"
	ReadPermission = "sites.read"
)

var (
	ErrInvalidConfig         = errors.New("analytics realtime configuration invalid")
	ErrInvalidRequest        = errors.New("analytics realtime request invalid")
	ErrPermissionDenied      = errors.New("analytics realtime permission denied")
	ErrScopeForbidden        = errors.New("analytics realtime scope forbidden")
	ErrInvalidSnapshot       = errors.New("analytics realtime snapshot invalid")
	ErrInvalidResponse       = errors.New("analytics realtime response invalid")
	ErrInvalidCursor         = errors.New("analytics realtime cursor invalid")
	ErrDependencyUnavailable = errors.New("analytics realtime dependency unavailable")
	ErrFactsMissing          = errors.New("analytics realtime authoritative facts missing")
	ErrUnavailable           = errors.New("analytics realtime unavailable")
	ErrInvalidInput          = ErrInvalidRequest
)

const (
	ReasonDependencyUnavailable = "dependency_unavailable"
	ReasonAuthoritativeMissing  = "authoritative_fact_missing"
)

type Audience string

const (
	AudiencePlatform Audience = "platform"
	AudienceTenant   Audience = "tenant"
)

type RankDimension string

const (
	RankByHost       RankDimension = "host"
	RankBySite       RankDimension = "site"
	RankByNode       RankDimension = "node"
	RankByStatusCode RankDimension = "status_code"
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
	NodeID     string
	Domain     string
	ListenPort uint16
	RankBy     RankDimension
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
	ExpiresAt        time.Time `json:"expires_at"`
}

type RankAfter struct {
	TrafficBytes uint64
	Requests     uint64
	Key          string
}

type Filter struct {
	From       time.Time
	To         time.Time
	Timezone   string
	SiteID     string
	NodeID     string
	Domain     string
	ListenPort uint16
	Bucket     time.Duration
	Snapshot   Snapshot
	RankBy     RankDimension
	Limit      uint16
	After      *RankAfter
}

type BasicPoint struct {
	Bucket       time.Time `json:"bucket"`
	Requests     uint64    `json:"requests"`
	TrafficBytes uint64    `json:"traffic_bytes"`
	BandwidthBPS float64   `json:"bandwidth_bps"`
	Connections  uint64    `json:"connections"`
}

type Basic struct {
	FactCount    uint64       `json:"fact_count"`
	Requests     uint64       `json:"requests"`
	TrafficBytes uint64       `json:"traffic_bytes"`
	BandwidthBPS float64      `json:"bandwidth_bps"`
	Connections  uint64       `json:"connections"`
	Series       []BasicPoint `json:"series"`
}

type QualityPoint struct {
	Bucket    time.Time `json:"bucket"`
	Status2xx uint64    `json:"status_2xx"`
	Status3xx uint64    `json:"status_3xx"`
	Status4xx uint64    `json:"status_4xx"`
	Status5xx uint64    `json:"status_5xx"`
}

type Quality struct {
	FactCount         uint64         `json:"fact_count"`
	Status2xx         uint64         `json:"status_2xx"`
	Status3xx         uint64         `json:"status_3xx"`
	Status4xx         uint64         `json:"status_4xx"`
	Status5xx         uint64         `json:"status_5xx"`
	CacheHits         uint64         `json:"cache_hits"`
	CacheMisses       uint64         `json:"cache_misses"`
	Errors            uint64         `json:"errors"`
	AverageDurationUS float64        `json:"average_duration_us"`
	Series            []QualityPoint `json:"series"`
}

type OriginPoint struct {
	Bucket      time.Time `json:"bucket"`
	ConnectUS   float64   `json:"connect_us"`
	FirstByteUS float64   `json:"first_byte_us"`
	TotalUS     float64   `json:"total_us"`
}

type Origin struct {
	FactCount   uint64        `json:"fact_count"`
	ConnectUS   float64       `json:"connect_us"`
	FirstByteUS float64       `json:"first_byte_us"`
	TotalUS     float64       `json:"total_us"`
	Series      []OriginPoint `json:"series"`
}

type RankItem struct {
	Key          string `json:"key"`
	Label        string `json:"label"`
	Requests     uint64 `json:"requests"`
	TrafficBytes uint64 `json:"traffic_bytes"`
}

type Rank struct {
	FactCount  uint64     `json:"fact_count"`
	Dimension  string     `json:"dimension"`
	Items      []RankItem `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

type RankResult struct {
	FactCount uint64
	Items     []RankItem
	HasMore   bool
}

type Section[T any] struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Value     *T     `json:"value,omitempty"`
}

type Meta struct {
	Range      string        `json:"range"`
	Timezone   string        `json:"timezone"`
	From       time.Time     `json:"from"`
	To         time.Time     `json:"to"`
	Bucket     time.Duration `json:"bucket"`
	Downsample bool          `json:"downsample"`
	Snapshot   Snapshot      `json:"snapshot"`
}

type Response struct {
	Version string           `json:"version"`
	Meta    Meta             `json:"meta"`
	Basic   Section[Basic]   `json:"basic"`
	Quality Section[Quality] `json:"quality"`
	Origin  Section[Origin]  `json:"origin"`
	Rank    Section[Rank]    `json:"rank"`
}

type Source interface {
	ResolveSnapshot(context.Context, Scope, Filter) (Snapshot, error)
	LoadBasic(context.Context, Scope, Filter) (Basic, error)
	LoadQuality(context.Context, Scope, Filter) (Quality, error)
	LoadOrigin(context.Context, Scope, Filter) (Origin, error)
	LoadRank(context.Context, Scope, Filter) (RankResult, error)
}

type Config struct {
	Now       func() time.Time
	CursorKey []byte
}

type Reader interface {
	Read(context.Context, Actor, Query) (Response, error)
}
