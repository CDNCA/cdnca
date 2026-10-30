package rangecache

import (
	"context"
	"crypto/sha256"
	"errors"
)

const (
	SchemaVersion = "cdnca.edge.range-cache/v1"

	MaxPolicyBytes           = 256 << 10
	MaxPolicyVersion         = 1<<53 - 1
	MaxSites                 = 64
	MaxHostsPerSite          = 32
	MaxIdentifierBytes       = 128
	MaxHostBytes             = 253
	MinSliceBytes      int64 = 64 << 10
	MaxSliceBytes      int64 = 16 << 20
	MaxCacheBytes      int64 = 1 << 40
	MaxCacheSeconds          = 7 * 24 * 60 * 60
	MinHeaderBytes           = 1024
	MaxHeaderBytes           = 64 << 10
	MaxRanges                = 16
	MaxRangeSpanBytes        = 64 << 20
)

var (
	ErrInvalidPolicy = errors.New("invalid range cache policy")
	ErrPrecheck      = errors.New("range cache configuration precheck failed")
	ErrReload        = errors.New("range cache configuration reload failed")
	ErrHealth        = errors.New("range cache configuration health check failed")
	ErrRollback      = errors.New("range cache configuration rollback failed")
)

type Policy struct {
	SchemaVersion          string `json:"schema_version"`
	PolicyVersion          uint64 `json:"policy_version"`
	SliceBytes             int64  `json:"slice_bytes"`
	CacheMaxBytes          int64  `json:"cache_max_bytes"`
	CacheInactiveSeconds   uint32 `json:"cache_inactive_seconds"`
	CacheValidSeconds      uint32 `json:"cache_valid_seconds"`
	MaxRangeHeaderBytes    uint32 `json:"max_range_header_bytes"`
	MaxIfRangeHeaderBytes  uint32 `json:"max_if_range_header_bytes"`
	MaxResponseHeaderBytes uint32 `json:"max_response_header_bytes"`
	Sites                  []Site `json:"sites"`
}

type Site struct {
	SiteID        string   `json:"site_id"`
	ListenAddress string   `json:"listen_address"`
	ListenPort    uint16   `json:"listen_port"`
	Hosts         []string `json:"hosts"`
	OriginHost    string   `json:"origin_host"`
	OriginPort    uint16   `json:"origin_port"`
}

type RuntimePaths struct {
	StateRoot string
	LuaRoot   string
}

type Artifact struct {
	PolicyVersion   uint64
	CanonicalPolicy []byte
	Nginx           []byte
	Digest          [sha256.Size]byte
}

type Publication struct {
	PolicyVersion uint64
	Digest        [sha256.Size]byte
	Previous      [sha256.Size]byte
	Changed       bool
}

type Runtime interface {
	Precheck(context.Context, string) error
	Reload(context.Context, string) error
	Healthy(context.Context, string) error
	Stop(context.Context, string) error
}

func invalid(format string, values ...any) error {
	return errors.Join(ErrInvalidPolicy, errorf(format, values...))
}
