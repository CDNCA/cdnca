package cachefreshness

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	SchemaVersion = edgeconfig.CacheFreshnessSchemaVersion

	MaxPolicyBytes             = edgeconfig.CacheFreshnessMaxPolicyBytes
	MaxPolicyVersion           = edgeconfig.CacheFreshnessMaxPolicyVersion
	MaxIdentifierBytes         = edgeconfig.CacheFreshnessMaxIdentifierBytes
	MaxHosts                   = edgeconfig.CacheFreshnessMaxHosts
	MaxHostBytes               = edgeconfig.CacheFreshnessMaxHostBytes
	MaxCacheBytes              = edgeconfig.CacheFreshnessMaxCacheBytes
	MaxCacheSeconds            = edgeconfig.CacheFreshnessMaxCacheSeconds
	MaxStaleSeconds            = edgeconfig.CacheFreshnessMaxStaleSeconds
	MinLockTimeoutMilliseconds = edgeconfig.CacheFreshnessMinLockTimeoutMilliseconds
	MaxLockTimeoutMilliseconds = edgeconfig.CacheFreshnessMaxLockTimeoutMilliseconds
	MinLockAgeMilliseconds     = edgeconfig.CacheFreshnessMinLockAgeMilliseconds
	MaxLockAgeMilliseconds     = edgeconfig.CacheFreshnessMaxLockAgeMilliseconds
)

const (
	ModeBaseline    Mode = edgeconfig.CacheFreshnessModeBaseline
	ModeEnhancement Mode = edgeconfig.CacheFreshnessModeEnhancement
)

const (
	FailureUpdating      FailureClass = edgeconfig.CacheFreshnessFailureUpdating
	FailureError         FailureClass = edgeconfig.CacheFreshnessFailureError
	FailureTimeout       FailureClass = edgeconfig.CacheFreshnessFailureTimeout
	FailureInvalidHeader FailureClass = edgeconfig.CacheFreshnessFailureInvalidHeader
	FailureHTTP500       FailureClass = edgeconfig.CacheFreshnessFailureHTTP500
	FailureHTTP502       FailureClass = edgeconfig.CacheFreshnessFailureHTTP502
	FailureHTTP503       FailureClass = edgeconfig.CacheFreshnessFailureHTTP503
	FailureHTTP504       FailureClass = edgeconfig.CacheFreshnessFailureHTTP504
)

const (
	ReasonFreshHit             ReasonCode = "cache_fresh_hit"
	ReasonMiss                 ReasonCode = "cache_miss"
	ReasonCoalescedFollower    ReasonCode = "coalesced_follower"
	ReasonCoalesceTimeout      ReasonCode = "coalesce_timeout_fallback"
	ReasonStaleRevalidate      ReasonCode = "stale_served_revalidate"
	ReasonStaleHardLimit       ReasonCode = "stale_hard_limit_reached"
	ReasonPrivateBypass        ReasonCode = "cache_private_bypass"
	ReasonRequestBypass        ReasonCode = "cache_request_bypass"
	ReasonOriginError          ReasonCode = "origin_error"
	ReasonOriginUncacheable    ReasonCode = "origin_headers_uncacheable"
	ReasonOriginHeadersInvalid ReasonCode = "origin_headers_invalid"
)

const (
	StateFresh   FreshnessState = "fresh"
	StateStale   FreshnessState = "stale"
	StateExpired FreshnessState = "expired"
)

const (
	FreshnessSourceSMaxAge OriginFreshnessSource = "s-maxage"
	FreshnessSourceMaxAge  OriginFreshnessSource = "max-age"
	FreshnessSourceExpires OriginFreshnessSource = "expires"
	// FreshnessSourceDefault: 源站没有给出显式寿命，使用策略配置的 fresh_seconds。
	FreshnessSourceDefault OriginFreshnessSource = "default"
)

var (
	ErrInvalidPolicy = edgeconfig.ErrInvalidCacheFreshnessPolicy
	ErrPrecheck      = errors.New("cache freshness configuration precheck failed")
	ErrActivate      = errors.New("cache freshness configuration activation failed")
	ErrHealth        = errors.New("cache freshness configuration health check failed")
	ErrRollback      = errors.New("cache freshness configuration rollback failed")
)

type Mode = edgeconfig.CacheFreshnessMode

type FailureClass = edgeconfig.CacheFreshnessFailureClass

type ReasonCode string

type FreshnessState string

type OriginFreshnessSource string

type Policy = edgeconfig.CacheFreshnessPolicy

type EnhancementPolicy = edgeconfig.CacheFreshnessEnhancementPolicy

type ExpertPolicy = edgeconfig.CacheFreshnessExpertPolicy

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
	Activate(context.Context, string, uint64) error
	Healthy(context.Context, uint64) error
	Stop(context.Context) error
}

type RequestFacts struct {
	Method              string
	Authorization       bool
	Cookie              bool
	CacheControlNoStore bool
	CacheControlNoCache bool
	Range               bool
	Conditional         bool
	Upgrade             bool
}

type ObjectFacts struct {
	Exists             bool
	Cacheable          bool
	StoredAt           time.Time
	Coalesced          bool
	LockTimedOut       bool
	FailureClass       FailureClass
	OriginCacheControl []string
	OriginAge          []string
	OriginDate         []string
	OriginExpires      []string
	OriginVary         []string
}

type Decision struct {
	Reason                ReasonCode            `json:"reason"`
	State                 FreshnessState        `json:"state"`
	PolicyVersion         uint64                `json:"policy_version"`
	ConfigurationVersion  uint64                `json:"configuration_version"`
	TenantID              string                `json:"tenant_id"`
	SiteID                string                `json:"site_id"`
	Mode                  Mode                  `json:"mode"`
	AgeSeconds            int64                 `json:"age_seconds"`
	FreshSeconds          uint64                `json:"fresh_seconds"`
	StaleWindowSeconds    uint32                `json:"stale_window_seconds"`
	OriginAgeSeconds      uint64                `json:"origin_age_seconds,omitempty"`
	OriginFreshnessSource OriginFreshnessSource `json:"origin_freshness_source,omitempty"`
	VaryHeaders           []string              `json:"vary_headers,omitempty"`
	ObjectFactsSHA256     string                `json:"object_facts_sha256"`
	Bypass                bool                  `json:"bypass"`
	Fallback              bool                  `json:"fallback"`
}

func CanonicalObjectFacts(input ObjectFacts) []byte {
	storedAt := ""
	if !input.StoredAt.IsZero() {
		storedAt = input.StoredAt.UTC().Format(time.RFC3339Nano)
	}
	encoded, _ := json.Marshal(struct {
		Exists             bool         `json:"exists"`
		Cacheable          bool         `json:"cacheable"`
		StoredAt           string       `json:"stored_at"`
		Coalesced          bool         `json:"coalesced"`
		LockTimedOut       bool         `json:"lock_timed_out"`
		FailureClass       FailureClass `json:"failure_class"`
		OriginCacheControl []string     `json:"origin_cache_control"`
		OriginAge          []string     `json:"origin_age"`
		OriginDate         []string     `json:"origin_date"`
		OriginExpires      []string     `json:"origin_expires"`
		OriginVary         []string     `json:"origin_vary"`
	}{
		Exists: input.Exists, Cacheable: input.Cacheable, StoredAt: storedAt,
		Coalesced: input.Coalesced, LockTimedOut: input.LockTimedOut, FailureClass: input.FailureClass,
		OriginCacheControl: append([]string{}, input.OriginCacheControl...),
		OriginAge:          append([]string{}, input.OriginAge...), OriginDate: append([]string{}, input.OriginDate...),
		OriginExpires: append([]string{}, input.OriginExpires...), OriginVary: append([]string{}, input.OriginVary...),
	})
	return append(encoded, '\n')
}

func ObjectFactsDigest(input ObjectFacts) [sha256.Size]byte {
	return sha256.Sum256(CanonicalObjectFacts(input))
}
