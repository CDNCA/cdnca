package cachetask

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	SchemaVersion   = 2
	CacheKeyVersion = "v2"
)

var (
	ErrInvalidTask    = errors.New("invalid cache task")
	ErrInvalidState   = errors.New("invalid cache task state")
	ErrConflict       = errors.New("cache task idempotency conflict")
	ErrSiteNotFound   = errors.New("published site context not found")
	ErrTaskNotFound   = errors.New("cache task not found")
	ErrTaskExpired    = errors.New("cache task id retention expired")
	ErrTaskCapacity   = errors.New("cache task journal capacity exhausted")
	ErrJournalWrite   = errors.New("cache task journal write failed")
	ErrJournalCorrupt = errors.New("cache task journal corrupt")
)

type Action string

const (
	ActionPurgeExact  Action = "purge_exact"
	ActionPurgePrefix Action = "purge_prefix"
	ActionPurgeSite   Action = "purge_site"
	ActionPrewarm     Action = "prewarm"
)

type Scope string

const (
	ScopeURL       Scope = "url"
	ScopeDirectory Scope = "directory"
	ScopeSite      Scope = "site"
)

type ResourceBudget struct {
	MaxAttempts         int           `json:"max_attempts"`
	MaxConcurrency      int           `json:"max_concurrency"`
	MaxPurgeEntries     int           `json:"max_purge_entries"`
	MaxScanEntries      int           `json:"max_scan_entries"`
	MaxScanBytes        int64         `json:"max_scan_bytes"`
	MaxScanDuration     time.Duration `json:"max_scan_duration"`
	MaxTotalBytes       int64         `json:"max_total_bytes"`
	MaxResourceBytes    int64         `json:"max_resource_bytes"`
	RequestsPerSecond   float64       `json:"requests_per_second"`
	Burst               int           `json:"burst"`
	InitialRetryBackoff time.Duration `json:"initial_retry_backoff"`
	MaximumRetryBackoff time.Duration `json:"maximum_retry_backoff"`
}

type Task struct {
	SchemaVersion   int            `json:"schema_version"`
	TaskID          string         `json:"task_id"`
	OperationID     string         `json:"operation_id"`
	TenantID        string         `json:"tenant_id"`
	SiteID          string         `json:"site_id"`
	Scope           Scope          `json:"scope"`
	ConfigVersionID string         `json:"config_version_id"`
	ConfigRevision  uint64         `json:"config_revision"`
	DeliveryAttempt int            `json:"delivery_attempt"`
	Deadline        time.Time      `json:"deadline"`
	Budget          ResourceBudget `json:"budget"`
	Action          Action         `json:"action"`
	Targets         []string       `json:"targets,omitempty"`

	// Kept only so the pre-v2 compile fixture continues to build. Version 2
	// validation rejects it; OperationID is the sole idempotency identity.
	IdempotencyKey        string `json:"-"`
	ExpectedConfigVersion string `json:"-"`
}

type SiteContext struct {
	TenantID            string
	SiteID              string
	ConfigVersionID     string
	ConfigRevision      uint64
	ActiveReleaseSHA256 string
	NginxSHA256         string
	Domain              string
	ListenPort          uint16
	Scheme              string
	CacheIdentity       string
	CacheEnabled        bool
	QueryMode           edgeconfig.CacheQueryMode
	QueryNames          []string
	VaryHeaders         []string
	CacheRules          []edgeconfig.CacheRuleDocument
	PrewarmPort         uint16
	PrewarmPathPrefix   string
	Listeners           []ListenerContext
	// Domains are every name the site serves (site runtime v2: the primary,
	// aliases and "*." wildcards, as its server_name). A target's host may be
	// any name they cover. Empty: only the listener's Domain.
	Domains []string
	// KeyByHost: the cache key names the request's own host instead of the
	// listener's Domain (site runtime v2, edgeconfig CacheListenerPolicy
	// KeyByHost); each host the site serves has its own objects.
	KeyByHost bool
	// CacheGeneration (site runtime v2, ge-cache): the namespace is the
	// site's stable edgeconfig.CacheSiteNamespaceID and the plain key's
	// version field is this generation instead of the config version.
	CacheGeneration string
}

// cacheKeyVersion is the plain key's version field.
func (site SiteContext) cacheKeyVersion() string {
	if site.CacheGeneration != "" {
		return site.CacheGeneration
	}
	return site.ConfigVersionID
}

// expectedCacheIdentity is the namespace the site's objects live in.
func (site SiteContext) expectedCacheIdentity() string {
	if site.CacheGeneration != "" {
		return edgeconfig.CacheSiteNamespaceID(site.TenantID, site.SiteID)
	}
	return CacheNamespaceID(site.TenantID, site.SiteID, site.ConfigVersionID)
}

type ListenerContext struct {
	Domain            string
	Scheme            string
	ListenPort        uint16
	PrewarmPort       uint16
	PrewarmPathPrefix string
	CacheEnabled      bool
	CacheFreshness    bool
}

type SiteResolver interface {
	ResolveSite(context.Context, string, string, string, uint64) (SiteContext, error)
}

type TaskReference struct {
	SchemaVersion int    `json:"schema_version"`
	TaskID        string `json:"task_id"`
	OperationID   string `json:"operation_id"`
	TenantID      string `json:"tenant_id"`
	SiteID        string `json:"site_id"`
}

type ItemStatus string

const (
	ItemPending ItemStatus = "pending"
	ItemWorking ItemStatus = "working"
	ItemSuccess ItemStatus = "success"
	ItemSkipped ItemStatus = "skipped"
	ItemFailed  ItemStatus = "failed"
)

type TaskState string

const (
	StateRunning       TaskState = "running"
	StateSucceeded     TaskState = "succeeded"
	StatePartialFailed TaskState = "partial_failed"
	StateFailed        TaskState = "failed"
	StateCancelled     TaskState = "cancelled"
)

type ItemResult struct {
	Index        int        `json:"index"`
	Target       string     `json:"target"`
	TargetDigest string     `json:"target_digest"`
	Status       ItemStatus `json:"status"`
	Code         string     `json:"code"`
	CauseCode    string     `json:"cause_code,omitempty"`
	Affected     int        `json:"affected"`
	Bytes        int64      `json:"bytes"`
	Attempts     int        `json:"attempts"`
	CompletedAt  time.Time  `json:"completed_at"`
}

type Progress struct {
	Total     int   `json:"total"`
	Completed int   `json:"completed"`
	Succeeded int   `json:"succeeded"`
	Skipped   int   `json:"skipped"`
	Failed    int   `json:"failed"`
	Bytes     int64 `json:"bytes"`
}

type Result struct {
	SchemaVersion   int          `json:"schema_version"`
	TaskID          string       `json:"task_id"`
	OperationID     string       `json:"operation_id"`
	TenantID        string       `json:"tenant_id"`
	SiteID          string       `json:"site_id"`
	Scope           Scope        `json:"scope"`
	ConfigVersionID string       `json:"config_version_id"`
	ConfigRevision  uint64       `json:"config_revision"`
	Digest          string       `json:"digest"`
	State           TaskState    `json:"state"`
	Attempt         int          `json:"attempt"`
	DeliveryAttempt int          `json:"delivery_attempt"`
	Progress        Progress     `json:"progress"`
	Items           []ItemResult `json:"items"`
	StartedAt       time.Time    `json:"started_at"`
	CompletedAt     time.Time    `json:"completed_at"`
	Replayed        bool         `json:"replayed"`
}

// MaxPrewarmObjectBytes is the largest object a prewarm may fetch.
const MaxPrewarmObjectBytes int64 = 1 << 40

type Config struct {
	GlobalConcurrency       int
	GlobalRequestsPerSecond float64
	GlobalBurst             int
	SiteRequestsPerSecond   float64
	SiteBurst               int
	RequestTimeout          time.Duration
	MaxResponseBytes        int64
	MaxTaskBytes            int64
	MaxBatchItems           int
	MaxTaskTargetBytes      int
	MaxAttempts             int
	MaxTaskConcurrency      int
	MaxPurgeEntries         int
	MaxScanEntries          int
	MaxScanBytes            int64
	MaxScanDuration         time.Duration
	MaxSiteLimiters         int
	RetainCompletedTasks    int
	MaxRegistryTasks        int
	MaxTombstoneTasks       int
	CancelSettlementTimeout time.Duration
	MaxDeadlineHorizon      time.Duration
	LoopbackAddress         netip.Addr
	AllowedStatuses         []int
	Now                     func() time.Time
	Sleep                   func(context.Context, time.Duration) error
	Jitter                  func(time.Duration) time.Duration
}

func DefaultConfig() Config {
	return Config{
		GlobalConcurrency:       8,
		GlobalRequestsPerSecond: 50,
		GlobalBurst:             8,
		SiteRequestsPerSecond:   10,
		SiteBurst:               2,
		// A prewarm request may fetch a large object (video, download):
		// minutes and GiB, not seconds and MiB (ge-cache; the node's
		// cache_task settings override these).
		RequestTimeout:          10 * time.Minute,
		MaxResponseBytes:        4 << 30,
		MaxTaskBytes:            64 << 30,
		MaxBatchItems:           500,
		MaxTaskTargetBytes:      256 << 10,
		MaxAttempts:             5,
		MaxTaskConcurrency:      8,
		MaxPurgeEntries:         100000,
		MaxScanEntries:          1000000,
		MaxScanBytes:            256 << 20,
		MaxScanDuration:         30 * time.Second,
		MaxSiteLimiters:         1024,
		RetainCompletedTasks:    4096,
		MaxRegistryTasks:        8192,
		MaxTombstoneTasks:       1000000,
		CancelSettlementTimeout: 5 * time.Second,
		MaxDeadlineHorizon:      24 * time.Hour,
		LoopbackAddress:         netip.MustParseAddr("127.0.0.1"),
		AllowedStatuses:         []int{200},
		Now:                     time.Now,
		Sleep:                   sleepContext,
		Jitter:                  func(value time.Duration) time.Duration { return value },
	}
}

func sleepContext(ctx context.Context, value time.Duration) error {
	timer := time.NewTimer(value)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

const (
	CodePurged                   = "PURGED"
	CodePrewarmed                = "PREWARMED"
	CodeCacheEntryNotFound       = "CACHE_ENTRY_NOT_FOUND"
	CodeAlreadyCached            = "ALREADY_CACHED"
	CodeCacheLayoutUnsafe        = "CACHE_LAYOUT_UNSAFE"
	CodeCacheMetadataInvalid     = "CACHE_METADATA_INVALID"
	CodeCacheEntryChanged        = "CACHE_ENTRY_CHANGED"
	CodeCacheDeleteFailed        = "CACHE_DELETE_FAILED"
	CodePurgeBudgetExceeded      = "PURGE_ENTRY_BUDGET_EXCEEDED"
	CodePurgeScanBudgetExceeded  = "PURGE_SCAN_BUDGET_EXCEEDED"
	CodeSiteContextStale         = "SITE_CONTEXT_STALE"
	CodePrewarmTimeout           = "PREWARM_TIMEOUT"
	CodePrewarmRedirect          = "PREWARM_REDIRECT_REJECTED"
	CodePrewarmResponseTooLarge  = "PREWARM_RESPONSE_TOO_LARGE"
	CodePrewarmTaskBytesExceeded = "PREWARM_TASK_BYTES_EXCEEDED"
	CodePrewarmUpstream          = "PREWARM_UPSTREAM_FAILED"
	CodePrewarmStatus            = "PREWARM_STATUS_REJECTED"
	CodePrewarmNotCacheable      = "PREWARM_NOT_CACHEABLE"
	CodeTaskCancelled            = "TASK_CANCELLED"
	CodeTaskDeadlineExceeded     = "TASK_DEADLINE_EXCEEDED"
	CodeRetryExhausted           = "RETRY_EXHAUSTED"
)
