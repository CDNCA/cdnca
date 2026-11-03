// Package cachetask holds the cache task contract the gateway client and the
// dynamic routing executor (dynroute.CacheTasks) share: the task, its result
// and the node's cache task settings.
package cachetask

import (
	"errors"
	"time"
)

const SchemaVersion = 2

var (
	ErrInvalidTask  = errors.New("invalid cache task")
	ErrConflict     = errors.New("cache task idempotency conflict")
	ErrSiteNotFound = errors.New("published site context not found")
	ErrTaskExpired  = errors.New("cache task id retention expired")
	ErrTaskCapacity = errors.New("cache task journal capacity exhausted")
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

// ResourceBudget is a task's budget. The node has no scan budget: a purge's
// only bound is the task deadline.
type ResourceBudget struct {
	MaxAttempts         int           `json:"max_attempts"`
	MaxConcurrency      int           `json:"max_concurrency"`
	MaxPurgeEntries     int           `json:"max_purge_entries"`
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
}

type ItemStatus string

const (
	ItemSuccess ItemStatus = "success"
	ItemSkipped ItemStatus = "skipped"
	ItemFailed  ItemStatus = "failed"
)

type TaskState string

const (
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

// Config is the node's cache task settings: the gateway client sizes each
// task's budget from it (localCacheBudgetFor) and dynroute.CacheTasks takes
// its prewarm request timeout.
type Config struct {
	SiteRequestsPerSecond float64
	SiteBurst             int
	RequestTimeout        time.Duration
	MaxResponseBytes      int64
	MaxTaskBytes          int64
	MaxAttempts           int
	MaxTaskConcurrency    int
	MaxPurgeEntries       int
	MaxDeadlineHorizon    time.Duration
}

func DefaultConfig() Config {
	return Config{
		SiteRequestsPerSecond: 10,
		SiteBurst:             2,
		// A prewarm request may fetch a large object (video, download):
		// minutes and GiB, not seconds and MiB (ge-cache; the node's
		// cache_task settings override these).
		RequestTimeout:     10 * time.Minute,
		MaxResponseBytes:   4 << 30,
		MaxTaskBytes:       64 << 30,
		MaxAttempts:        5,
		MaxTaskConcurrency: 8,
		MaxPurgeEntries:    100000,
		MaxDeadlineHorizon: 24 * time.Hour,
	}
}

const (
	CodePurged                   = "PURGED"
	CodePrewarmed                = "PREWARMED"
	CodeAlreadyCached            = "ALREADY_CACHED"
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
)
