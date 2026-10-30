// Package ipintelupdate is the official plugin module.ipintel.dnspup (PA-16,
// ADR 0007 section 4.4, user decisions 2026-10-17): the platform enters its
// own dnspup customer API key pair and a pull schedule; the control plane
// pulls the IP intelligence snapshot (GET /v1/tools/ip-intel-snapshot),
// builds the library locally (libs/entitlement/ipintel/builder) and stores it
// as the local artifact ipintel/local (artifactsync). The node artifact set
// then carries whichever of ipintel/base (license, pulled once) and
// ipintel/local has newer data. Any failure keeps the stored library; without
// the module in the lease nothing is pulled and ipintel/local is not used.
//
// Every state change is audited (system.ip_intel_update.*): settings saved,
// connection test, "check now", each pull outcome.
package ipintelupdate

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	// Feature is the lease module that enables this plugin.
	Feature = "module.ipintel.dnspup"
	// PermissionManage configures it (platform scope; platform.admin too).
	PermissionManage = "system.ip_intel_updates.manage"

	ActionSettings = "system.ip_intel_update.settings"
	ActionTest     = "system.ip_intel_update.test"
	ActionCheck    = "system.ip_intel_update.check"
	ActionPull     = "system.ip_intel_update.pull"

	OutcomePublished   = "published"
	OutcomeUnchanged   = "unchanged"
	OutcomeNotModified = "not_modified"
	OutcomePending     = "pending"
	OutcomeFailed      = "failed"

	MinIntervalMinutes     = 60
	MaxIntervalMinutes     = 43200
	DefaultIntervalMinutes = 1440
	DefaultAnchorMinute    = 240
	DefaultTimeZone        = "Asia/Shanghai"

	maxURL       = 2048
	retryAfter   = 15 * time.Minute
	pullTimeout  = 10 * time.Minute
	pollInterval = time.Minute
	secretDomain = "cdnca-ip-intel-update-secret/v1\x00"
)

var (
	ErrInvalidInput      = errors.New("ip intel update invalid input")
	ErrUnauthenticated   = errors.New("ip intel update authentication required")
	ErrPermissionDenied  = errors.New("ip intel update permission denied")
	ErrIdempotency       = errors.New("ip intel update idempotency key reused with a different request")
	ErrFeatureDenied     = errors.New("module.ipintel.dnspup is not included in the licence")
	ErrSecretRequired    = errors.New("ip intel update secret must be entered again")
	ErrSecretUnavailable = errors.New("ip intel update secret keyring unavailable")
	ErrDisabled          = errors.New("ip intel update is not enabled")
)

// Actor is the authenticated platform administrator of a write.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
	IP        string
}

// SettingsInput is the page form. APISecret nil keeps the stored secret
// (same API key and URL origin only), "" clears it, anything else replaces
// it. Schedule: every IntervalMinutes, aligned on AnchorMinute (minute of
// day) in TimeZone.
type SettingsInput struct {
	Enabled         bool    `json:"enabled"`
	URL             string  `json:"url"`
	APIKey          string  `json:"api_key"`
	APISecret       *string `json:"api_secret"`
	IntervalMinutes int     `json:"interval_minutes"`
	AnchorMinute    int     `json:"anchor_minute"`
	TimeZone        string  `json:"time_zone"`
}

// Status is the page view. The secret is never returned.
type Status struct {
	Licensed          bool       `json:"licensed"`
	Enabled           bool       `json:"enabled"`
	URL               string     `json:"url"`
	APIKey            string     `json:"api_key"`
	SecretConfigured  bool       `json:"secret_configured"`
	SecretFingerprint string     `json:"secret_fingerprint,omitempty"`
	IntervalMinutes   int        `json:"interval_minutes"`
	AnchorMinute      int        `json:"anchor_minute"`
	TimeZone          string     `json:"time_zone"`
	Revision          int64      `json:"revision"`
	SettingsUpdatedAt time.Time  `json:"settings_updated_at"`
	Running           bool       `json:"running"`
	CheckRequested    bool       `json:"check_requested"`
	LastCheckedAt     *time.Time `json:"last_checked_at"`
	LastSuccessAt     *time.Time `json:"last_success_at"`
	LastOutcome       string     `json:"last_outcome"`
	LastRelease       string     `json:"last_release"`
	LastHTTPStatus    int        `json:"last_http_status"`
	LastErrorCode     string     `json:"last_error_code"`
	LastError         string     `json:"last_error"`
	NextCheckAt       *time.Time `json:"next_check_at"`
	// Libraries: what the control plane holds and which one nodes get.
	Base      *Library `json:"base"`
	Local     *Library `json:"local"`
	NodeUses  string   `json:"node_uses"` // ipintel/base | ipintel/local | ""
	UseReason string   `json:"use_reason,omitempty"`
}

// Library is one stored IP library.
type Library struct {
	ArtifactID    string    `json:"artifact_id"`
	Revision      uint64    `json:"revision"`
	Version       string    `json:"version"`
	SourceRelease string    `json:"source_release"`
	DataUpdatedAt time.Time `json:"data_updated_at"`
	Usable        bool      `json:"usable"` // listed by artifactsync now (lease grants it)
}

// TestResult is a connection test (HEAD, not metered by dnspup).
type TestResult struct {
	OK          bool   `json:"ok"`
	HTTPStatus  int    `json:"http_status"`
	Release     string `json:"release,omitempty"`
	State       string `json:"state,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	ErrorCode   string `json:"error_code,omitempty"`
	SourceError string `json:"source_error_code,omitempty"`
	Error       string `json:"error,omitempty"`
}

// PullResult is one pull attempt (Ran false: not due or lease held).
type PullResult struct {
	Ran        bool   `json:"ran"`
	Outcome    string `json:"outcome"`
	Release    string `json:"release"`
	Revision   uint64 `json:"revision"`
	HTTPStatus int    `json:"http_status"`
	ErrorCode  string `json:"error_code,omitempty"`
}
