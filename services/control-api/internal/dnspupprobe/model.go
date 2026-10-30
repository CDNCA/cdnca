package dnspupprobe

import (
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

const (
	// Feature is the lease module that enables this plugin (official, free).
	Feature = "module.probe.dnspup"
	// PermissionManage configures it (platform scope; platform.admin too).
	PermissionManage = "system.probe_dnspup.manage"

	ActionSettings = "system.probe_dnspup.settings"
	ActionTest     = "system.probe_dnspup.test"
	ActionDegrade  = "system.probe_dnspup.degrade"

	EventTypeDegraded = notification.EventTypeProbeDNSPupDegraded
	degradedTemplate  = "probe.dnspup.degraded.zh-cn"

	secretDomain = "cdnca-probe-dnspup-secret/v1\x00"
	// SettingsPagePath is the console page of the plugin.
	SettingsPagePath = "/sys/probe-dnspup"
)

// Probe sources.
const (
	SourceNode       = "node"
	SourceDNSPup     = "dnspup"
	SourceController = "controller"
)

var (
	DefaultOriginSources = []string{SourceNode, SourceDNSPup, SourceController}
	DefaultEdgeSources   = []string{SourceNode, SourceDNSPup}
)

var (
	ErrInvalidInput      = errors.New("dnspup probe invalid input")
	ErrUnauthenticated   = errors.New("dnspup probe authentication required")
	ErrPermissionDenied  = errors.New("dnspup probe permission denied")
	ErrIdempotency       = errors.New("dnspup probe idempotency key reused with a different request")
	ErrFeatureDenied     = errors.New("module.probe.dnspup is not included in the licence")
	ErrSecretRequired    = errors.New("dnspup probe secret must be entered again")
	ErrSecretUnavailable = errors.New("dnspup probe secret keyring unavailable")
)

// Actor is the authenticated platform administrator of a write.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
	IP        string
}

// SettingsInput is the page form. APISecret nil keeps the stored secret
// (same API key and base URL host only), "" clears it, anything else
// replaces it (换钥).
type SettingsInput struct {
	Enabled       bool     `json:"enabled"`
	BaseURL       string   `json:"base_url"`
	APIKey        string   `json:"api_key"`
	APISecret     *string  `json:"api_secret"`
	SourceDomain  string   `json:"source_domain"`
	OriginSources []string `json:"origin_sources"`
	EdgeSources   []string `json:"edge_sources"`
}

// Status is the page view. The secret is never returned.
type Status struct {
	Licensed          bool       `json:"licensed"`
	Enabled           bool       `json:"enabled"`
	Active            bool       `json:"active"` // licensed, enabled, configured and not paused
	BaseURL           string     `json:"base_url"`
	APIKey            string     `json:"api_key"`
	SecretConfigured  bool       `json:"secret_configured"`
	SecretFingerprint string     `json:"secret_fingerprint,omitempty"`
	SourceDomain      string     `json:"source_domain"`
	OriginSources     []string   `json:"origin_sources"`
	EdgeSources       []string   `json:"edge_sources"`
	Revision          int64      `json:"revision"`
	SettingsUpdatedAt time.Time  `json:"settings_updated_at"`
	AccountCheckedAt  *time.Time `json:"account_checked_at"`
	AsyncCapable      bool       `json:"async_capable"`
	MonthlyLimit      int64      `json:"monthly_limit"`
	MonthlyUsed       int64      `json:"monthly_used"`
	AccountErrorCode  string     `json:"account_error_code"`
	PausedUntil       *time.Time `json:"paused_until"`
	PauseReason       string     `json:"pause_reason"`
	PauseCode         string     `json:"pause_code"`
}

// TestResult is a connection test (GET /v1/account, not metered).
type TestResult struct {
	OK           bool     `json:"ok"`
	HTTPStatus   int      `json:"http_status"`
	AsyncCapable bool     `json:"async_capable"`
	HTTPAllowed  bool     `json:"http_allowed"`
	TCPAllowed   bool     `json:"tcping_allowed"`
	MonthlyLimit int64    `json:"monthly_limit"`
	MonthlyUsed  int64    `json:"monthly_used"`
	Tools        []string `json:"allowed_tools"`
	ErrorCode    string   `json:"error_code,omitempty"`
}
