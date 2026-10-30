package systemconfig

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput        = errors.New("invalid system configuration input")
	ErrInvalidStore        = errors.New("invalid system configuration store")
	ErrPermissionDenied    = errors.New("system configuration permission denied")
	ErrNotFound            = errors.New("system configuration revision not found")
	ErrRevisionConflict    = errors.New("system configuration revision conflict")
	ErrInvalidTransition   = errors.New("invalid system configuration transition")
	ErrPreflightHash       = errors.New("system configuration preflight hash mismatch")
	ErrPreflightRequired   = errors.New("successful system configuration preflight required")
	ErrPreflightExpired    = errors.New("system configuration preflight expired")
	ErrClockRollback       = errors.New("system configuration clock moved backwards")
	ErrIdempotencyConflict = errors.New("system configuration idempotency conflict")
	ErrPublicationFailed   = errors.New("system configuration edge publication failed")
	// ErrRegionOverrideUnsupported: a region override of a setting read when a
	// site/forward/certificate is created (it has no single region) — only the
	// website defaults' gzip switch and types, rendered per node, may be
	// overridden. Wraps ErrInvalidInput.
	ErrRegionOverrideUnsupported = fmt.Errorf("%w: region override not supported for this setting", ErrInvalidInput)
)

const (
	StatusDraft      = "draft"
	StatusValidated  = "validated"
	StatusActive     = "active"
	StatusSuperseded = "superseded"
	StatusRejected   = "rejected"

	SecretProviderVault       = "vault"
	SecretProviderKMSEnvelope = "kms-envelope"

	EnvelopeAES256GCM        = "aes-256-gcm"
	EnvelopeChaCha20Poly1305 = "chacha20-poly1305"
	EnvelopeKMSManaged       = "kms-managed"

	PreflightSchema      = "schema"
	PreflightReferences  = "references"
	PreflightCapacity    = "capacity"
	PreflightNginxSafety = "nginx_safety"
	PreflightErrorPages  = "error_pages"

	CheckPass = "pass"
	CheckFail = "fail"

	PortModeDefault = "default"
	PortModeCustom  = "custom"

	ConfigurationScopeRegion = "region"
	ConfigurationScopeNode   = "node"
)

const canonicalSchema = "cdnca.system-configuration/v2"

type Clock func() time.Time

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type ActivationPublisher interface {
	PublishActivation(context.Context, pgx.Tx, ActivationPublicationRequest) ([]ActivationPublication, error)
}

type ActivationPublicationRequest struct {
	Actor          Actor
	Revision       int64
	SnapshotSHA256 string
	Configuration  Configuration
	IdempotencyKey string
	RequestID      string
	ActivatedAt    time.Time
}

type ActivationPublication struct {
	TenantScopeID        uuid.UUID `json:"tenant_scope_id"`
	TenantSourceRevision int64     `json:"tenant_source_revision"`
	PublicationID        uuid.UUID `json:"publication_id"`
	ConfigVersionID      uuid.UUID `json:"config_version_id"`
	RolloutID            uuid.UUID `json:"rollout_id"`
	ArtifactSHA256       string    `json:"artifact_sha256"`
	ReasonCode           string    `json:"reason_code"`
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type RevisionReference struct {
	ID       uuid.UUID `json:"id"`
	Revision int64     `json:"revision"`
}

type NginxWorkerSettings struct {
	WorkerProcesses         int    `json:"worker_processes"`
	WorkerConnections       int    `json:"worker_connections"`
	WorkerRlimitNoFile      int    `json:"worker_rlimit_nofile"`
	WorkerShutdownTimeoutMS int    `json:"worker_shutdown_timeout_ms"`
	LogsDir                 string `json:"logs_dir"`
}

type LargeClientHeaderBuffers struct {
	Count     int   `json:"count"`
	SizeBytes int64 `json:"size_bytes"`
}

type NginxHTTPSettings struct {
	GzipLevel                 int                      `json:"gzip_comp_level"`
	GzipHTTPVersion           string                   `json:"gzip_http_version"`
	GzipMinimumBytes          int64                    `json:"gzip_min_length_bytes"`
	GzipVary                  bool                     `json:"gzip_vary"`
	ServerAddrOutgoing        bool                     `json:"server_addr_outgoing"`
	ProxyRequestBuffering     bool                     `json:"proxy_request_buffering"`
	ProxyBuffering            bool                     `json:"proxy_buffering"`
	ProxyCacheMaxBytes        int64                    `json:"proxy_cache_max_size_bytes"`
	ProxyCacheMinFreeBytes    int64                    `json:"proxy_cache_min_free_bytes"`
	ProxyCacheMethods         []string                 `json:"proxy_cache_methods"`
	ProxyHTTPVersion          string                   `json:"proxy_http_version"`
	ProxyMaxTempFileBytes     int64                    `json:"proxy_max_temp_file_size_bytes"`
	ProxyNextUpstream         []string                 `json:"proxy_next_upstream"`
	ProxyConnectTimeoutMS     int                      `json:"proxy_connect_timeout_ms"`
	ProxySendTimeoutMS        int                      `json:"proxy_send_timeout_ms"`
	ProxyReadTimeoutMS        int                      `json:"proxy_read_timeout_ms"`
	ClientBodyBufferSizeBytes int64                    `json:"client_body_buffer_size_bytes"`
	ServerHeader              string                   `json:"server"`
	ClientMaxBodyBytes        int64                    `json:"client_max_body_size_bytes"`
	DefaultMIMEType           string                   `json:"default_type"`
	KeepaliveRequests         int                      `json:"keepalive_requests"`
	KeepaliveTimeoutMS        int                      `json:"keepalive_timeout_ms"`
	LogNotFound               bool                     `json:"log_not_found"`
	ServerTokens              bool                     `json:"server_tokens"`
	LargeClientHeaderBuffers  LargeClientHeaderBuffers `json:"large_client_header_buffers"`
	ServerNamesHashMaxSize    int                      `json:"server_names_hash_max_size"`
	ServerNamesHashBucketSize int                      `json:"server_names_hash_bucket_size"`
}

type NginxStreamSettings struct {
	ProxyConnectTimeoutMS int `json:"proxy_connect_timeout_ms"`
	ProxyTimeoutMS        int `json:"proxy_timeout_ms"`
}

type NginxWorkerOverride struct {
	WorkerProcesses         *int    `json:"worker_processes,omitempty"`
	WorkerConnections       *int    `json:"worker_connections,omitempty"`
	WorkerRlimitNoFile      *int    `json:"worker_rlimit_nofile,omitempty"`
	WorkerShutdownTimeoutMS *int    `json:"worker_shutdown_timeout_ms,omitempty"`
	LogsDir                 *string `json:"logs_dir,omitempty"`
}

type NginxHTTPOverride struct {
	GzipLevel                 *int                      `json:"gzip_comp_level,omitempty"`
	GzipHTTPVersion           *string                   `json:"gzip_http_version,omitempty"`
	GzipMinimumBytes          *int64                    `json:"gzip_min_length_bytes,omitempty"`
	GzipVary                  *bool                     `json:"gzip_vary,omitempty"`
	ServerAddrOutgoing        *bool                     `json:"server_addr_outgoing,omitempty"`
	ProxyRequestBuffering     *bool                     `json:"proxy_request_buffering,omitempty"`
	ProxyBuffering            *bool                     `json:"proxy_buffering,omitempty"`
	ProxyCacheMaxBytes        *int64                    `json:"proxy_cache_max_size_bytes,omitempty"`
	ProxyCacheMinFreeBytes    *int64                    `json:"proxy_cache_min_free_bytes,omitempty"`
	ProxyCacheMethods         *[]string                 `json:"proxy_cache_methods,omitempty"`
	ProxyHTTPVersion          *string                   `json:"proxy_http_version,omitempty"`
	ProxyMaxTempFileBytes     *int64                    `json:"proxy_max_temp_file_size_bytes,omitempty"`
	ProxyNextUpstream         *[]string                 `json:"proxy_next_upstream,omitempty"`
	ProxyConnectTimeoutMS     *int                      `json:"proxy_connect_timeout_ms,omitempty"`
	ProxySendTimeoutMS        *int                      `json:"proxy_send_timeout_ms,omitempty"`
	ProxyReadTimeoutMS        *int                      `json:"proxy_read_timeout_ms,omitempty"`
	ClientBodyBufferSizeBytes *int64                    `json:"client_body_buffer_size_bytes,omitempty"`
	ServerHeader              *string                   `json:"server,omitempty"`
	ClientMaxBodyBytes        *int64                    `json:"client_max_body_size_bytes,omitempty"`
	DefaultMIMEType           *string                   `json:"default_type,omitempty"`
	KeepaliveRequests         *int                      `json:"keepalive_requests,omitempty"`
	KeepaliveTimeoutMS        *int                      `json:"keepalive_timeout_ms,omitempty"`
	LogNotFound               *bool                     `json:"log_not_found,omitempty"`
	ServerTokens              *bool                     `json:"server_tokens,omitempty"`
	LargeClientHeaderBuffers  *LargeClientHeaderBuffers `json:"large_client_header_buffers,omitempty"`
	ServerNamesHashMaxSize    *int                      `json:"server_names_hash_max_size,omitempty"`
	ServerNamesHashBucketSize *int                      `json:"server_names_hash_bucket_size,omitempty"`
}

type NginxStreamOverride struct {
	ProxyConnectTimeoutMS *int `json:"proxy_connect_timeout_ms,omitempty"`
	ProxyTimeoutMS        *int `json:"proxy_timeout_ms,omitempty"`
}

type NginxOverride struct {
	Worker *NginxWorkerOverride `json:"worker,omitempty"`
	HTTP   *NginxHTTPOverride   `json:"http,omitempty"`
	Stream *NginxStreamOverride `json:"stream,omitempty"`
}

type ScopedNginxOverride struct {
	ID      string        `json:"id"`
	Scope   string        `json:"scope"`
	ScopeID string        `json:"scope_id"`
	Values  NginxOverride `json:"values"`
}

type NginxLimits struct {
	WorkerProcesses         int
	WorkerConnections       int
	WorkerRlimitNoFile      int
	WorkerShutdownTimeoutMS int
	LogsDir                 string
	GzipLevel               int
	GzipHTTPVersion         string
	GzipMinimumBytes        int64
	GzipVary                bool
	ServerAddrOutgoing      bool
	ProxyRequestBuffering   bool
	ProxyBuffering          bool
	// ProxyCacheMaxBytes / ProxyCacheMinFreeBytes / ProxyCacheZoneBytes are
	// the node's cache budget (edgeconfig.CacheNodeBudget): every site's
	// disk and key zone are scaled to fit; min_free keeps the cache file
	// system this free. The cache lives under the node's state root.
	ProxyCacheMaxBytes          int64
	ProxyCacheMinFreeBytes      int64
	ProxyCacheMethods           []string
	ProxyHTTPVersion            string
	ProxyMaxTempFileBytes       int64
	ProxyNextUpstream           []string
	ProxyConnectTimeoutMS       int
	ProxySendTimeoutMS          int
	ProxyReadTimeoutMS          int
	ClientBodyBufferSizeBytes   int64
	ServerHeader                string
	ClientMaxBodyBytes          int64
	DefaultMIMEType             string
	KeepaliveRequests           int
	KeepaliveTimeoutMS          int
	LogNotFound                 bool
	ServerTokens                bool
	LargeClientHeaderBuffers    LargeClientHeaderBuffers
	ServerNamesHashMaxSize      int
	ServerNamesHashBucketSize   int
	StreamProxyConnectTimeoutMS int
	StreamProxyTimeoutMS        int
	Overrides                   []ScopedNginxOverride

	// Runtime-only values are derived from the single project bootstrap and are
	// intentionally absent from the competitor-facing canonical JSON.
	ResolverAddresses   []string
	ResolverTimeoutMS   int
	ProxyCacheZoneBytes int64
}

type DefaultSSLSettings struct {
	Mode                string   `json:"mode"`
	Protocols           []string `json:"protocols"`
	CipherSuites        string   `json:"cipher_suites"`
	PreferServerCiphers bool     `json:"prefer_server_ciphers"`
}

type DefaultWebsiteHTTPSettings struct {
	ListenPorts []uint16 `json:"listen_ports"`
}

type DefaultWebsiteHTTPSSettings struct {
	ListenPorts         []uint16           `json:"listen_ports"`
	HSTSEnabled         bool               `json:"hsts_enabled"`
	HTTP2Enabled        bool               `json:"http2_enabled"`
	HTTP3Enabled        bool               `json:"http3_enabled"`
	ForceHTTPS          bool               `json:"force_https"`
	SSL                 DefaultSSLSettings `json:"ssl"`
	OCSPStaplingEnabled bool               `json:"ocsp_stapling_enabled"`
}

type DefaultWebsiteOriginSettings struct {
	Scheme                 string   `json:"scheme"`
	HTTPPort               uint16   `json:"http_port"`
	HTTPSPort              uint16   `json:"https_port"`
	ResponseTimeoutSeconds int      `json:"response_timeout_seconds"`
	ConnectTimeoutSeconds  int      `json:"connect_timeout_seconds"`
	SSLProtocols           []string `json:"ssl_protocols"`
	HTTPVersion            string   `json:"http_version"`
	KeepaliveEnabled       bool     `json:"keepalive_enabled"`
	PostBodyLimitBytes     int64    `json:"post_body_limit_bytes"`
}

type DefaultCacheNoCacheCondition struct {
	Variable string `json:"variable"`
	String   string `json:"string"`
}

type DefaultCacheRule struct {
	ID          string                         `json:"id"`
	Match       string                         `json:"match"`
	Content     *string                        `json:"content"`
	TTLSeconds  int                            `json:"ttl_seconds"`
	IgnoreQuery bool                           `json:"ignore_query"`
	ForceCache  bool                           `json:"force_cache"`
	Range       bool                           `json:"range"`
	IgnoreVary  bool                           `json:"ignore_vary"`
	NoCache     []DefaultCacheNoCacheCondition `json:"no_cache"`
	Enabled     bool                           `json:"enabled"`
	Position    int                            `json:"position"`
}

type DefaultOriginRequestHeader struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Value          *string `json:"value"`
	Action         string  `json:"action"`
	AllowDuplicate bool    `json:"allow_duplicate"`
	Enabled        bool    `json:"enabled"`
	Position       int     `json:"position"`
}

type DefaultAccessLogSettings struct {
	CaptureRequestHeaders  bool `json:"capture_request_headers"`
	CaptureResponseHeaders bool `json:"capture_response_headers"`
	CaptureRequestBody     bool `json:"capture_request_body"`
	RequestBodyLimitKB     int  `json:"request_body_limit_kb"`
}

type DefaultWAFAutoBlockSettings struct {
	Enabled       bool `json:"enabled"`
	WindowSeconds int  `json:"window_seconds"`
	HitThreshold  int  `json:"hit_threshold"`
	BlockSeconds  int  `json:"block_seconds"`
}

type DefaultWAFModules struct {
	SQLI     string `json:"sqli"`
	XSS      string `json:"xss"`
	Upload   string `json:"upload"`
	FI       string `json:"fi"`
	CMDI     string `json:"cmdi"`
	Java     string `json:"java"`
	JDeser   string `json:"jdeser"`
	PHP      string `json:"php"`
	PHPDeser string `json:"phpdeser"`
	SSTI     string `json:"ssti"`
}

type DefaultSecuritySettings struct {
	DefaultCCPolicyID *string                     `json:"default_cc_policy_id"`
	WAFEnabled        bool                        `json:"waf_enabled"`
	WAFAutoBlock      DefaultWAFAutoBlockSettings `json:"waf_auto_block"`
	WAFModules        DefaultWAFModules           `json:"waf_modules"`
}

// DefaultWebsiteOtherSettings: LoadBalancing is new sites' origin load
// balancing; GzipEnabled/GzipTypes are the node-wide gzip default (sites
// override it). crawler_policy was removed (CC rules carry
// crawler handling), block_transparent_proxy and realtime_response/send
// (no runtime behind them); websocket_enabled is for the site WebSocket
// switch (ge-origin).
type DefaultWebsiteOtherSettings struct {
	LoadBalancing    string   `json:"load_balancing"`
	GzipEnabled      bool     `json:"gzip_enabled"`
	GzipTypes        []string `json:"gzip_types"`
	WebsocketEnabled bool     `json:"websocket_enabled"`
}

type DefaultWebsiteSettings struct {
	HTTP                 DefaultWebsiteHTTPSettings   `json:"http"`
	HTTPS                DefaultWebsiteHTTPSSettings  `json:"https"`
	Origin               DefaultWebsiteOriginSettings `json:"origin"`
	CacheRules           []DefaultCacheRule           `json:"cache_rules"`
	OriginRequestHeaders []DefaultOriginRequestHeader `json:"origin_request_headers"`
	AccessLog            DefaultAccessLogSettings     `json:"access_log"`
	Security             DefaultSecuritySettings      `json:"security"`
	Other                DefaultWebsiteOtherSettings  `json:"other"`
}

type DefaultStreamSettings struct {
	Protocol             string `json:"protocol"`
	LoadBalancing        string `json:"load_balancing"`
	ProxyProtocolEnabled bool   `json:"proxy_protocol_enabled"`
}

type DefaultCertificateSettings struct {
	// Issuer is the CA new ACME orders use: lets_encrypt (the
	// installation's ACME_DIRECTORY_URL), zerossl or google_trust (need the
	// CA's EAB credentials, acmecacredentials).
	Issuer string `json:"issuer"`
}

// CertificateIssuers are the accepted Issuer values.
var CertificateIssuers = []string{"lets_encrypt", "zerossl", "google_trust"}

type DefaultWebsiteOriginOverride struct {
	Scheme                 *string   `json:"scheme,omitempty"`
	HTTPPort               *uint16   `json:"http_port,omitempty"`
	HTTPSPort              *uint16   `json:"https_port,omitempty"`
	ResponseTimeoutSeconds *int      `json:"response_timeout_seconds,omitempty"`
	ConnectTimeoutSeconds  *int      `json:"connect_timeout_seconds,omitempty"`
	SSLProtocols           *[]string `json:"ssl_protocols,omitempty"`
	HTTPVersion            *string   `json:"http_version,omitempty"`
	KeepaliveEnabled       *bool     `json:"keepalive_enabled,omitempty"`
	PostBodyLimitBytes     *int64    `json:"post_body_limit_bytes,omitempty"`
}

type DefaultWebsiteOverride struct {
	HTTPListenPorts      *[]uint16                     `json:"http_listen_ports,omitempty"`
	HTTPSListenPorts     *[]uint16                     `json:"https_listen_ports,omitempty"`
	HSTSEnabled          *bool                         `json:"hsts_enabled,omitempty"`
	HTTP2Enabled         *bool                         `json:"http2_enabled,omitempty"`
	HTTP3Enabled         *bool                         `json:"http3_enabled,omitempty"`
	ForceHTTPS           *bool                         `json:"force_https,omitempty"`
	SSL                  *DefaultSSLSettings           `json:"ssl,omitempty"`
	OCSPStaplingEnabled  *bool                         `json:"ocsp_stapling_enabled,omitempty"`
	Origin               *DefaultWebsiteOriginOverride `json:"origin,omitempty"`
	CacheRules           *[]DefaultCacheRule           `json:"cache_rules,omitempty"`
	OriginRequestHeaders *[]DefaultOriginRequestHeader `json:"origin_request_headers,omitempty"`
	DefaultCCPolicyID    **string                      `json:"default_cc_policy_id,omitempty"`
	WAFEnabled           *bool                         `json:"waf_enabled,omitempty"`
	WAFModules           *DefaultWAFModules            `json:"waf_modules,omitempty"`
	Other                *DefaultWebsiteOtherSettings  `json:"other,omitempty"`
}

type DefaultStreamOverride struct {
	Protocol             *string `json:"protocol,omitempty"`
	LoadBalancing        *string `json:"load_balancing,omitempty"`
	ProxyProtocolEnabled *bool   `json:"proxy_protocol_enabled,omitempty"`
}

type DefaultCertificateOverride struct {
	Issuer *string `json:"issuer,omitempty"`
}

type DefaultOverrides struct {
	Website     *DefaultWebsiteOverride     `json:"website,omitempty"`
	Stream      *DefaultStreamOverride      `json:"stream,omitempty"`
	Certificate *DefaultCertificateOverride `json:"certificate,omitempty"`
}

type ScopedDefaultOverride struct {
	ID      string           `json:"id"`
	Scope   string           `json:"scope"`
	ScopeID string           `json:"scope_id"`
	Values  DefaultOverrides `json:"values"`
}

type DefaultReferences struct {
	Website     DefaultWebsiteSettings     `json:"website"`
	Stream      DefaultStreamSettings      `json:"stream"`
	Certificate DefaultCertificateSettings `json:"certificate"`
	Overrides   []ScopedDefaultOverride    `json:"overrides"`

	// These values remain process-internal projections for existing publishers;
	// v2 has no legacy wire representation or compatibility mode.
	SiteTemplate *RevisionReference `json:"-"`
	CachePolicy  *RevisionReference `json:"-"`
	WAFPolicy    *RevisionReference `json:"-"`
	CCPolicy     *RevisionReference `json:"-"`
	ACLPolicy    *RevisionReference `json:"-"`
	ListenPort   uint16             `json:"-"`
	OriginScheme string             `json:"-"`
	OriginPort   uint16             `json:"-"`
	HTTPSPort    uint16             `json:"-"`
}

type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

type ResourceSiteSettings struct {
	MinimumRelatedConfigLimit   int    `json:"related_config_min_limit"`
	RelatedConfigMaxMultiplier  int    `json:"related_config_max_times_limit"`
	MaxBlacklistIPsPerSite      int    `json:"black_ip_limit"`
	MaxWhitelistIPsPerSite      int    `json:"white_ip_limit"`
	DailyURLPurgeLimit          int    `json:"daily_clean_url_limit"`
	DailyDirectoryPurgeLimit    int    `json:"daily_clean_dir_limit"`
	DailyPrewarmLimit           int    `json:"daily_pre_cache_url_limit"`
	DailyIPUnlockLimit          int    `json:"daily_ip_unlock_limit"`
	IPUnlockPerRequestLimit     int    `json:"ip_unlock_per_request_limit"`
	MaxCCRulesPerPolicy         int    `json:"cc_rule_max_limit"`
	MaxDomainsPerSite           int    `json:"max_domains_per_site"`
	ListenDefaultHTTP80         bool   `json:"listen_default_http_80"`
	DailyAccessLogDownloadLimit int    `json:"daily_access_log_download_limit"`
	AccessLogTemporaryDir       string `json:"access_log_tmp_dir"`
	AccessLogRetentionHours     int    `json:"access_log_retain_hours"`
}

type ResourceStreamSettings struct {
	CustomPortNotAllow         []PortRange `json:"custom_port_not_allow"`
	MinimumRelatedConfigLimit  int         `json:"related_config_min_limit"`
	RelatedConfigMaxMultiplier int         `json:"related_config_max_times_limit"`
	MaxACLRulesPerPolicy       int         `json:"acl_max_limit"`
}

type ResourceSiteStreamSettings struct {
	CustomPortNotAllow []PortRange `json:"custom_port_not_allow"`
	CustomPortAllow    []PortRange `json:"custom_port_allow"`
}

type ResourceSiteOverride struct {
	MaxBlacklistIPsPerSite *int  `json:"black_ip_limit,omitempty"`
	MaxWhitelistIPsPerSite *int  `json:"white_ip_limit,omitempty"`
	ListenDefaultHTTP80    *bool `json:"listen_default_http_80,omitempty"`
}

type ResourceStreamOverride struct {
	CustomPortNotAllow *[]PortRange `json:"custom_port_not_allow,omitempty"`
}

type ResourceSiteStreamOverride struct {
	CustomPortNotAllow *[]PortRange `json:"custom_port_not_allow,omitempty"`
	CustomPortAllow    *[]PortRange `json:"custom_port_allow,omitempty"`
}

type ResourceOverrides struct {
	Site       *ResourceSiteOverride       `json:"site,omitempty"`
	Stream     *ResourceStreamOverride     `json:"stream,omitempty"`
	SiteStream *ResourceSiteStreamOverride `json:"site_stream,omitempty"`
}

type ScopedResourceOverride struct {
	ID      string            `json:"id"`
	Scope   string            `json:"scope"`
	ScopeID string            `json:"scope_id"`
	Values  ResourceOverrides `json:"values"`
}

type ResourceLimits struct {
	MaxDomainsPerSite                int
	MaxBlacklistIPsPerSite           int
	MaxWhitelistIPsPerSite           int
	DailyURLPurgeLimit               int
	DailyDirectoryPurgeLimit         int
	DailyPrewarmLimit                int
	DailyIPUnlockLimit               int
	IPUnlockPerRequestLimit          int
	MaxCCRulesPerPolicy              int
	ListenDefaultHTTP80              bool
	DailyAccessLogDownloadLimit      int
	AccessLogTemporaryDir            string
	AccessLogRetentionHours          int
	MinimumRelatedConfigLimit        int
	RelatedConfigMaxMultiplier       int
	StreamCustomPortNotAllow         []PortRange
	StreamMinimumRelatedConfigLimit  int
	StreamRelatedConfigMaxMultiplier int
	MaxACLRulesPerPolicy             int
	CustomPortNotAllow               []PortRange
	CustomPortAllow                  []PortRange
	Overrides                        []ScopedResourceOverride

	// Runtime-only limits are not part of the competitor resource page.
	MaxSitesPerTenant        int
	MaxOriginsPerSite        int
	MaxCertificatesPerTenant int
	MaxCustomErrorPageBytes  int64
}

type ErrorPageMetadata struct {
	StatusCode       int    `json:"status_code"`
	MIMEType         string `json:"mime_type"`
	SizeBytes        int64  `json:"size_bytes"`
	SHA256           string `json:"sha256"`
	StorageObjectKey string `json:"storage_object_key"`
}

// SecretEnvelopeReference deliberately has no plaintext or ciphertext field.
// It identifies externally managed material and records only envelope metadata.
type SecretEnvelopeReference struct {
	Provider         string `json:"provider"`
	Reference        string `json:"reference"`
	KeyID            string `json:"key_id"`
	Algorithm        string `json:"algorithm"`
	CiphertextSHA256 string `json:"ciphertext_sha256"`
	Masked           bool   `json:"masked,omitempty"`
}

type SensitiveReferences struct {
	ErrorPageStorage *SecretEnvelopeReference `json:"error_page_storage,omitempty"`
}

type NodeMonitoringConfiguration struct {
	PortMode                    string    `json:"port_mode"`
	CustomPort                  *uint16   `json:"custom_port,omitempty"`
	MonitorEnabled              *bool     `json:"monitor_enabled,omitempty"`
	Protocol                    string    `json:"protocol,omitempty"`
	MonitorPort                 *uint16   `json:"monitor_port,omitempty"`
	MonitorGroups               *[]string `json:"monitor_groups,omitempty"`
	MonitorAction               string    `json:"monitor_action,omitempty"`
	FailureRatio                *uint8    `json:"failure_ratio,omitempty"`
	BandwidthOverLimit          *uint8    `json:"bandwidth_over_limit,omitempty"`
	ProbeIntervalMS             int       `json:"probe_interval_ms"`
	ProbeTimeoutMS              int       `json:"probe_timeout_ms"`
	FailureThreshold            int       `json:"failure_threshold"`
	RecoveryThreshold           int       `json:"recovery_threshold"`
	FailureDebounceMS           int       `json:"failure_debounce_ms"`
	RecoveryDebounceMS          int       `json:"recovery_debounce_ms"`
	RecoveryNotificationEnabled bool      `json:"recovery_notification_enabled"`
}

type Configuration struct {
	Nginx          NginxLimits                  `json:"nginx"`
	Defaults       DefaultReferences            `json:"defaults"`
	Resources      ResourceLimits               `json:"resources"`
	ErrorPages     []ErrorPageMetadata          `json:"error_pages"`
	Secrets        SensitiveReferences          `json:"secrets"`
	NodeMonitoring *NodeMonitoringConfiguration `json:"node_monitoring,omitempty"`
	// DDoSProtection is the node-level kernel connection protection
	// (edgeconfig.DDoSProtection); absent: nodes install none.
	DDoSProtection *edgeconfig.DDoSProtection `json:"ddos_protection,omitempty"`
	// AccessLogFields is the optional access log fields recorded
	// (edgeconfig.AccessLogFields); absent: edgeconfig.DefaultAccessLogFields.
	AccessLogFields *edgeconfig.AccessLogFields `json:"access_log_fields,omitempty"`
}

type SiteOverride struct {
	Nginx      NginxOverride
	Defaults   DefaultOverrides
	Resources  ResourceOverrides
	ErrorPages []ErrorPageMetadata
}

type Revision struct {
	ScopeID        uuid.UUID     `json:"scope_id"`
	Revision       int64         `json:"revision"`
	Status         string        `json:"status"`
	Configuration  Configuration `json:"configuration"`
	SnapshotSHA256 string        `json:"snapshot_sha256"`
	SourceRevision *int64        `json:"source_revision,omitempty"`
	CreatedBy      uuid.UUID     `json:"created_by"`
	CreatedAt      time.Time     `json:"created_at"`
	StateChangedAt time.Time     `json:"state_changed_at"`
	Replayed       bool          `json:"-"`
}

type CreateDraftRequest struct {
	ExpectedHeadRevision int64
	Configuration        Configuration
	IdempotencyKey       string
	RequestID            string
}

type PreflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type RecordPreflightRequest struct {
	Revision       int64
	ExpectedStatus string
	SnapshotSHA256 string
	Checks         []PreflightCheck
	IdempotencyKey string
	RequestID      string
}

type ActivateRequest struct {
	Revision               int64
	ExpectedActiveRevision int64
	// ExpectedPendingCategories is the set of categories the caller confirmed
	// the activation makes effective; nil means not supplied.
	ExpectedPendingCategories *[]string
	IdempotencyKey            string
	RequestID                 string

	// enforcePendingCategories is set by CategoryManager; internal callers
	// such as the bootstrap activate a whole configuration by design.
	enforcePendingCategories bool
}

type RollbackRequest struct {
	TargetRevision         int64
	ExpectedHeadRevision   int64
	ExpectedActiveRevision int64
	IdempotencyKey         string
	RequestID              string
}
