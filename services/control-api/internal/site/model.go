package site

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	StatusActive          = "active"
	StatusDisabled        = "disabled"
	StatusPackageExpired  = "package_expired"
	StatusTrafficExceeded = "traffic_exceeded"
	StatusLocked          = "locked"
	StatusSyncing         = "syncing"
	StatusSyncFailed      = "sync_failed"

	SyncStatusSynced  = "synced"
	SyncStatusPending = "pending"
	SyncStatusFailed  = "failed"

	BatchActionEnable  = "enable"
	BatchActionDisable = "disable"
	BatchActionDelete  = "delete"
	// BatchActionSetProtocols writes the HTTPS protocol columns (migration
	// 512) of each selected site (网站协议批量设置).
	BatchActionSetProtocols = "set_protocols"

	BalanceRoundRobin = "round_robin"
	BalanceIPHash     = "ip_hash"
	BalanceURLHash    = "url_hash"
	BalanceLeastConn  = "least_conn"
	BalanceRandom     = "random"

	TLSProtocol12 = "TLSv1.2"
	TLSProtocol13 = "TLSv1.3"
)

type IPv6RuntimeState string

const (
	IPv6RuntimeDisabled IPv6RuntimeState = "disabled"
	IPv6RuntimePending  IPv6RuntimeState = "pending"
	IPv6RuntimeActive   IPv6RuntimeState = "active"
	IPv6RuntimeFailed   IPv6RuntimeState = "failed"
)

type ListenerState struct {
	IPv6DesiredEnabled bool             `json:"ipv6_desired_enabled"`
	IPv6RuntimeState   IPv6RuntimeState `json:"ipv6_runtime_state"`
}

func initialIPv6RuntimeState(enabled bool) IPv6RuntimeState {
	if enabled {
		return IPv6RuntimePending
	}
	return IPv6RuntimeDisabled
}

func nextIPv6RuntimeState(previousDesired bool, previous IPv6RuntimeState, desired bool) IPv6RuntimeState {
	if previousDesired == desired {
		return previous
	}
	return IPv6RuntimePending
}

var (
	ErrInvalidInput        = errors.New("invalid site input")
	ErrNotFound            = errors.New("site not found")
	ErrPermissionDenied    = errors.New("site permission denied")
	ErrDomainConflict      = errors.New("site domain already exists")
	ErrRevisionConflict    = errors.New("site revision conflict")
	ErrIdempotencyConflict = errors.New("site idempotency conflict")
	ErrLocked              = errors.New("site is locked")
	ErrLockStateConflict   = errors.New("site lock state conflict")
	// ErrDNSMutationInProgress: a DNS reconcile task holds an active provider
	// mutation claim on the site (089/475); retry once it finishes.
	ErrDNSMutationInProgress = errors.New("site DNS records are being changed")
	ErrOriginSectionConflict = errors.New("site origin section conflict")
	// ErrOriginAuthRequiresHTTPS: an enabled origin authentication rule
	// signs https://<bucket>; its origin must stay HTTPS on port 443.
	ErrOriginAuthRequiresHTTPS  = errors.New("site origin authentication requires HTTPS on port 443")
	ErrTLSLegacyProtocolBlocked = errors.New("legacy site TLS protocol is blocked")
	ErrTLSProtocolsInvalid      = errors.New("site TLS protocols are invalid")
	ErrTLSProfileInvalid        = errors.New("site TLS profile is invalid")
	ErrRecoveryReportStale      = errors.New("site status recovery report is stale")
	ErrRecoveryReportDuplicate  = errors.New("site status recovery report is duplicate")
	ErrRecoveryVersionMismatch  = errors.New("site status recovery active version does not match")
	ErrRecoveryUnhealthy        = errors.New("site status recovery edge version is not healthy")
)

// FieldError is an ErrInvalidInput that names the refused request field, so
// the editor can say which field to fix instead of "request fields are invalid".
type FieldError struct {
	Field  string
	Reason string
}

func (e *FieldError) Error() string { return "invalid site field " + e.Field + ": " + e.Reason }
func (e *FieldError) Unwrap() error { return ErrInvalidInput }

func fieldError(field, reason string) error { return &FieldError{Field: field, Reason: reason} }

type OperationalStatus string

const (
	OperationalStatusNormal          OperationalStatus = "normal"
	OperationalStatusPackageExpired  OperationalStatus = "package_expired"
	OperationalStatusTrafficExceeded OperationalStatus = "traffic_exceeded"
	OperationalStatusLocked          OperationalStatus = "locked"
)

type RecoveryTrigger string

const (
	RecoveryTriggerRenewal      RecoveryTrigger = "renewal"
	RecoveryTriggerTrafficTopUp RecoveryTrigger = "traffic_top_up"
	RecoveryTriggerUnlock       RecoveryTrigger = "unlock"
)

// TrafficEnforcement is the package traffic enforcement fact of a site: the
// open suspension ("suspended"), or a recovery within the display window
// ("recovered").
type TrafficEnforcement struct {
	State           string     `json:"state"`
	SubscriptionID  uuid.UUID  `json:"subscription_id"`
	SuspendedAt     time.Time  `json:"suspended_at"`
	RecoveredAt     *time.Time `json:"recovered_at"`
	RecoveredReason *string    `json:"recovered_reason"`
}

type StatusRecovery struct {
	TaskID               uuid.UUID       `json:"task_id"`
	TaskState            string          `json:"task_state"`
	Trigger              RecoveryTrigger `json:"trigger"`
	SiteRevision         int64           `json:"site_revision"`
	EdgeSourceRevision   int64           `json:"edge_source_revision"`
	DesiredEdgeVersionID *uuid.UUID      `json:"desired_edge_version_id"`
	ActiveEdgeVersionID  *uuid.UUID      `json:"active_edge_version_id"`
	Healthy              bool            `json:"healthy"`
	Attempt              uint32          `json:"attempt"`
	Sequence             uint64          `json:"sequence"`
}

func CanonicalTLSProtocols() []string {
	return []string{TLSProtocol12, TLSProtocol13}
}

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	SessionID uuid.UUID `json:"-"`
}

type Reference struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type OwnerReference struct {
	ID          uuid.UUID `json:"id"`
	DisplayID   string    `json:"display_id"`
	DisplayName string    `json:"display_name"`
}

type RegionReference struct {
	Name          string `json:"name"`
	NodeGroupName string `json:"node_group_name"`
}

type LockOperator struct {
	DisplayName string `json:"display_name"`
}

type LockState struct {
	Locked   bool          `json:"locked"`
	Reason   *string       `json:"reason"`
	LockedAt *time.Time    `json:"locked_at"`
	Operator *LockOperator `json:"operator"`
}

type Origin struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	Enabled bool   `json:"enabled"`
	// Level orders the pool's origins: 0 is the primary, 1 backup 1, and so
	// on. The edge uses a level only when every origin of the levels before
	// it (from the pool's active level) is down; within a level the balance
	// method and weights apply.
	Level int `json:"level"`
	// MaxConns bounds the edge's connections to this origin per worker
	// (nginx max_conns); 0 is unlimited.
	MaxConns int `json:"max_conns"`
	// PortInherited: the origin has no port of its own and uses the pool's
	// (HTTPPort, HTTPSPort for scheme https); Port then holds that port and
	// a written Port is ignored (migration 490).
	PortInherited bool `json:"port_inherited"`
}

type OriginPool struct {
	Origins          []Origin `json:"origins"`
	BalanceMethod    string   `json:"balance_method"`
	FailoverTries    int      `json:"failover_tries"`
	ConnectTimeoutMS int      `json:"connect_timeout_ms"`
	ReadTimeoutMS    int      `json:"read_timeout_ms"`
	// KeepaliveEnabled reuses idle origin connections for up to
	// KeepaliveIdleTimeoutMS, which must stay below the origin's own
	// keepalive timeout. Absent (older clients) means enabled: the node's
	// nginx reuses origin connections by default.
	KeepaliveEnabled       *bool `json:"keepalive_enabled"`
	KeepaliveIdleTimeoutMS int   `json:"keepalive_idle_timeout_ms"`

	// HashKey is the balance key of BalanceHash: nginx variables from
	// HashKeyVariables joined by literal text, e.g. "$cookie_uid$uri".
	HashKey string `json:"hash_key,omitempty"`
	// Sticky pins a visitor to one origin by a cookie, header or query
	// argument (BalanceSticky); the edge issues the cookie itself.
	Sticky *OriginSticky `json:"sticky,omitempty"`
	// RequestHost is the Host header sent to the origin.
	RequestHost OriginRequestHost `json:"request_host"`
	// Scheme is how the edge connects: http, https, or follow (TLS
	// listeners connect with HTTPS on HTTPSPort, plain ones with HTTP on the
	// origin's port). Follow with FollowPort is the competitor's 跟随协议和端口:
	// both protocols on the visitor's port.
	Scheme string `json:"scheme"`
	// HTTPPort (HTTP 回源端口) and HTTPSPort are the pool's origin ports: an
	// origin without its own port (PortInherited) uses HTTPPort for http and
	// follow, HTTPSPort for https; follow's HTTPS visits use HTTPSPort.
	HTTPPort  int `json:"http_port"`
	HTTPSPort int `json:"https_port"`
	// TLS applies to HTTPS connections; the origin certificate is always
	// verified.
	TLS OriginTLS `json:"tls"`
	// FollowPort sends each request to the origin on the listener's public
	// port instead of the origin's configured port.
	FollowPort bool `json:"follow_port"`
	// WebSocket is per site (absent: on, any Origin); AllowedOrigins
	// (empty: any) are the browser Origin values (scheme://host[:port]) a
	// WebSocket upgrade may carry.
	WebSocket *OriginWebSocket `json:"websocket"`
	// TrustedProxyCIDRs are peers (a CDN or load balancer in front of the
	// edge) whose X-Forwarded-For / X-Real-IP are kept; from anyone else
	// the edge replaces them with the peer's address.
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs"`
	// FailbackMode: after a higher level recovers, auto returns to it once
	// the origin probe confirms it, manual waits for the user's switch back.
	FailbackMode string `json:"failback_mode"`
	// HealthCheckPath is the path the control plane probes on every origin.
	HealthCheckPath string `json:"health_check_path"`
	// FollowRedirect (ge36): the edge follows the origin's redirects for a
	// bodyless GET/HEAD (absent: off). Needs ORIGIN_FOLLOW_REDIRECT.
	FollowRedirect *OriginFollowRedirect `json:"follow_redirect,omitempty"`
	// BackupOrigins (write only) are the backup origins in switch order,
	// one "host[:port]" per entry like basic.origins: entry n becomes level
	// n. Blank entries are ignored and repeats dropped; when present, Origins
	// holds only the primaries (level 0). Responses carry the levels.
	BackupOrigins []string `json:"backup_origins,omitempty"`

	// Site edit options (migration 466; node capability
	// SITE_EDGE_OPTIONS). Absent in a write: off / the default.
	//
	// SearchEngineOrigin (搜索引擎回源): host[:port] that search engine
	// crawlers (by User-Agent) are proxied to, bypassing the cache; "" off.
	SearchEngineOrigin string `json:"search_engine_origin"`
	// ACMEPassthrough (源站申请证书): /.well-known/acme-challenge/ goes to
	// the origin unless the node holds our own token for it (ours wins).
	ACMEPassthrough bool `json:"acme_passthrough"`
	// ResponseBuffering / RequestBuffering (数据实时返回 / 数据实时发送):
	// false proxies without buffering, only requests the cache does not
	// serve (a cached request keeps buffering). Absent: true.
	ResponseBuffering *bool `json:"response_buffering"`
	RequestBuffering  *bool `json:"request_buffering"`
	// L2 (L2 配置): package (the line group's L2, default), off (straight
	// to the origin) or custom (only the L2 nodes of L2ConfigID).
	L2Mode     string     `json:"l2_mode"`
	L2ConfigID *uuid.UUID `json:"l2_config_id"`

	// OriginAuthEnabled (回源鉴权开关, migration 490): false keeps the site's
	// origin auth rules but signs nothing. Absent: true.
	OriginAuthEnabled *bool `json:"origin_auth_enabled"`
}

const (
	SiteL2Package = "package"
	SiteL2Off     = "off"
	SiteL2Custom  = "custom"
)

const (
	FailbackAuto   = "auto"
	FailbackManual = "manual"
	// MaxOriginLevel bounds the levels (0 primary .. 15).
	MaxOriginLevel = 15
)

type OriginSticky struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

type OriginRequestHost struct {
	Mode  string `json:"mode"`
	Value string `json:"value,omitempty"`
}

type OriginTLS struct {
	// SNI is sent in the TLS handshake; empty uses the origin request Host
	// (without its port).
	SNI string `json:"sni,omitempty"`
	// Trust is system (the node's CA store) or custom (CAPEM only).
	Trust string `json:"trust"`
	CAPEM string `json:"ca_pem,omitempty"`
}

// OriginFollowRedirect: Enabled follows a 301/302/303/307/308 Location, at
// most MaxHops times (1..5, default 3); CrossOrigin also follows a Location
// whose host is not the visitor's host, a site domain or a pool origin
// (off: such a redirect is returned to the visitor).
type OriginFollowRedirect struct {
	Enabled     bool `json:"enabled"`
	MaxHops     int  `json:"max_hops"`
	CrossOrigin bool `json:"cross_origin"`
}

const (
	DefaultFollowRedirectHops = 3
	MaxFollowRedirectHops     = 5
)

type OriginWebSocket struct {
	Enabled        bool     `json:"enabled"`
	AllowedOrigins []string `json:"allowed_origins"`
}

const (
	BalanceHash   = "hash"
	BalanceSticky = "sticky"

	OriginStickyCookie = "cookie"
	OriginStickyHeader = "header"
	OriginStickyArg    = "arg"

	OriginRequestHostVisitor = "visitor"
	// OriginRequestHostVisitorPort (访问域名+端口): the visitor's host with
	// the port it visited.
	OriginRequestHostVisitorPort = "visitor_port"
	OriginRequestHostOrigin      = "origin"
	OriginRequestHostCustom      = "custom"

	OriginSchemeHTTP   = "http"
	OriginSchemeHTTPS  = "https"
	OriginSchemeFollow = "follow"

	OriginTrustSystem = "system"
	OriginTrustCustom = "custom"
	// OriginTrustNone: 不校验源站证书 (源站自签证书时选，存在中间人风险).
	// Publication needs ORIGIN_TLS_NO_VERIFY.
	OriginTrustNone = "none"
)

// DefaultKeepaliveIdleTimeoutMS is the node nginx's own upstream keepalive
// idle timeout (1.29.7+), below common origin timeouts (nginx 75s, IIS 120s);
// origins with shorter timeouts (Apache, Node.js: 5s) need a lower value.
const DefaultKeepaliveIdleTimeoutMS = 60_000

// KeepsDefaultOriginReuse reports the node default: reuse with the default
// idle timeout. Only other settings are published to nodes.
func (pool OriginPool) KeepsDefaultOriginReuse() bool {
	return pool.KeepaliveEnabled != nil && *pool.KeepaliveEnabled && pool.KeepaliveIdleTimeoutMS == DefaultKeepaliveIdleTimeoutMS
}

type Site struct {
	ID           uuid.UUID       `json:"id"`
	DisplayID    string          `json:"display_id"`
	ScopeID      uuid.UUID       `json:"scope_id"`
	Owner        *OwnerReference `json:"owner"`
	Domain       string          `json:"domain"`
	Domains      []string        `json:"domains"`
	HTTPPorts    []string        `json:"http_ports"`
	HTTPSPorts   []string        `json:"https_ports"`
	ListenPorts  []string        `json:"listen_ports"`
	Origins      []string        `json:"origins"`
	OriginPool   OriginPool      `json:"origin_pool"`
	CNAME        string          `json:"cname"`
	TLSProtocols []string        `json:"tls_protocols"`
	// TLS profile (migration 367).
	TLSCipherPreset string `json:"tls_cipher_preset"`
	// TLSCipherSuites: the custom preset's ordered TLS 1.2 list
	// (migration 520); nil with the other presets.
	TLSCipherSuites []string      `json:"tls_cipher_suites"`
	TLSOCSPStapling bool          `json:"tls_ocsp_stapling"`
	TLSClientAuth   string        `json:"tls_client_auth"`
	TLSClientCAPEM  string        `json:"tls_client_ca_pem"`
	ListenerState   ListenerState `json:"listener_state"`
	HTTPSEnabled    bool          `json:"https_enabled"`
	// HTTPSCertificateBound (be-gap-2): projected on reads, like the list item's.
	HTTPSCertificateBound bool `json:"https_certificate_bound"`
	ForceHTTPS            bool `json:"force_https"`
	HTTPSRedirectPort     int  `json:"https_redirect_port"`

	// HTTPS protocols (migration 515): HTTP/2 and HTTP/3 on
	// by default; TLSPreferServerCiphers nil follows the cipher preset
	// (modern off, compatible/legacy on).
	HTTP2Enabled           bool  `json:"http2_enabled"`
	HTTP3Enabled           bool  `json:"http3_enabled"`
	TLSPreferServerCiphers *bool `json:"tls_prefer_server_ciphers"`

	// CacheSharedAcrossDomains: every domain of the site reads one cache
	// (keyed by the primary domain); false keys each object by the request
	// host.
	CacheSharedAcrossDomains bool              `json:"cache_shared_across_domains"`
	CacheStatusHeader        bool              `json:"cache_status_header"` // 响应头显示缓存状态 (X-CDN-Cache, migration 472), on by default
	Enabled                  bool              `json:"enabled"`
	Package                  *Reference        `json:"package"`
	PackageID                *uuid.UUID        `json:"package_id"`
	PackageSubscriptionID    *uuid.UUID        `json:"package_subscription_id"`
	CNAMEMode                *string           `json:"cname_mode"`
	CNAMEDomain              *string           `json:"cname_domain"`
	CNAMEHostname            *string           `json:"cname_hostname"`
	CNAMEState               *string           `json:"cname_state"`
	CNAMEFailureCode         *string           `json:"cname_failure_code"` // why the current CNAME task failed
	CNAMETaskID              *uuid.UUID        `json:"cname_task_id"`
	CNAMECurrentRevision     *int64            `json:"cname_current_revision"`
	CNAMELKGRevision         *int64            `json:"cname_lkg_revision"`
	GroupID                  *uuid.UUID        `json:"group_id"`
	GroupName                *string           `json:"group_name"`
	RegionID                 *uuid.UUID        `json:"region_id"`
	NodeGroupID              *uuid.UUID        `json:"node_group_id"`
	Region                   *RegionReference  `json:"region"`
	Status                   string            `json:"status"`
	OperationalStatus        OperationalStatus `json:"status_state"`
	StatusRecovery           *StatusRecovery   `json:"status_recovery"`
	// SyncStatus is derived (site_sync_status_503, PJ-C02): synced / pending /
	// failed from the site's latest automatic publication.
	SyncStatus          string    `json:"sync_status"`
	Lock                LockState `json:"lock"`
	IsDefault           bool      `json:"is_default"`
	Revision            int64     `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	ipv6RuntimeRevision int64
	ownerID             uuid.UUID
	packageName         *string
	regionName          *string
	nodeGroupName       *string

	TrafficEnforcement *TrafficEnforcement `json:"traffic_enforcement"`

	// PackageExpiresAt is the period end (ends_at) of the site's package
	// subscription; nil without one (site-backend6).
	PackageExpiresAt *time.Time `json:"package_expires_at"`

	// AccessReadiness: 接入状态, projected on reads.
	AccessReadiness *AccessReadiness `json:"access_readiness"`
	// PackageUnavailableReason: why the site is not served for lack of a
	// valid package; nil while its package is valid.
	PackageUnavailableReason *string `json:"package_unavailable_reason"`
}

// Reasons a site is not served for lack of a valid package (
// only sites on an enabled, undeleted package are published).
const (
	PackageUnavailableNoPackage = "no_package"
	PackageUnavailableDisabled  = "package_disabled"
	PackageUnavailableDeleted   = "package_deleted"
)

// packageUnavailableReason maps the site's subscription and its validity
// (valid / disabled / deleted, nil when the row is gone) to the reason.
func packageUnavailableReason(subscriptionID *uuid.UUID, state *string) *string {
	reason := ""
	switch {
	case subscriptionID == nil:
		// Community edition: a site needs no package (it is served on the
		// platform default line group), so no package is not a reason.
		return nil
	case state == nil || *state == "deleted":
		reason = PackageUnavailableDeleted
	case *state == "disabled":
		reason = PackageUnavailableDisabled
	default:
		return nil
	}
	return &reason
}

// PackageExpiredDays is how many whole days ago expiresAt passed at now:
// 0 before it and on the day it passes (less than 24 hours after), as the
// competitor shows "已过期 N 天".
func PackageExpiredDays(expiresAt, now time.Time) int {
	if !now.After(expiresAt) {
		return 0
	}
	return int(now.Sub(expiresAt) / (24 * time.Hour))
}

// PackageRemainingDays is the competitor's 剩余 N 天: the 24-hour days left
// until expiresAt, rounded up (Math.ceil), 0 once it has passed. Like
// PackageExpiredDays it counts elapsed time, not calendar days, so the
// result does not depend on the time zone the expiry is shown in.
func PackageRemainingDays(expiresAt, now time.Time) int {
	if !expiresAt.After(now) {
		return 0
	}
	left := expiresAt.Sub(now)
	days := int(left / (24 * time.Hour))
	if left%(24*time.Hour) != 0 {
		days++
	}
	return days
}

type ListItem struct {
	ID                    uuid.UUID       `json:"id"`
	DisplayID             string          `json:"display_id"`
	Revision              int64           `json:"version"`
	Owner                 *OwnerReference `json:"owner"`
	Domain                string          `json:"domain"`
	Domains               []string        `json:"domains"`
	ListenPorts           []string        `json:"listen_ports"`
	Origins               []string        `json:"origins"`
	CNAME                 string          `json:"cname"`
	PackageSubscriptionID *uuid.UUID      `json:"package_subscription_id"`
	CNAMEState            *string         `json:"cname_state"`
	CNAMEFailureCode      *string         `json:"cname_failure_code"`
	CNAMEDomain           *string         `json:"cname_domain"`
	CNAMETaskID           *uuid.UUID      `json:"cname_task_id"`
	CNAMECurrentRevision  *int64          `json:"cname_current_revision"`
	CNAMELKGRevision      *int64          `json:"cname_lkg_revision"`
	HTTPSEnabled          bool            `json:"https_enabled"`
	// HTTPSCertificateBound (WEB-C01/C05): the site's current certificate
	// binding is a bind; HTTPS enabled without it is not serving yet.
	HTTPSCertificateBound bool              `json:"https_certificate_bound"`
	Package               *Reference        `json:"package"`
	GroupName             *string           `json:"group_name"`
	Region                *RegionReference  `json:"region"`
	Status                string            `json:"status"`
	OperationalStatus     OperationalStatus `json:"status_state"`
	StatusRecovery        *StatusRecovery   `json:"status_recovery"`
	ListenerState         ListenerState     `json:"listener_state"`
	Lock                  LockState         `json:"lock"`
	CreatedAt             time.Time         `json:"created_at"`

	TrafficEnforcement *TrafficEnforcement `json:"traffic_enforcement"`
	// AutoDNS: 建站「DNS API（自动添加记录）」 task (nil: none asked for).
	AutoDNS *AutoDNSStatus `json:"auto_dns"`
	// AccessReadiness: 接入状态, read from stored facts.
	AccessReadiness *AccessReadiness `json:"access_readiness"`
	// PackageUnavailableReason: see Site.PackageUnavailableReason.
	PackageUnavailableReason *string `json:"package_unavailable_reason"`
}

type SiteFields struct {
	Domain      string
	Domains     []string
	HTTPPorts   []string
	HTTPSPorts  []string
	IPv6Enabled bool
	// IPv6Omitted: a create that left ipv6_enabled out (the owner's 默认设置
	// > IPv6 decides, else off). Updates always carry it.
	IPv6Omitted  bool `json:"-"`
	Origins      []string
	CNAME        string
	TLSProtocols []string
	// TLS profile: nil keeps the current value; on create, the system
	// default (cipher preset and OCSP stapling) or off (client verification).
	TLSCipherPreset *string
	// TLSCipherSuites goes with TLSCipherPreset: the custom preset's list,
	// nil with any other (and is stored as such); nil with no preset keeps
	// the stored pair.
	TLSCipherSuites []string
	TLSOCSPStapling *bool
	TLSClientAuth   *string
	// TLSClientCAPEM is the client CA bundle (with client verification on).
	TLSClientCAPEM *string
	HTTPSEnabled   bool

	// HTTP2Enabled / HTTP3Enabled: nil keeps the current value; on create,
	// the owner's 默认设置, else on. TLSPreferServerCiphers: nil keeps the
	// current value (on create, the 默认设置, else by preset);
	// TLSPreferServerCiphersReset stores "by preset" again.
	HTTP2Enabled                *bool
	HTTP3Enabled                *bool
	TLSPreferServerCiphers      *bool
	TLSPreferServerCiphersReset bool

	// ForceHTTPS redirects plain HTTP to HTTPSRedirectPort (0: the lowest
	// HTTPS port). Nil keeps the current value; on create, the system default.
	ForceHTTPS        *bool
	HTTPSRedirectPort *int
	// CacheSharedAcrossDomains (所有域名共用缓存): nil keeps the current value;
	// on create, off.
	CacheSharedAcrossDomains *bool
	CacheStatusHeader        *bool // 响应头显示缓存状态: nil keeps the current value; on create, on
	Enabled                  bool
	Status                   string
	IsDefault                bool
	PackageID                *uuid.UUID
	PackageSubscriptionID    *uuid.UUID
	CNAMEMode                string
	CNAMEDomain              string
	CNAMEHostname            string
	CNAMERegenerate          bool
	PackageName              string
	GroupID                  *uuid.UUID
	GroupName                string
	RegionID                 *uuid.UUID
	RegionName               string
	NodeGroupID              *uuid.UUID
	NodeGroupName            string
	// tlsProtocolsDefaulted: the request named no TLS protocols (normalize
	// filled the baseline). An update then keeps the stored value; a create
	// takes the system default's.
	tlsProtocolsDefaulted bool
	// hstsDefault: the owner's 默认设置 > HSTS for a new HTTPS site (nil:
	// the platform default).
	hstsDefault *bool
	// gzipDefault: the owner's 默认设置 > Gzip (nil: the node-wide default).
	gzipDefault *bool
	originHosts []string
	originItems []Origin
}

type CreateRequest struct {
	TargetScopeID uuid.UUID
	OwnerUserID   uuid.UUID
	Fields        SiteFields
	OriginPool    *OriginPool
	// DNSProviderID (建站「DNS API（自动添加记录）」, migration 490): the
	// owner's DNS account that gets a CNAME of every site domain to the
	// site CNAME after the site is created. A failure there never fails the
	// create; it shows on the site (解析检测) and is retried.
	DNSProviderID *uuid.UUID
	// DefaultDNSAllowed: the creator may write DNS records (dns.manage), so
	// the owner's 默认设置 > DNS API fills a create that named no account.
	DefaultDNSAllowed bool
	// DefaultHTTPPolicyAllowed: the creator may manage HTTP policies
	// (http_policies.manage), so 默认设置 > 源站请求头 / 上传限制 become the
	// new site's HTTP policy (fp-site5b).
	DefaultHTTPPolicyAllowed bool
	// userDefaults: the owner's defaults read by Service.Create, copied into
	// the new site in the store's tx (rule libraries, HTTP policy).
	userDefaults siteCreationUserDefaults
	// dnsProviderDefaulted: DNSProviderID came from that default; an account
	// since disabled or revoked then skips the records instead of failing.
	dnsProviderDefaulted bool
	// preauthorized: see DeleteRequest.preauthorized.
	preauthorized bool
	// defaultPool: the request named no origin pool, so the pool's load
	// balancing follows the platform default (系统设置 > 网站默认) unless the
	// owner's own default (网站列表 > 默认设置) set it.
	defaultPool    bool
	IdempotencyKey string
	RequestID      string
}

type UpdateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Fields           SiteFields
	IdempotencyKey   string
	RequestID        string
	// SourceIP is the caller's address for the audit trail (empty: unknown).
	SourceIP string
}

type UpdateOriginRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Pool             OriginPool
	IdempotencyKey   string
	RequestID        string
}

type DeleteRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	// preauthorized: Transfer already took the IAM scope locks for both
	// tenants (one lock set per transaction, iam_scope_locks_v1).
	preauthorized bool
}

type LockRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Reason           string
	IdempotencyKey   string
	RequestID        string
}

type UnlockRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
}

type StatusRecoveryRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Trigger          RecoveryTrigger
	IdempotencyKey   string
	RequestID        string
}

type RecoveryReportCursor struct {
	Attempt  uint32
	Sequence uint64
}

type ListFilter struct {
	Page      int
	Limit     int
	Domain    string
	Domains   []string
	OriginIP  string
	SiteIDs   []uuid.UUID
	Owner     string
	PackageID *uuid.UUID
	// Package (package name substring) and Site (domain substring or exact
	// display ID) are the name forms of PackageID / SiteIDs.
	Package       string
	Site          string
	GroupID       *uuid.UUID
	RegionID      *uuid.UUID
	NodeGroupID   *uuid.UUID
	CNAMEDomain   string
	CNAMEHostname string
	HTTPPort      string
	HTTPSPort     string
	HTTPSEnabled  *bool
	Enabled       *bool
	Status        string
	IsDefault     *bool
	SyncStatus    string
}

type ListResult struct {
	Items []ListItem `json:"items"`
	Total int64      `json:"total"`
	Page  int        `json:"page"`
	Limit int        `json:"limit"`
}

type WriteResult struct {
	Site     Site
	Replayed bool
}

type DeleteResult struct {
	Replayed bool
}

type BatchActionItem struct {
	ID               uuid.UUID `json:"id"`
	ExpectedRevision int64     `json:"expected_version"`
}

type BatchActionRequest struct {
	Action string            `json:"action"`
	Items  []BatchActionItem `json:"items"`
	// Protocols: set_protocols only (required there, rejected otherwise).
	Protocols      *BatchProtocols `json:"protocols,omitempty"`
	IdempotencyKey string          `json:"-"`
	RequestID      string          `json:"-"`
}

// BatchProtocols is what set_protocols writes on every selected site: a nil
// HTTP2Enabled/HTTP3Enabled/TLSPreferServerCiphers keeps the site's value;
// TLSPreferServerCiphersReset stores "by the cipher preset" (NULL) again.
// At least one change is required.
type BatchProtocols struct {
	HTTP2Enabled                *bool `json:"http2_enabled,omitempty"`
	HTTP3Enabled                *bool `json:"http3_enabled,omitempty"`
	TLSPreferServerCiphers      *bool `json:"tls_prefer_server_ciphers,omitempty"`
	TLSPreferServerCiphersReset bool  `json:"tls_prefer_server_ciphers_reset,omitempty"`
}

type BatchItemError struct {
	Code string `json:"code"`
}

type BatchActionItemResult struct {
	ID     uuid.UUID       `json:"id"`
	Status string          `json:"status"`
	Site   *Site           `json:"site,omitempty"`
	Error  *BatchItemError `json:"error,omitempty"`
}

type BatchActionResult struct {
	Items    []BatchActionItemResult `json:"items"`
	Replayed bool                    `json:"-"`
}
