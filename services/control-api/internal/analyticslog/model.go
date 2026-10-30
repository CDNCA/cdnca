package analyticslog

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	ReadPermission = "sites.read"
	DefaultLimit   = uint16(50)
	MaxLimit       = uint16(100)
)

var (
	ErrInvalidInput          = errors.New("invalid analytics log input")
	ErrInvalidConfiguration  = errors.New("invalid analytics log configuration")
	ErrPermissionDenied      = errors.New("analytics log permission denied")
	ErrScopeForbidden        = errors.New("analytics log scope forbidden")
	ErrCapabilityUnsupported = errors.New("analytics log capability unsupported")
	ErrStorageUnavailable    = errors.New("analytics log storage unavailable")
	ErrInvalidResponse       = errors.New("invalid analytics log storage response")
	ErrResponseTooLarge      = errors.New("analytics log response too large")
	ErrConflict              = errors.New("analytics log export conflict")
	ErrNotFound              = errors.New("analytics log export not found")
	ErrExpired               = errors.New("analytics log export grant expired")
)

type Audience uint8

const (
	AudienceInvalid Audience = iota
	AudiencePlatform
	AudienceTenant
)

type Actor struct {
	ScopeKind   string
	TenantID    string
	ActorID     string
	ScopeID     string
	SessionID   string
	Permissions []string
}

type QueryRequest struct {
	Audience Audience
	TenantID string
	Filter   Filter
	Limit    uint16
	Cursor   string
}

// SecurityLogActions are the security event actions the security log lists:
// every hit the WAF overview counts (block, challenge, log = observed,
// temporary_ban = auto blocked). allow (an allowlist match) is not a hit.
var SecurityLogActions = []string{"block", "challenge", "log", "temporary_ban"}

type Filter struct {
	From             time.Time
	To               time.Time
	SiteID           string
	Host             string
	NodeID           string
	ClientIP         string
	URIPath          string
	URIPathPrefix    bool
	StatusCode       uint16
	HasStatus        bool
	Method           string
	Protocol         string
	CacheStatus      string
	UpstreamResult   string
	ContentType      string
	UserAgent        string
	RequestBytesMin  *uint64
	RequestBytesMax  *uint64
	ResponseBytesMin *uint64
	ResponseBytesMax *uint64
	CountryCode      string
	Carrier          string
	// Action narrows the security log to one of SecurityLogActions ("" = all;
	// sec-log-agg: CC challenge pages are aggregated lines with a count).
	Action string
	// EventType narrows the security log to one event type (waf, cc, ...);
	// the WAF page pins waf so it lists what the WAF overview counts.
	EventType            string
	JA4                  string
	OriginConnectUSMin   *uint64
	OriginConnectUSMax   *uint64
	OriginFirstByteUSMin *uint64
	OriginFirstByteUSMax *uint64
	OriginTotalUSMin     *uint64
	OriginTotalUSMax     *uint64
}

// CCBan is one site + client IP + CC rule that auto-banned the client in the
// window, aggregated from cc/temporary_ban security events (NF34).
type CCBan struct {
	SiteID        string    `json:"site_id"`
	Host          string    `json:"host"`
	ClientIP      string    `json:"client_ip"`
	RuleID        string    `json:"rule_id"`
	BanCount      uint64    `json:"ban_count"`
	FirstBannedAt time.Time `json:"first_banned_at"`
	LastBannedAt  time.Time `json:"last_banned_at"`
}

type CCBanPage struct {
	Items      []CCBan
	Truncated  bool
	SnapshotAt time.Time
}

type AccessLog struct {
	EventID           string            `json:"event_id"`
	OccurredAt        time.Time         `json:"-"`
	SiteID            string            `json:"site_id"`
	NodeID            string            `json:"node_id"`
	RequestID         string            `json:"request_id"`
	TraceID           string            `json:"trace_id"`
	ConfigVersion     string            `json:"config_version_id"`
	Host              string            `json:"host"`
	ListenPort        uint16            `json:"listen_port"`
	URIPath           string            `json:"uri_path"`
	ClientIP          string            `json:"client_ip"`
	CountryCode       string            `json:"country_code"`
	Carrier           string            `json:"carrier"`
	Method            string            `json:"method"`
	Protocol          string            `json:"protocol"`
	CacheStatus       string            `json:"cache_status"`
	UpstreamResult    string            `json:"upstream_result"`
	UpstreamAddr      string            `json:"upstream_addr"`
	StatusCode        uint16            `json:"status_code"`
	RequestBytes      uint64            `json:"request_bytes"`
	ResponseBytes     uint64            `json:"response_bytes"`
	DurationUS        uint64            `json:"duration_us"`
	TaskID            *string           `json:"task_id"`
	InstallationID    string            `json:"installation_id"`
	RequestHeaders    map[string]string `json:"request_headers"`
	ResponseHeaders   map[string]string `json:"response_headers"`
	RequestBody       map[string]any    `json:"request_body"`
	ResponseBody      map[string]any    `json:"response_body"`
	JA4               *string           `json:"ja4"`
	OriginConnectUS   *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS     *uint64           `json:"origin_total_us"`
}

type BlockEvent struct {
	EventID           string            `json:"event_id"`
	OccurredAt        time.Time         `json:"-"`
	SiteID            string            `json:"site_id"`
	NodeID            string            `json:"node_id"`
	RequestID         string            `json:"request_id"`
	TraceID           string            `json:"trace_id"`
	ConfigVersion     string            `json:"config_version_id"`
	Host              string            `json:"host"`
	URIPath           string            `json:"uri_path"`
	URIQuery          string            `json:"uri_query"` // P14: the logged query, sensitive values ***, ≤ 512 bytes
	ClientIP          string            `json:"client_ip"`
	CountryCode       string            `json:"country_code"`
	Carrier           string            `json:"carrier"`
	EventType         string            `json:"event_type"`
	Action            string            `json:"action"`
	Severity          string            `json:"severity"`
	RuleID            string            `json:"rule_id"`
	StatusCode        uint16            `json:"status_code"`
	RequestBytes      uint64            `json:"request_bytes"`
	ResponseBytes     uint64            `json:"response_bytes"`
	TaskID            *string           `json:"task_id"`
	InstallationID    string            `json:"installation_id"`
	RequestHeaders    map[string]string `json:"request_headers"`
	ResponseHeaders   map[string]string `json:"response_headers"`
	RequestBody       map[string]any    `json:"request_body"`
	ResponseBody      map[string]any    `json:"response_body"`
	JA4               *string           `json:"ja4"`
	OriginConnectUS   *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS     *uint64           `json:"origin_total_us"`
	// Attack evidence (ge-waf S4): the deciding policy, detector, matched
	// fragment, User-Agent and request body excerpt ("" when absent).
	PolicyID           string `json:"policy_id"`
	Detector           string `json:"detector"`
	Matched            string `json:"matched"`
	UserAgent          string `json:"user_agent"`
	RequestBodyExcerpt string `json:"request_body_excerpt"`
	// Count: requests the line stands for (a CC challenge page / 429 is
	// logged once per site, client IP, rule, action and minute; sec-log-agg).
	Count uint64 `json:"count"`
}

// maxSecurityEventCount bounds a row's count (the ingest bound).
const maxSecurityEventCount = 1_000_000_000

// maxSecurityQueryBytes bounds a security event's query (the node's bound).
const maxSecurityQueryBytes = 512

type AccessPage struct {
	Items      []AccessLog
	NextCursor string
	SnapshotAt time.Time
}

type BlockEventPage struct {
	Items      []BlockEvent
	NextCursor string
	SnapshotAt time.Time
}

// scope is one tenant, or every tenant of the platform when tenantID is ""
// (platform audience without a tenant filter).
type scope struct {
	tenantID string
}

func (value scope) platform() bool { return value.tenantID == "" }

func validScope(value scope) bool { return value.platform() || validUUID(value.tenantID) }

func validateFilter(filter Filter) error {
	from := filter.From.UTC()
	to := filter.To.UTC()
	if from.IsZero() || to.IsZero() || !from.Before(to) || to.Sub(from) > 31*24*time.Hour ||
		from.Nanosecond()%int(time.Millisecond) != 0 || to.Nanosecond()%int(time.Millisecond) != 0 {
		return ErrInvalidInput
	}
	if filter.SiteID != "" && !validUUID(filter.SiteID) {
		return ErrInvalidInput
	}
	if filter.Host != "" && !validHostListFilter(filter.Host) {
		return ErrInvalidInput
	}
	if !validTokenFilter(filter.EventType, 64) {
		return ErrInvalidInput
	}
	if filter.NodeID != "" && !validUUID(filter.NodeID) {
		return ErrInvalidInput
	}
	if filter.ClientIP != "" {
		address, err := netip.ParseAddr(filter.ClientIP)
		if err != nil || address.Zone() != "" {
			return ErrInvalidInput
		}
	}
	if filter.HasStatus && filter.StatusCode != 0 && (filter.StatusCode < 100 || filter.StatusCode > 599) {
		return ErrInvalidInput
	}
	if !validURIPathFilter(filter.URIPath) || (filter.URIPathPrefix && filter.URIPath == "") || !validTokenFilter(filter.Method, 32) || !validProtocolFilter(filter.Protocol) ||
		!validTokenFilter(filter.CacheStatus, 32) || !validTokenFilter(filter.UpstreamResult, 64) ||
		!validContentTypeFilter(filter.ContentType) || !validTextFilter(filter.UserAgent, 512) ||
		!validUint64Range(filter.RequestBytesMin, filter.RequestBytesMax) ||
		!validUint64Range(filter.ResponseBytesMin, filter.ResponseBytesMax) || !validCountryCode(filter.CountryCode) ||
		!validTextFilter(filter.Carrier, 128) || !validTextFilter(filter.JA4, 128) ||
		!validUint64Range(filter.OriginConnectUSMin, filter.OriginConnectUSMax) ||
		!validUint64Range(filter.OriginFirstByteUSMin, filter.OriginFirstByteUSMax) ||
		!validUint64Range(filter.OriginTotalUSMin, filter.OriginTotalUSMax) {
		return ErrInvalidInput
	}
	return nil
}

func validContentTypeFilter(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.Count(value, "/") != 1 {
		return value == ""
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$&^_.+-/", character)) {
			return false
		}
	}
	return true
}

func validUint64Range(minimum, maximum *uint64) bool {
	return minimum == nil || maximum == nil || *minimum <= *maximum
}

// uriPathMatches applies the exact (default) or prefix URI path filter.
func uriPathMatches(path string, filter Filter) bool {
	if filter.URIPath == "" {
		return true
	}
	if filter.URIPathPrefix {
		return strings.HasPrefix(path, filter.URIPath)
	}
	return path == filter.URIPath
}

func validURIPathFilter(value string) bool {
	return value == "" || (len(value) <= 4096 && safeURIPath(value) == value && validTextFilter(value, 4096))
}

func normalizeFilter(filter Filter) Filter {
	filter.From = filter.From.UTC()
	filter.To = filter.To.UTC()
	filter.SiteID = strings.ToLower(filter.SiteID)
	filter.Host = strings.ToLower(strings.TrimSuffix(filter.Host, "."))
	filter.NodeID = strings.ToLower(filter.NodeID)
	if filter.ClientIP != "" {
		filter.ClientIP = netip.MustParseAddr(filter.ClientIP).String()
	}
	filter.Method = strings.ToUpper(filter.Method)
	filter.CountryCode = strings.ToUpper(filter.CountryCode)
	filter.ContentType = strings.ToLower(filter.ContentType)
	return filter
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == strings.ToLower(value)
}

func validTokenFilter(value string, limit int) bool {
	if value == "" {
		return true
	}
	if len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character)) {
			return false
		}
	}
	return true
}

// maxHostFilterDomains matches the WAF overview's domain list limit.
const maxHostFilterDomains = 64

// validHostListFilter accepts one host or a space-separated list of distinct
// hosts, the same domain list the WAF overview filters by.
func validHostListFilter(value string) bool {
	hosts := strings.Split(value, " ")
	if len(hosts) > maxHostFilterDomains {
		return false
	}
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		key := strings.ToLower(host)
		if _, duplicate := seen[key]; duplicate || host == "" || !validHostFilter(host) {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

// hostFilterMatches reports whether host is one of the filter's hosts.
func hostFilterMatches(host, filter string) bool {
	if filter == "" {
		return true
	}
	for _, candidate := range strings.Split(filter, " ") {
		if strings.EqualFold(host, candidate) {
			return true
		}
	}
	return false
}

func validHostFilter(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.HasSuffix(value, ".") {
		return value == ""
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	return true
}

func validProtocolFilter(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 32 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("./_-", character)) {
			return false
		}
	}
	return true
}

func validCountryCode(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 8 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return false
		}
	}
	return true
}

func validTextFilter(value string, limit int) bool {
	if value == "" {
		return true
	}
	if !utf8.ValidString(value) || len(value) > limit || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validOpaqueCursor(value string) bool {
	if len(value) == 0 || len(value) > maxLogCursorBytes {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maxLogCursorBytes {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	var cursor logCursor
	if decoder.Decode(&cursor) != nil || decoder.Decode(&struct{}{}) != io.EOF || cursor.Version != 1 ||
		cursor.SnapshotMS <= 0 || cursor.OccurredAtMS <= 0 || !validEventID(cursor.EventID) {
		return false
	}
	query, err := base64.RawURLEncoding.DecodeString(cursor.Query)
	return err == nil && len(query) == 32
}

func safeURIPath(value string) string {
	if !strings.HasPrefix(value, "/") {
		return ""
	}
	if index := strings.IndexAny(value, "?#"); index >= 0 {
		value = value[:index]
	}
	return value
}
