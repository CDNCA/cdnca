package analytics

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	MetricVersion           uint16 = 1
	maxCapturedHeaderValue         = 16 << 10
	maxCapturedBodyBytes           = 1 << 20
	maxCapturedBodyDepth           = 8
	maxCapturedBodyKeyBytes        = 128
	maxCapturedObjectKeys          = 128
	maxWAFDomainFilterBytes        = 4096
	maxWAFDomainFilters            = 64
	redactedCaptureValue           = "[REDACTED]"
)

var ErrInvalidInput = errors.New("invalid analytics input")

type AccessEvent struct {
	MetricVersion         uint16            `json:"metric_version"`
	EventID               string            `json:"event_id"`
	OccurredAt            time.Time         `json:"occurred_at"`
	TenantID              string            `json:"tenant_id"`
	PackageSubscriptionID string            `json:"package_subscription_id"`
	SiteID                string            `json:"site_id"`
	NodeID                string            `json:"node_id"`
	RequestID             string            `json:"request_id,omitempty"`
	TraceID               string            `json:"trace_id,omitempty"`
	ConfigVersion         string            `json:"config_version_id,omitempty"`
	Host                  string            `json:"host"`
	Path                  string            `json:"path"`
	ClientIP              string            `json:"client_ip"`
	CountryCode           string            `json:"country_code,omitempty"`
	Carrier               string            `json:"carrier,omitempty"`
	Method                string            `json:"method"`
	Protocol              string            `json:"protocol"`
	CacheStatus           string            `json:"cache_status"`
	UpstreamResult        string            `json:"upstream_result,omitempty"`
	StatusCode            uint16            `json:"status_code"`
	RequestBytes          uint64            `json:"request_bytes"`
	ResponseBytes         uint64            `json:"response_bytes"`
	DurationUS            uint64            `json:"duration_us"`
	RequestHeaders        map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders       map[string]string `json:"response_headers,omitempty"`
	RequestBody           map[string]any    `json:"request_body,omitempty"`
	ResponseBody          map[string]any    `json:"response_body,omitempty"`
	TaskID                *string           `json:"task_id"`
	InstallationID        string            `json:"-"`
	JA4                   *string           `json:"ja4"`
	OriginConnectUS       *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS     *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS         *uint64           `json:"origin_total_us"`
	ListenPort            uint16            `json:"listen_port"`
	// Blocked marks a block page the node answered itself (FX60): package
	// traffic excludes it when block_page_not_counted is on.
	Blocked bool `json:"blocked,omitempty"`
	// ClientBrowser / ClientOS are the node's User-Agent families
	// (edgeconfig.TelemetryClientBrowsers / TelemetryClientOSes); empty when
	// the node did not log them.
	ClientBrowser string `json:"client_browser,omitempty"`
	ClientOS      string `json:"client_os,omitempty"`
	// UpstreamAddr is the origin address(es) the node sent the request to
	// ($upstream_addr, fix-upstreamaddr); empty when not sent to origin or not
	// recorded. UpstreamResult is the diagnostic code, never the address.
	UpstreamAddr string `json:"upstream_addr,omitempty"`
	// Province is the client's GB/T 2260 province code from the control
	// plane's IP library, filled at ingest (never sent by nodes).
	Province string `json:"-"`
}

type SecurityEvent struct {
	MetricVersion         uint16    `json:"metric_version"`
	EventID               string    `json:"event_id"`
	OccurredAt            time.Time `json:"occurred_at"`
	TenantID              string    `json:"tenant_id"`
	PackageSubscriptionID string    `json:"package_subscription_id"`
	SiteID                string    `json:"site_id"`
	NodeID                string    `json:"node_id"`
	RequestID             string    `json:"request_id,omitempty"`
	TraceID               string    `json:"trace_id,omitempty"`
	ConfigVersion         string    `json:"config_version_id,omitempty"`
	Host                  string    `json:"host"`
	Path                  string    `json:"path"`
	ClientIP              string    `json:"client_ip"`
	CountryCode           string    `json:"country_code,omitempty"`
	Carrier               string    `json:"carrier,omitempty"`
	Method                string    `json:"method"`
	ListenPort            uint16    `json:"listen_port"`
	DestinationPort       uint16    `json:"destination_port,omitempty"`
	Protocol              string    `json:"protocol"`
	RequestClass          string    `json:"request_class"`
	EventType             string    `json:"event_type"`
	Action                string    `json:"action"`
	Severity              string    `json:"severity"`
	RuleID                string    `json:"rule_id,omitempty"`
	// Attack evidence (ge-waf S4); empty for events that carry none.
	PolicyID           string `json:"policy_id,omitempty"`
	Detector           string `json:"detector,omitempty"`
	Matched            string `json:"matched,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	RequestBodyExcerpt string `json:"request_body_excerpt,omitempty"`
	// Count: requests one aggregated line stands for (CC challenge page /
	// 429 per minute, sec-log-agg); 0 = one request.
	Count             uint32            `json:"count,omitempty"`
	StatusCode        uint16            `json:"status_code"`
	RequestBytes      uint64            `json:"request_bytes"`
	ResponseBytes     uint64            `json:"response_bytes"`
	RequestHeaders    map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders   map[string]string `json:"response_headers,omitempty"`
	RequestBody       map[string]any    `json:"request_body,omitempty"`
	ResponseBody      map[string]any    `json:"response_body,omitempty"`
	TaskID            *string           `json:"task_id"`
	InstallationID    string            `json:"-"`
	JA4               *string           `json:"ja4"`
	OriginConnectUS   *uint64           `json:"origin_connect_us"`
	OriginFirstByteUS *uint64           `json:"origin_first_byte_us"`
	OriginTotalUS     *uint64           `json:"origin_total_us"`
	// Province: see AccessEvent.Province.
	Province string `json:"-"`
}

// MaxSecurityEventCount bounds an aggregated security line's count.
const MaxSecurityEventCount = 1_000_000_000

// eventCount is the stored event_count (an unaggregated event is one).
func eventCount(count uint32) uint32 {
	if count == 0 {
		return 1
	}
	return count
}

type scopeKind uint8

const (
	scopeInvalid scopeKind = iota
	scopeAdmin
	scopeTenant
)

type Scope struct {
	kind     scopeKind
	tenantID string
}

func AdminScope() Scope {
	return Scope{kind: scopeAdmin}
}

func TenantScope(tenantID string) (Scope, error) {
	if !validUUID(tenantID) || nilUUID(tenantID) {
		return Scope{}, ErrInvalidInput
	}
	return Scope{kind: scopeTenant, tenantID: strings.ToLower(tenantID)}, nil
}

type Filter struct {
	From       time.Time
	To         time.Time
	SiteID     string
	Domain     string
	NodeID     string
	ListenPort uint16
	Timezone   string
	SnapshotAt time.Time
}

type Summary struct {
	MetricVersion       uint16  `json:"metric_version"`
	RequestCount        uint64  `json:"request_count"`
	RequestBytes        uint64  `json:"request_bytes"`
	ResponseBytes       uint64  `json:"response_bytes"`
	TotalBytes          uint64  `json:"total_bytes"`
	AverageBandwidthBPS float64 `json:"average_bandwidth_bps"`
	Status2xx           uint64  `json:"status_2xx"`
	Status3xx           uint64  `json:"status_3xx"`
	Status4xx           uint64  `json:"status_4xx"`
	Status5xx           uint64  `json:"status_5xx"`
	// SecurityEvents counts requests (an aggregated CC challenge / 429 line
	// stands for its count, sec-log-agg); SecurityEventRows the lines.
	SecurityEvents    uint64 `json:"security_events"`
	SecurityEventRows uint64 `json:"security_event_rows"`
	// CacheHitRequests / CacheHitBytes: requests answered from the edge
	// cache (cache_status HIT) and their request+response bytes; the hit
	// ratio is CacheHitRequests/RequestCount.
	CacheHitRequests uint64 `json:"cache_hit_requests"`
	CacheHitBytes    uint64 `json:"cache_hit_bytes"`
	// UniqueClientIPs is the number of distinct client addresses that sent
	// a request (exact; per trend point it is that hour's count).
	UniqueClientIPs uint64 `json:"unique_client_ips"`
}

type TrendPoint struct {
	Hour                time.Time
	MetricVersion       uint16
	RequestCount        uint64
	RequestBytes        uint64
	ResponseBytes       uint64
	TotalBytes          uint64
	AverageBandwidthBPS float64
	Status2xx           uint64
	Status3xx           uint64
	Status4xx           uint64
	Status5xx           uint64
	SecurityEvents      uint64
	SecurityEventRows   uint64
	CacheHitRequests    uint64
	CacheHitBytes       uint64
	UniqueClientIPs     uint64
}

// PeakBandwidth is the busiest BucketSeconds-long window's average bandwidth.
type PeakBandwidth struct {
	PeakBandwidthBPS uint64 `json:"peak_bandwidth_bps"`
	BucketSeconds    uint32 `json:"bucket_seconds"`
}

type BlockedIPTrendPoint struct {
	Hour           time.Time
	BlockedIPCount uint64
}

// WAFOverview contains only security events emitted by the WAF runtime. It is
// deliberately separate from the compatibility summary, which also includes
// access traffic and global-firewall events.
type WAFOverview struct {
	Attacks      uint64          `json:"attacks"`
	Blocked      uint64          `json:"blocked"`
	Intercepted  uint64          `json:"intercepted"`
	Observed     uint64          `json:"observed"`
	AutoBlocked  uint64          `json:"auto_blocked"`
	Clients      uint64          `json:"clients"`
	Trend        []WAFTrendPoint `json:"trend"`
	AttackTypes  []WAFRankItem   `json:"attack_types"`
	TopDomains   []WAFRankItem   `json:"top_domains"`
	TopClients   []WAFRankItem   `json:"top_clients"`
	TopCountries []WAFRankItem   `json:"top_countries"`
	TopProvinces []WAFRankItem   `json:"top_provinces"`
	TopCarriers  []WAFRankItem   `json:"top_carriers"`
	TopURIs      []WAFRankItem   `json:"top_uris"`
}

type WAFTrendPoint struct {
	Hour        time.Time `json:"hour"`
	Attacks     uint64    `json:"attacks"`
	Blocked     uint64    `json:"blocked"`
	Intercepted uint64    `json:"intercepted"`
	Observed    uint64    `json:"observed"`
	AutoBlocked uint64    `json:"auto_blocked"`
	Clients     uint64    `json:"clients"`
}

type WAFRankItem struct {
	Key   string `json:"key"`
	Count uint64 `json:"count"`
	// Name (attack_types only): the rule's name when Key is a policy rule or
	// an OWASP CRS rule ID; "" when unknown (ui-errmsg-1024).
	Name string `json:"name,omitempty"`
}

type TopDimension uint8

const (
	TopBySite TopDimension = iota + 1
	TopByNode
	TopByStatusCode
	TopBySecurityAction
)

type TopItem struct {
	Key            string `json:"key"`
	RequestCount   uint64 `json:"request_count"`
	ResponseBytes  uint64 `json:"response_bytes"`
	SecurityEvents uint64 `json:"security_events"`
}

func validateAccessEvent(event AccessEvent) error {
	if !validEventBase(event.MetricVersion, event.EventID, event.OccurredAt, event.TenantID, event.SiteID, event.NodeID) ||
		!validOptionalUUID(event.PackageSubscriptionID) ||
		!bounded(event.RequestID, 128) || !bounded(event.TraceID, 128) || !bounded(event.ConfigVersion, 128) ||
		!required(event.Host, 253) || !required(event.Path, 4096) || !capturePathSafe(event.Path) || net.ParseIP(event.ClientIP) == nil ||
		!bounded(event.CountryCode, 8) || !bounded(event.Carrier, 128) || !required(event.Method, 32) ||
		!required(event.Protocol, 32) || !required(event.CacheStatus, 32) || !bounded(event.UpstreamResult, 64) ||
		event.StatusCode < 100 || event.StatusCode > 599 || !validCapture(event.RequestHeaders, event.ResponseHeaders, event.RequestBody, event.ResponseBody) ||
		!validOptionalCaptureText(event.TaskID, 128) || !validInstallation(event.InstallationID) || !validOptionalCaptureText(event.JA4, 128) ||
		!validOriginTiming(event.OriginConnectUS, event.OriginFirstByteUS, event.OriginTotalUS) ||
		!validClientFamily(event.ClientBrowser, edgeconfig.TelemetryClientBrowsers) ||
		!validClientFamily(event.ClientOS, edgeconfig.TelemetryClientOSes) || !validProvince(event.Province) ||
		!bounded(event.UpstreamAddr, 64) {
		return ErrInvalidInput
	}
	return nil
}

// validClientFamily: empty or one of the node's fixed families.
func validClientFamily(value string, families []string) bool {
	if value == "" {
		return true
	}
	for _, family := range families {
		if value == family {
			return true
		}
	}
	return false
}

// validProvince: empty or a GB/T 2260 six digit code.
func validProvince(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 6 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validateSecurityEvent(event SecurityEvent) error {
	if !validEventBase(event.MetricVersion, event.EventID, event.OccurredAt, event.TenantID, event.SiteID, event.NodeID) ||
		!validOptionalUUID(event.PackageSubscriptionID) ||
		!bounded(event.RequestID, 128) || !bounded(event.TraceID, 128) || !bounded(event.ConfigVersion, 128) ||
		!required(event.Host, 253) || !required(event.Path, 4096) || !capturePathSafe(event.Path) || net.ParseIP(event.ClientIP) == nil ||
		!bounded(event.CountryCode, 8) || !bounded(event.Carrier, 128) || !validSecurityTransport(event) || !required(event.EventType, 64) ||
		!required(event.Action, 64) || !required(event.Severity, 32) || !bounded(event.RuleID, 128) ||
		(event.StatusCode != 0 && (event.StatusCode < 100 || event.StatusCode > 599)) ||
		!validCapture(event.RequestHeaders, event.ResponseHeaders, event.RequestBody, event.ResponseBody) ||
		!validOptionalCaptureText(event.TaskID, 128) || !validInstallation(event.InstallationID) || !validOptionalCaptureText(event.JA4, 128) ||
		!validOriginTiming(event.OriginConnectUS, event.OriginFirstByteUS, event.OriginTotalUS) ||
		!(event.PolicyID == "" || validUUID(event.PolicyID)) || !bounded(event.Detector, 16) ||
		len(event.Matched) > 256 || !utf8.ValidString(event.Matched) || len(event.UserAgent) > 512 ||
		!utf8.ValidString(event.UserAgent) || len(event.RequestBodyExcerpt) > 1024 || !utf8.ValidString(event.RequestBodyExcerpt) ||
		event.Count > MaxSecurityEventCount {
		return ErrInvalidInput
	}
	return nil
}

func validSecurityTransport(event SecurityEvent) bool {
	if event.Method == "" && event.ListenPort == 0 && event.DestinationPort == 0 && event.Protocol == "" && event.RequestClass == "" {
		return true
	}
	if event.RequestClass == "network" {
		if event.Method != "NETWORK" {
			return false
		}
		switch event.Protocol {
		case "tcp", "udp":
			return event.ListenPort == event.DestinationPort && event.DestinationPort > 0
		case "icmp":
			return event.ListenPort == 0 && event.DestinationPort == 0
		default:
			return false
		}
	}
	return required(event.Method, 32) && validSecurityRequestClass(event.RequestClass) &&
		event.ListenPort > 0 && event.DestinationPort == 0 &&
		(event.Protocol == "http" || event.Protocol == "https")
}

func validSecurityRequestClass(value string) bool {
	switch value {
	case "standard", "websocket", "sse", "task_stream", "import", "acme", "health", "network":
		return true
	default:
		return false
	}
}

func validEventBase(metricVersion uint16, eventID string, occurredAt time.Time, ids ...string) bool {
	if metricVersion != MetricVersion || !required(eventID, 128) || occurredAt.IsZero() || occurredAt.Location() != time.UTC {
		return false
	}
	for _, id := range ids {
		if !validUUID(id) || nilUUID(id) {
			return false
		}
	}
	for _, character := range eventID {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character)) {
			return false
		}
	}
	return true
}

func validateScopeFilter(scope Scope, filter Filter) error {
	if filter.ListenPort != 0 || filter.Domain != "" && !validDomainFilter(filter.Domain) {
		return ErrInvalidInput
	}
	return validateScopeFilterGranularity(scope, filter, time.Hour)
}

// validateSummaryScopeFilter: summarySQL filters on millisecond occurred_at,
// so the window only has to be minute aligned (10/30-minute analysis presets).
func validateSummaryScopeFilter(scope Scope, filter Filter) error {
	if filter.ListenPort != 0 || filter.Domain != "" && !validDomainFilter(filter.Domain) {
		return ErrInvalidInput
	}
	return validateScopeFilterGranularity(scope, filter, time.Minute)
}

func validateRankScopeFilter(scope Scope, filter Filter) error {
	if _, ok := normalizeRankDomainFilter(filter.Domain); !ok {
		return ErrInvalidInput
	}
	return validateScopeFilterGranularity(scope, filter, time.Minute)
}

func validateWAFScopeFilter(scope Scope, filter Filter) error {
	domains := filter.Domain
	filter.Domain = ""
	if err := validateScopeFilter(scope, filter); err != nil {
		return err
	}
	if domains != "" && !validWAFDomainFilter(domains) {
		return ErrInvalidInput
	}
	return nil
}

func validateScopeFilterGranularity(scope Scope, filter Filter, granularity time.Duration) error {
	if scope.kind != scopeAdmin && scope.kind != scopeTenant {
		return ErrInvalidInput
	}
	if scope.kind == scopeTenant && (!validUUID(scope.tenantID) || nilUUID(scope.tenantID)) {
		return ErrInvalidInput
	}
	from := filter.From.UTC()
	to := filter.To.UTC()
	if from.IsZero() || to.IsZero() || !from.Before(to) || to.Sub(from) > 31*24*time.Hour+time.Hour ||
		!from.Equal(from.Truncate(granularity)) || !to.Equal(to.Truncate(granularity)) {
		return ErrInvalidInput
	}
	if filter.SiteID != "" && (!validUUID(filter.SiteID) || nilUUID(filter.SiteID)) {
		return ErrInvalidInput
	}
	if filter.NodeID != "" && (!validUUID(filter.NodeID) || nilUUID(filter.NodeID)) {
		return ErrInvalidInput
	}
	if filter.SnapshotAt.IsZero() {
		if filter.Timezone != "" {
			return ErrInvalidInput
		}
		return nil
	}
	location, err := time.LoadLocation(filter.Timezone)
	now := time.Now().UTC()
	if !required(filter.Timezone, 64) || err != nil || location == time.Local || filter.Timezone == "Local" ||
		filter.SnapshotAt.Location() != time.UTC || !filter.SnapshotAt.Equal(filter.SnapshotAt.Truncate(time.Millisecond)) ||
		filter.SnapshotAt.After(now.Add(time.Minute)) || filter.SnapshotAt.Before(now.Add(-packageMetricFactRetention)) {
		return ErrInvalidInput
	}
	return nil
}

func validDomainFilter(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value || strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(strings.ToLower(value), ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

func normalizeRankDomainFilter(value string) (string, bool) {
	if value == "" {
		return "", true
	}
	values := strings.Fields(value)
	if len(values) == 0 || len(values) > 64 {
		return "", false
	}
	seen := make(map[string]struct{}, len(values))
	domains := make([]string, 0, len(values))
	for _, candidate := range values {
		domain := strings.ToLower(strings.TrimSuffix(candidate, "."))
		if !validDomainFilter(domain) {
			return "", false
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	return strings.Join(domains, " "), len(domains) != 0
}

func validWAFDomainFilter(value string) bool {
	if len(value) > maxWAFDomainFilterBytes {
		return false
	}
	domains := strings.Fields(value)
	if len(domains) == 0 || len(domains) > maxWAFDomainFilters || strings.Join(domains, " ") != value {
		return false
	}
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		canonical := strings.ToLower(domain)
		if canonical != domain || !validDomainFilter(domain) {
			return false
		}
		if _, duplicate := seen[domain]; duplicate {
			return false
		}
		seen[domain] = struct{}{}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func nilUUID(value string) bool {
	return strings.EqualFold(value, "00000000-0000-0000-0000-000000000000")
}

func validOptionalUUID(value string) bool {
	return value == "" || validUUID(value) && !nilUUID(value)
}

func required(value string, limit int) bool {
	return value != "" && bounded(value, limit)
}

func bounded(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func validInstallation(value string) bool {
	return value == "" || validBatchID(value)
}

func validOptionalCaptureText(value *string, limit int) bool {
	return value == nil || required(*value, limit)
}

func validOriginTiming(connect, firstByte, total *uint64) bool {
	return (connect == nil || firstByte == nil || *connect <= *firstByte) &&
		(firstByte == nil || total == nil || *firstByte <= *total) &&
		(connect == nil || total == nil || *connect <= *total)
}

func validCapture(requestHeaders, responseHeaders map[string]string, requestBody, responseBody map[string]any) bool {
	return validCapturedHeaders(requestHeaders) && validCapturedHeaders(responseHeaders) &&
		validCapturedBody(requestBody) && validCapturedBody(responseBody)
}

func validCapturedHeaders(headers map[string]string) bool {
	if len(headers) > maxCapturedObjectKeys {
		return false
	}
	for name, value := range headers {
		if http.CanonicalHeaderKey(name) != name || !validCapturedHeaderName(name) || !utf8.ValidString(value) ||
			len(value) > maxCapturedHeaderValue || captureSensitiveName(name) && value != redactedCaptureValue {
			return false
		}
	}
	return true
}

func validCapturedHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func validCapturedBody(body map[string]any) bool {
	if body == nil {
		return true
	}
	keys := len(body)
	if keys > maxCapturedObjectKeys {
		return false
	}
	for name, value := range body {
		if !validCapturedBodyKey(name) || captureSensitiveName(name) && value != redactedCaptureValue ||
			!validCapturedValue(value, 0, &keys) {
			return false
		}
	}
	encoded, err := json.Marshal(body)
	return err == nil && len(encoded) <= maxCapturedBodyBytes
}

func validCapturedValue(value any, depth int, keys *int) bool {
	if depth > maxCapturedBodyDepth {
		return false
	}
	switch typed := value.(type) {
	case nil, bool:
		return true
	case json.Number:
		encoded, err := json.Marshal(typed)
		return err == nil && json.Valid(encoded)
	case string:
		return utf8.ValidString(typed)
	case []any:
		for _, item := range typed {
			if !validCapturedValue(item, depth+1, keys) {
				return false
			}
		}
		return true
	case map[string]any:
		if len(typed) > maxCapturedObjectKeys-*keys {
			return false
		}
		*keys += len(typed)
		for name, item := range typed {
			if !validCapturedBodyKey(name) || captureSensitiveName(name) && item != redactedCaptureValue ||
				!validCapturedValue(item, depth+1, keys) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validCapturedBodyKey(value string) bool {
	return value != "" && len(value) <= maxCapturedBodyKeyBytes && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func capturePathSafe(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return false
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return false
	}
	for name, values := range query {
		if captureSensitiveName(name) {
			for _, item := range values {
				if item != redactedCaptureValue {
					return false
				}
			}
		}
	}
	return true
}

func captureSensitiveName(value string) bool {
	runes := []rune(value)
	var tokenized strings.Builder
	tokenized.Grow(len(value))
	for index, character := range runes {
		if index > 0 && unicode.IsUpper(character) &&
			(unicode.IsLower(runes[index-1]) || unicode.IsDigit(runes[index-1]) ||
				unicode.IsUpper(runes[index-1]) && index+1 < len(runes) && unicode.IsLower(runes[index+1])) {
			tokenized.WriteByte(' ')
		}
		tokenized.WriteRune(unicode.ToLower(character))
	}
	lower := tokenized.String()
	replacer := strings.NewReplacer("-", " ", "_", " ", ".", " ", "[", " ", "]", " ")
	for _, part := range strings.Fields(replacer.Replace(lower)) {
		switch part {
		case "authorization", "cookie", "password", "passwd", "token", "key", "apikey", "secret", "certificate", "cert", "privatekey", "setcookie":
			return true
		}
	}
	return lower == "set-cookie" || strings.Contains(lower, "authorization")
}
