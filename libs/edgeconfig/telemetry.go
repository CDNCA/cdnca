package edgeconfig

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const TelemetryIdentityManifestPath = "telemetry/identity-v1.json"

const telemetryIdentitySchemaVersion = 1

// The identity manifest lists every website listener of a configuration
// scope. Site runtime v8 delivers a scope as site objects with no 1000-site
// bound, so the manifest is bounded only as a safety ceiling (about 1.2 KiB a
// listener).
const (
	MaxTelemetryIdentityListeners = 1 << 22
	MaxTelemetryIdentityBytes     = 1 << 30
)

const (
	telemetryCaptureSchemaVersion = 1
	defaultCaptureValueBytes      = 4096
	defaultCaptureBodyBytes       = 64 << 10
	defaultCaptureEventBytes      = 1 << 20
	maximumCaptureListEntries     = 128
)

type TelemetryCapturePolicy struct {
	SchemaVersion              uint16
	Revision                   uint64
	EvidenceDigest             string
	Enabled                    bool
	Methods                    []string
	URIPrefixes                []string
	RequestHeaderAllowlist     []string
	ResponseHeaderAllowlist    []string
	RequestBodyFieldAllowlist  []string
	ResponseBodyFieldAllowlist []string
	MaxValueBytes              int
	MaxBodyBytes               int
	MaxEventBytes              int
}

type TelemetrySiteCapturePolicy struct {
	SiteID                     string   `json:"site_id"`
	Domain                     string   `json:"domain"`
	ListenPort                 uint16   `json:"listen_port"`
	Revision                   uint64   `json:"revision,omitempty"`
	EvidenceDigest             string   `json:"evidence_digest,omitempty"`
	Enabled                    bool     `json:"enabled"`
	Methods                    []string `json:"methods"`
	URIPrefixes                []string `json:"uri_prefixes"`
	RequestHeaderAllowlist     []string `json:"request_header_allowlist"`
	ResponseHeaderAllowlist    []string `json:"response_header_allowlist"`
	RequestBodyFieldAllowlist  []string `json:"request_body_field_allowlist"`
	ResponseBodyFieldAllowlist []string `json:"response_body_field_allowlist"`
	MaxValueBytes              int      `json:"max_value_bytes"`
	MaxBodyBytes               int      `json:"max_body_bytes"`
	MaxEventBytes              int      `json:"max_event_bytes"`
}

type TelemetryCapturePolicyManifest struct {
	SchemaVersion uint16                       `json:"schema_version"`
	Sites         []TelemetrySiteCapturePolicy `json:"sites"`
}

type TelemetrySourceCapabilities struct {
	SchemaVersion uint16 `json:"schema_version"`
	TaskBinding   bool   `json:"task_binding"`
	JA4           bool   `json:"ja4"`
}

type TelemetrySiteIdentity struct {
	SiteID                string `json:"site_id"`
	PackageSubscriptionID string `json:"package_subscription_id,omitempty"`
	Domain                string `json:"domain"`
	ListenPort            uint16 `json:"listen_port"`
	NamespaceID           string `json:"namespace_id"`
	AccessLogPath         string `json:"access_log_path"`
	SecurityLogPath       string `json:"security_log_path"`
}

type TelemetryIdentityManifest struct {
	SchemaVersion      int                            `json:"schema_version"`
	ConfigVersionID    string                         `json:"config_version_id"`
	ConfigRevision     uint64                         `json:"config_revision"`
	TenantID           string                         `json:"tenant_id"`
	InstallationID     string                         `json:"installation_id,omitempty"`
	Sites              []TelemetrySiteIdentity        `json:"sites"`
	CapturePolicy      TelemetryCapturePolicyManifest `json:"capture_policy"`
	SourceCapabilities TelemetrySourceCapabilities    `json:"source_capabilities"`
}

func ParseTelemetryIdentityManifest(content []byte) (TelemetryIdentityManifest, error) {
	if len(content) == 0 || len(content) > MaxTelemetryIdentityBytes || RejectDuplicateJSONKeys(content) != nil {
		return TelemetryIdentityManifest{}, ErrInvalidConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest TelemetryIdentityManifest
	if err := decoder.Decode(&manifest); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		manifest.SchemaVersion != telemetryIdentitySchemaVersion || !versionPattern.MatchString(manifest.ConfigVersionID) ||
		!uuidPattern.MatchString(manifest.TenantID) || len(manifest.Sites) == 0 || len(manifest.Sites) > MaxTelemetryIdentityListeners ||
		(manifest.InstallationID != "" && !uuidPattern.MatchString(manifest.InstallationID)) ||
		manifest.CapturePolicy.SchemaVersion != telemetryCaptureSchemaVersion || len(manifest.CapturePolicy.Sites) != len(manifest.Sites) ||
		manifest.SourceCapabilities.SchemaVersion != 1 {
		return TelemetryIdentityManifest{}, ErrInvalidConfig
	}
	type listenerKey struct {
		port   uint16
		domain string
	}
	seen := make(map[listenerKey]struct{}, len(manifest.Sites))
	siteDomains := make(map[string]string, len(manifest.Sites))
	for index, site := range manifest.Sites {
		domain, err := normalizeSiteDomainName(site.Domain)
		if err != nil || domain != site.Domain || !uuidPattern.MatchString(site.SiteID) ||
			(site.PackageSubscriptionID != "" && !uuidPattern.MatchString(site.PackageSubscriptionID)) || site.ListenPort == 0 ||
			site.NamespaceID != CacheSiteNamespaceID(manifest.TenantID, site.SiteID) ||
			!safeAbsolutePath(site.AccessLogPath) || !safeAbsolutePath(site.SecurityLogPath) ||
			site.AccessLogPath == site.SecurityLogPath {
			return TelemetryIdentityManifest{}, ErrInvalidConfig
		}
		if !bindSiteDomain(siteDomains, site.SiteID, site.Domain) {
			return TelemetryIdentityManifest{}, ErrInvalidConfig
		}
		key := listenerKey{port: site.ListenPort, domain: site.Domain}
		if _, exists := seen[key]; exists || index > 0 &&
			(manifest.Sites[index-1].ListenPort > site.ListenPort ||
				manifest.Sites[index-1].ListenPort == site.ListenPort && manifest.Sites[index-1].Domain >= site.Domain) {
			return TelemetryIdentityManifest{}, ErrInvalidConfig
		}
		seen[key] = struct{}{}
	}
	for index, policy := range manifest.CapturePolicy.Sites {
		site := manifest.Sites[index]
		if policy.SiteID != site.SiteID || policy.Domain != site.Domain || policy.ListenPort != site.ListenPort ||
			!validManifestCapturePolicy(policy) {
			return TelemetryIdentityManifest{}, ErrInvalidConfig
		}
	}
	return manifest, nil
}

func telemetryIdentityManifest(spec normalizedSpec) []byte {
	sites := make([]TelemetrySiteIdentity, 0, len(spec.Sites))
	policies := make([]TelemetrySiteCapturePolicy, 0, len(spec.Sites))
	for _, site := range spec.Sites {
		access, security := telemetryLogPaths(spec.StateRoot, spec.ConfigVersionID, site.ID, site.ListenPort)
		sites = append(sites, TelemetrySiteIdentity{
			SiteID: site.ID, PackageSubscriptionID: site.PackageSubscriptionID,
			Domain: site.Domain, ListenPort: site.ListenPort,
			NamespaceID:   CacheSiteNamespaceID(spec.TenantID, site.ID),
			AccessLogPath: access, SecurityLogPath: security,
		})
		policies = append(policies, manifestCapturePolicy(site.ID, site.Domain, site.ListenPort, site.TelemetryCapture))
	}
	content, err := json.Marshal(TelemetryIdentityManifest{
		SchemaVersion: telemetryIdentitySchemaVersion, ConfigVersionID: spec.ConfigVersionID,
		ConfigRevision: spec.ConfigRevision, TenantID: spec.TenantID, InstallationID: spec.InstallationID, Sites: sites,
		CapturePolicy:      TelemetryCapturePolicyManifest{SchemaVersion: telemetryCaptureSchemaVersion, Sites: policies},
		SourceCapabilities: TelemetrySourceCapabilities{SchemaVersion: 1},
	})
	if err != nil {
		panic("normalized telemetry identity became invalid")
	}
	return append(content, '\n')
}

func ValidateTelemetryCacheReleaseIdentity(telemetry TelemetryIdentityManifest, cache CachePolicyManifest) error {
	if telemetry.ConfigRevision == 0 || telemetry.ConfigVersionID != cache.ConfigVersionID ||
		telemetry.ConfigRevision != cache.ConfigRevision || telemetry.TenantID != cache.TenantID ||
		len(telemetry.Sites) != len(cache.Listeners) {
		return ErrInvalidConfig
	}
	type listenerIdentity struct {
		siteID      string
		domain      string
		listenPort  uint16
		namespaceID string
	}
	type listenerTuple struct {
		domain     string
		listenPort uint16
	}
	telemetryDomains := make(map[string]string, len(telemetry.Sites))
	telemetryTuples := make(map[listenerTuple]struct{}, len(telemetry.Sites))
	for _, site := range telemetry.Sites {
		tuple := listenerTuple{domain: site.Domain, listenPort: site.ListenPort}
		if !bindSiteDomain(telemetryDomains, site.SiteID, site.Domain) {
			return ErrInvalidConfig
		}
		if _, duplicate := telemetryTuples[tuple]; duplicate {
			return ErrInvalidConfig
		}
		telemetryTuples[tuple] = struct{}{}
	}
	cacheDomains := make(map[string]string, len(cache.Listeners))
	cacheTuples := make(map[listenerTuple]struct{}, len(cache.Listeners))
	listeners := make(map[listenerIdentity]int, len(cache.Listeners))
	for _, listener := range cache.Listeners {
		tuple := listenerTuple{domain: listener.Domain, listenPort: listener.ListenPort}
		if !bindSiteDomain(cacheDomains, listener.SiteID, listener.Domain) {
			return ErrInvalidConfig
		}
		if _, duplicate := cacheTuples[tuple]; duplicate {
			return ErrInvalidConfig
		}
		cacheTuples[tuple] = struct{}{}
		key := listenerIdentity{
			siteID: listener.SiteID, domain: listener.Domain,
			listenPort: listener.ListenPort, namespaceID: listener.NamespaceID,
		}
		listeners[key]++
	}
	for _, site := range telemetry.Sites {
		key := listenerIdentity{
			siteID: site.SiteID, domain: site.Domain,
			listenPort: site.ListenPort, namespaceID: site.NamespaceID,
		}
		if listeners[key] == 0 {
			return ErrInvalidConfig
		}
		listeners[key]--
	}
	return nil
}

func bindSiteDomain(bindings map[string]string, siteID, domain string) bool {
	bound, exists := bindings[siteID]
	if exists {
		return bound == domain
	}
	bindings[siteID] = domain
	return true
}

func normalizeTelemetryCapturePolicy(policy TelemetryCapturePolicy) (TelemetryCapturePolicy, error) {
	zero := policy.SchemaVersion == 0 && policy.Revision == 0 && policy.EvidenceDigest == "" && !policy.Enabled && policy.Methods == nil && policy.URIPrefixes == nil && policy.RequestHeaderAllowlist == nil &&
		policy.ResponseHeaderAllowlist == nil && policy.RequestBodyFieldAllowlist == nil && policy.ResponseBodyFieldAllowlist == nil &&
		policy.MaxValueBytes == 0 && policy.MaxBodyBytes == 0 && policy.MaxEventBytes == 0
	if zero {
		policy.SchemaVersion = telemetryCaptureSchemaVersion
	} else if policy.SchemaVersion != telemetryCaptureSchemaVersion {
		return TelemetryCapturePolicy{}, ErrInvalidConfig
	}
	if policy.MaxValueBytes == 0 {
		policy.MaxValueBytes = defaultCaptureValueBytes
	}
	if policy.MaxBodyBytes == 0 {
		policy.MaxBodyBytes = defaultCaptureBodyBytes
	}
	if policy.MaxEventBytes == 0 {
		policy.MaxEventBytes = defaultCaptureEventBytes
	}
	var err error
	if policy.Methods, err = canonicalCaptureMethods(policy.Methods); err != nil {
		return TelemetryCapturePolicy{}, err
	}
	if policy.URIPrefixes, err = canonicalCaptureURIPrefixes(policy.URIPrefixes); err != nil {
		return TelemetryCapturePolicy{}, err
	}
	if policy.RequestHeaderAllowlist, err = canonicalCaptureList(policy.RequestHeaderAllowlist, true); err != nil {
		return TelemetryCapturePolicy{}, err
	}
	if policy.ResponseHeaderAllowlist, err = canonicalCaptureList(policy.ResponseHeaderAllowlist, true); err != nil {
		return TelemetryCapturePolicy{}, err
	}
	if policy.RequestBodyFieldAllowlist, err = canonicalCaptureList(policy.RequestBodyFieldAllowlist, false); err != nil {
		return TelemetryCapturePolicy{}, err
	}
	if policy.ResponseBodyFieldAllowlist, err = canonicalCaptureList(policy.ResponseBodyFieldAllowlist, false); err != nil {
		return TelemetryCapturePolicy{}, err
	}
	if !validTelemetryCaptureIdentity(policy.Revision, policy.EvidenceDigest) ||
		policy.MaxValueBytes < 1 || policy.MaxValueBytes > 16<<10 || policy.MaxBodyBytes < 1 || policy.MaxBodyBytes > 1<<20 ||
		policy.MaxEventBytes < 256 || policy.MaxEventBytes > 1<<20 || !policy.Enabled &&
		(len(policy.Methods) != 0 || len(policy.URIPrefixes) != 0 || len(policy.RequestHeaderAllowlist) != 0 || len(policy.ResponseHeaderAllowlist) != 0 ||
			len(policy.RequestBodyFieldAllowlist) != 0 || len(policy.ResponseBodyFieldAllowlist) != 0) {
		return TelemetryCapturePolicy{}, ErrInvalidConfig
	}
	return policy, nil
}

func manifestCapturePolicy(siteID, domain string, listenPort uint16, policy TelemetryCapturePolicy) TelemetrySiteCapturePolicy {
	return TelemetrySiteCapturePolicy{
		SiteID: siteID, Domain: domain, ListenPort: listenPort,
		Revision: policy.Revision, EvidenceDigest: policy.EvidenceDigest, Enabled: policy.Enabled,
		Methods:                    append([]string{}, policy.Methods...),
		URIPrefixes:                append([]string{}, policy.URIPrefixes...),
		RequestHeaderAllowlist:     append([]string{}, policy.RequestHeaderAllowlist...),
		ResponseHeaderAllowlist:    append([]string{}, policy.ResponseHeaderAllowlist...),
		RequestBodyFieldAllowlist:  append([]string{}, policy.RequestBodyFieldAllowlist...),
		ResponseBodyFieldAllowlist: append([]string{}, policy.ResponseBodyFieldAllowlist...),
		MaxValueBytes:              policy.MaxValueBytes, MaxBodyBytes: policy.MaxBodyBytes, MaxEventBytes: policy.MaxEventBytes,
	}
}

func validManifestCapturePolicy(policy TelemetrySiteCapturePolicy) bool {
	domain, domainErr := normalizeSiteDomainName(policy.Domain)
	if !uuidPattern.MatchString(policy.SiteID) || domainErr != nil || domain != policy.Domain || policy.ListenPort == 0 ||
		policy.RequestHeaderAllowlist == nil || policy.ResponseHeaderAllowlist == nil ||
		policy.RequestBodyFieldAllowlist == nil || policy.ResponseBodyFieldAllowlist == nil {
		return false
	}
	normalized, err := normalizeTelemetryCapturePolicy(TelemetryCapturePolicy{
		SchemaVersion: telemetryCaptureSchemaVersion, Revision: policy.Revision,
		EvidenceDigest: policy.EvidenceDigest, Enabled: policy.Enabled,
		Methods: policy.Methods, URIPrefixes: policy.URIPrefixes,
		RequestHeaderAllowlist: policy.RequestHeaderAllowlist, ResponseHeaderAllowlist: policy.ResponseHeaderAllowlist,
		RequestBodyFieldAllowlist: policy.RequestBodyFieldAllowlist, ResponseBodyFieldAllowlist: policy.ResponseBodyFieldAllowlist,
		MaxValueBytes: policy.MaxValueBytes, MaxBodyBytes: policy.MaxBodyBytes, MaxEventBytes: policy.MaxEventBytes,
	})
	return err == nil && equalStrings(normalized.Methods, policy.Methods) && equalStrings(normalized.URIPrefixes, policy.URIPrefixes) &&
		equalStrings(normalized.RequestHeaderAllowlist, policy.RequestHeaderAllowlist) &&
		equalStrings(normalized.ResponseHeaderAllowlist, policy.ResponseHeaderAllowlist) &&
		equalStrings(normalized.RequestBodyFieldAllowlist, policy.RequestBodyFieldAllowlist) &&
		equalStrings(normalized.ResponseBodyFieldAllowlist, policy.ResponseBodyFieldAllowlist)
}

func validTelemetryCaptureIdentity(revision uint64, digest string) bool {
	if revision == 0 || digest == "" {
		return revision == 0 && digest == ""
	}
	if revision > 1<<53-1 || len(digest) != 64 || strings.ToLower(digest) != digest {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32
}

func canonicalCaptureMethods(values []string) ([]string, error) {
	if len(values) > maximumCaptureListEntries {
		return nil, ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || !ascii(value) {
			return nil, ErrInvalidConfig
		}
		value = strings.ToUpper(value)
		switch value {
		case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		default:
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func canonicalCaptureURIPrefixes(values []string) ([]string, error) {
	if len(values) > maximumCaptureListEntries {
		return nil, ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
			value[0] != '/' || strings.ContainsAny(value, "?#\r\n\x00") {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func canonicalCaptureList(values []string, headers bool) ([]string, error) {
	if len(values) > maximumCaptureListEntries {
		return nil, ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if headers {
			for _, character := range value {
				if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
					(character >= '0' && character <= '9') || character == '-') {
					return nil, ErrInvalidConfig
				}
			}
			value = http.CanonicalHeaderKey(value)
		} else if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
			strings.ContainsAny(value, "\r\n\x00") || !ascii(value) {
			return nil, ErrInvalidConfig
		}
		if value == "" {
			return nil, ErrInvalidConfig
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func telemetryLogPaths(stateRoot, configVersionID, siteID string, listenPort uint16) (string, string) {
	directory := filepath.Join(stateRoot, "shared", "telemetry", configVersionID, siteID, strconv.Itoa(int(listenPort)))
	return filepath.Join(directory, "access.jsonl"), filepath.Join(directory, "security.jsonl")
}

// TelemetryLogPaths is where a listener's access and security logs live.
func TelemetryLogPaths(stateRoot, configVersionID, siteID string, listenPort uint16) (string, string) {
	return telemetryLogPaths(stateRoot, configVersionID, siteID, listenPort)
}

func ValidateTelemetryIdentityPaths(manifest TelemetryIdentityManifest, stateRoot string) error {
	if !safeAbsolutePath(stateRoot) {
		return ErrInvalidConfig
	}
	for _, site := range manifest.Sites {
		access, security := telemetryLogPaths(stateRoot, manifest.ConfigVersionID, site.SiteID, site.ListenPort)
		if site.AccessLogPath != access || site.SecurityLogPath != security {
			return ErrInvalidConfig
		}
	}
	return nil
}

// telemetryAccessJSON and telemetrySecurityJSON are the access and security
// log lines of every site runtime (the per-site servers of v7 and the shared
// servers of dynamic routing, RenderDynamicRoutingTelemetryHTTP): one field
// list, so the two runtimes cannot drift apart.
const (
	telemetryAccessJSON   = `{"schema_version":1,"type":"access.v1","occurred_at":"$time_iso8601","tenant_id":"$cdnca_tenant_id","site_id":"$cdnca_site_id","node_id":"$cdnca_node_id","config_version_id":"$cdnca_config_version_id","installation_id":"","task_id":null,"request_id":"$request_id","trace_id":"$http_traceparent","host":"$host","path":"$uri","client_ip":"$remote_addr","method":"$request_method","protocol":"$server_protocol","connection":"$connection","connection_requests":$connection_requests,"cache_status":"$cdnca_telemetry_cache_status","status_code":$status,"request_bytes":$request_length,"response_bytes":$bytes_sent,"duration_us":$cdnca_duration_us,"request_headers":null,"response_headers":null,"request_body":null,"response_body":null,"ja4":"$cdnca_ja4_log","origin_connect_us":$cdnca_origin_connect_us,"origin_first_byte_us":$cdnca_origin_first_byte_us,"origin_total_us":$cdnca_origin_total_us,"blocked":$cdnca_security_block_page_log,"client_browser":"$cdnca_client_browser","client_os":"$cdnca_client_os","upstream_addr":"$cdnca_upstream_addr_log"}`
	telemetrySecurityJSON = `{"schema_version":1,"type":"security.v1","occurred_at":"$time_iso8601","tenant_id":"$cdnca_tenant_id","site_id":"$cdnca_site_id","node_id":"$cdnca_node_id","config_version_id":"$cdnca_config_version_id","installation_id":"","task_id":null,"request_id":"$request_id","trace_id":"$http_traceparent","host":"$host","path":"$uri","client_ip":"$remote_addr","method":"$request_method","listen_port":$server_port,"protocol":"$scheme","request_class":"$cdnca_security_request_class","status_code":$status,"request_bytes":$request_length,"response_bytes":$bytes_sent,"security_type":"$cdnca_security_type","action":"$cdnca_security_action","severity":"$cdnca_security_severity","rule_id":"$cdnca_security_rule_id","policy_id":"$cdnca_security_policy_id","detector":"$cdnca_security_detector","matched":"$cdnca_security_matched","user_agent":"$cdnca_security_user_agent","request_body_excerpt":"$cdnca_security_body","request_headers":null,"response_headers":null,"request_body":null,"response_body":null,"ja4":"$cdnca_ja4_log","origin_connect_us":$cdnca_origin_connect_us,"origin_first_byte_us":$cdnca_origin_first_byte_us,"origin_total_us":$cdnca_origin_total_us}`
)

// renderTelemetryMaps writes the http{} level maps the log lines read.
// ja4Map: $cdnca_ja4_log is a map filled per server (v7); the dynamic
// routing runtime declares it as a plain variable its log phase writes.
func renderTelemetryMaps(output *strings.Builder, ja4Map bool) {
	output.WriteString("  map $upstream_cache_status $cdnca_telemetry_cache_status { '' BYPASS; default $upstream_cache_status; }\n")
	output.WriteString("  map \"$http_upgrade|$http_connection|$http_accept|$uri\" $cdnca_security_request_class {\n    default standard;\n    ~*^websocket\\|[^|]*upgrade\\| websocket;\n    ~*^[^|]*\\|[^|]*\\|[^|]*text/event-stream\\| sse;\n    ~*^[^|]*\\|[^|]*\\|[^|]*\\|/\\.well-known/acme-challenge/ acme;\n    ~*^[^|]*\\|[^|]*\\|[^|]*\\|/(?:healthz|readyz)$ health;\n  }\n")
	renderTelemetryTimingMap(output, "$upstream_connect_time", "$cdnca_origin_connect_us", "cdnca_origin_connect")
	renderTelemetryTimingMap(output, "$upstream_header_time", "$cdnca_origin_first_byte_us", "cdnca_origin_first_byte")
	renderTelemetryTimingMap(output, "$upstream_response_time", "$cdnca_origin_total_us", "cdnca_origin_total")
	renderTelemetryDurationMap(output)
	renderTelemetryClientMaps(output)
	// $cdnca_ja4_log is the request's JA4 or empty. It is filled per server
	// (renderTelemetryJA4) from the native module's $cdnca_ja4 through Lua,
	// which reads an unknown variable as nil, so a runtime without the module
	// still passes nginx -t and logs "" (the Agent records it as null).
	if ja4Map {
		output.WriteString("  map $host $cdnca_ja4_log { default \"\"; }\n")
	}
	// FX60: $cdnca_security_block_page is "1" when the node answered a block page
	// itself; the access log carries it as a JSON boolean.
	output.WriteString("  map $cdnca_security_block_page $cdnca_security_block_page_log { \"1\" true; default false; }\n")
	// ge-waf S4: the security log's User-Agent, at most 512 bytes (longer
	// values are cut; the agent refuses lines over its event size).
	output.WriteString("  map $http_user_agent $cdnca_security_user_agent { \"~^(?<cdnca_ua>.{0,512})\" $cdnca_ua; default \"\"; }\n")
	// fix-upstreamaddr: the access log's origin address ($upstream_addr, every
	// tried upstream), at most 64 bytes without a trailing separator (the
	// Agent refuses longer or space-padded values); "" when not sent to origin.
	output.WriteString("  map $upstream_addr $cdnca_upstream_addr_log { \"~^(?<cdnca_upaddr>.{0,63}[^ ,])\" $cdnca_upaddr; default \"\"; }\n")
}

func renderTelemetryFormats(output *strings.Builder) {
	renderTelemetryMaps(output, true)
	output.WriteString("  log_format cdnca_access_json escape=json '" + telemetryAccessJSON + "';\n")
	output.WriteString("  log_format cdnca_security_json escape=json '" + telemetrySecurityJSON + "';\n")
	output.WriteString("  log_format cdnca_url_auth_json escape=json '{\"schema_version\":1,\"type\":\"security.url_auth.v1\",\"occurred_at\":\"$time_iso8601\",\"tenant_id\":\"$cdnca_tenant_id\",\"site_id\":\"$cdnca_site_id\",\"node_id\":\"$cdnca_node_id\",\"config_version_id\":\"$cdnca_config_version_id\",\"request_id\":\"$request_id\",\"trace_id\":\"$cdnca_urlauth_trace_id\",\"action\":\"$cdnca_urlauth_action\",\"reason\":\"$cdnca_urlauth_reason\",\"status\":$cdnca_urlauth_status,\"policy_version\":$cdnca_urlauth_policy_version,\"policy_event\":\"$cdnca_urlauth_policy_event\"}';\n")
	output.WriteString("  log_format cdnca_access_capture_json escape=none '$cdnca_access_telemetry_json';\n")
	output.WriteString("  log_format cdnca_security_capture_json escape=none '$cdnca_security_telemetry_json';\n")
}

// renderTelemetryJA4 sets $cdnca_ja4_log for one server (see
// renderTelemetryFormats).
func renderTelemetryJA4(output *strings.Builder) {
	output.WriteString("    set_by_lua_block $cdnca_ja4_log { return ngx.var." + JA4Variable + " or \"\" }\n")
}

func renderTelemetryTimingMap(output *strings.Builder, source, target, prefix string) {
	fmt.Fprintf(output, "  map %s %s {\n", source, target)
	output.WriteString("    '' null;\n    '-' null;\n    ~^0\\.000$ 0;\n")
	fmt.Fprintf(output, "    ~^0\\.00(?<%s_1>[1-9])$ ${%s_1}000;\n", prefix, prefix)
	fmt.Fprintf(output, "    ~^0\\.0(?<%s_2>[1-9][0-9])$ ${%s_2}000;\n", prefix, prefix)
	fmt.Fprintf(output, "    \"~^0\\.(?<%s_3>[1-9][0-9]{2})$\" ${%s_3}000;\n", prefix, prefix)
	fmt.Fprintf(output, "    \"~^(?<%s_s>[1-9][0-9]{0,5})\\.(?<%s_f>[0-9]{3})$\" ${%s_s}${%s_f}000;\n", prefix, prefix, prefix, prefix)
	output.WriteString("    default invalid;\n  }\n")
}

// renderTelemetryDurationMap maps $request_time ("seconds.milliseconds", from
// the first request byte read to the last response byte sent) to
// $cdnca_duration_us. Bandwidth peak and 95th percentile spread a request's
// bytes over [occurred_at-duration, occurred_at] with it, so a long download
// is not billed as if every byte left in the second it finished. Anything
// unexpected becomes 0 (a point sample), never an invalid log line.
func renderTelemetryDurationMap(output *strings.Builder) {
	output.WriteString("  map $request_time $cdnca_duration_us {\n")
	output.WriteString("    ~^0\\.000$ 0;\n")
	output.WriteString("    ~^0\\.00(?<cdnca_duration_1>[1-9])$ ${cdnca_duration_1}000;\n")
	output.WriteString("    ~^0\\.0(?<cdnca_duration_2>[1-9][0-9])$ ${cdnca_duration_2}000;\n")
	output.WriteString("    \"~^0\\.(?<cdnca_duration_3>[1-9][0-9]{2})$\" ${cdnca_duration_3}000;\n")
	output.WriteString("    \"~^(?<cdnca_duration_s>[1-9][0-9]{0,6})\\.(?<cdnca_duration_f>[0-9]{3})$\" ${cdnca_duration_s}${cdnca_duration_f}000;\n")
	output.WriteString("    default 0;\n  }\n")
}

// Client browser and OS families for the history reports (parsed from the
// User-Agent on the node). Each map yields one fixed token, so the log
// and ClickHouse keep a low-cardinality value and never the raw User-Agent.
// The first matching regex wins: specific browsers precede the engines whose
// tokens they also carry (Edge/Opera/WeChat send "Chrome/", Chrome sends
// "Safari/", Android sends "Linux").
var (
	TelemetryClientBrowsers = []string{"bot", "wechat", "qq", "uc", "samsung", "edge", "opera", "firefox", "chrome", "safari", "ie", "other"}
	TelemetryClientOSes     = []string{"harmonyos", "android", "ios", "windows", "macos", "chromeos", "linux", "other"}
)

func renderTelemetryClientMaps(output *strings.Builder) {
	output.WriteString(`  map $http_user_agent $cdnca_client_browser {
    "~*(bot|spider|crawl|slurp|curl/|wget/|python-requests|go-http-client|okhttp|java/|libwww|httpclient)" bot;
    ~*MicroMessenger wechat;
    "~*(MQQBrowser|QQBrowser| QQ/)" qq;
    "~*(UCBrowser|UCWEB)" uc;
    ~*SamsungBrowser samsung;
    "~*(Edg/|Edge/|EdgA/|EdgiOS/)" edge;
    "~*(OPR/|Opera)" opera;
    "~*(Firefox/|FxiOS/)" firefox;
    "~*(Chrome/|CriOS/|Chromium/)" chrome;
    ~*Safari/ safari;
    "~*(MSIE |Trident/)" ie;
    default other;
  }
  map $http_user_agent $cdnca_client_os {
    "~*(HarmonyOS|OpenHarmony)" harmonyos;
    ~*Android android;
    "~*(iPhone|iPad|iPod|CPU OS )" ios;
    ~*Windows windows;
    "~*(Macintosh|Mac OS X)" macos;
    ~*CrOS chromeos;
    ~*Linux linux;
    default other;
  }
`)
}

func renderTelemetryCapture(output *strings.Builder, policy TelemetryCapturePolicy) {
	if len(policy.ResponseBodyFieldAllowlist) > 0 {
		output.WriteString("      body_filter_by_lua_block {\n")
		renderTelemetryCaptureBodyFilterLua(output, policy)
		output.WriteString("      }\n")
	}
	output.WriteString("      log_by_lua_block {\n")
	renderTelemetryCaptureLogLua(output, policy)
	output.WriteString("      }\n")
}

// renderTelemetryCaptureBodyFilterLua is the body of the capture's
// body_filter_by_lua_block (response body fields only).
func renderTelemetryCaptureBodyFilterLua(output *strings.Builder, policy TelemetryCapturePolicy) {
	fmt.Fprintf(output, "        local methods, prefixes = %s, %s\n", luaTelemetryArray(policy.Methods), luaTelemetryArray(policy.URIPrefixes))
	output.WriteString("        local method, uri, method_ok, uri_ok = ngx.var.request_method or \"\", ngx.var.uri or \"\", #methods == 0, #prefixes == 0\n")
	output.WriteString("        for _, value in ipairs(methods) do if method == value then method_ok = true; break end end\n")
	output.WriteString("        for _, value in ipairs(prefixes) do if string.sub(uri, 1, #value) == value then uri_ok = true; break end end\n")
	fmt.Fprintf(output, "        if method_ok and uri_ok then local c=ngx.arg[1]; if c and c ~= \"\" then local x=ngx.ctx.cdnca_capture_chunks or {}; local n=(ngx.ctx.cdnca_capture_bytes or 0)+#c; ngx.ctx.cdnca_capture_bytes=n; if n>%d then ngx.ctx.cdnca_capture_invalid=true else x[#x+1]=c; ngx.ctx.cdnca_capture_chunks=x end end end\n", policy.MaxBodyBytes)
}

// renderTelemetryCaptureLogLua is the body of the capture's log_by_lua_block:
// it builds the captured access and security events.
func renderTelemetryCaptureLogLua(output *strings.Builder, policy TelemetryCapturePolicy) {
	output.WriteString("        local cjson = require(\"cjson.safe\")\n        local null = cjson.null\n        local redacted = \"[REDACTED]\"\n")
	fmt.Fprintf(output, "        local max_value, max_body, max_event = %d, %d, %d\n", policy.MaxValueBytes, policy.MaxBodyBytes, policy.MaxEventBytes)
	fmt.Fprintf(output, "        local capture_methods = %s\n", luaTelemetryArray(policy.Methods))
	fmt.Fprintf(output, "        local capture_uri_prefixes = %s\n", luaTelemetryArray(policy.URIPrefixes))
	fmt.Fprintf(output, "        local request_header_names = %s\n", luaTelemetryArray(policy.RequestHeaderAllowlist))
	fmt.Fprintf(output, "        local response_header_names = %s\n", luaTelemetryArray(policy.ResponseHeaderAllowlist))
	fmt.Fprintf(output, "        local request_body_names = %s\n", luaTelemetryArray(policy.RequestBodyFieldAllowlist))
	fmt.Fprintf(output, "        local response_body_names = %s\n", luaTelemetryArray(policy.ResponseBodyFieldAllowlist))
	output.WriteString(telemetryCaptureLogBody)
}

// telemetryCaptureLogBody is the capture log Lua after the policy locals
// (max_value, max_body, max_event, capture_methods, capture_uri_prefixes and
// the four allowlists). The dynamic routing runtime runs the same text
// (edge/openresty/dynroute/cdnca_telemetry.lua, TestDynamicRoutingCaptureLuaIsV7).
const telemetryCaptureLogBody = `        local function capture_matches(method, uri)
          local method_ok, uri_ok = #capture_methods == 0, #capture_uri_prefixes == 0
          for _, value in ipairs(capture_methods) do if method == value then method_ok = true; break end end
          for _, value in ipairs(capture_uri_prefixes) do if string.sub(uri, 1, #value) == value then uri_ok = true; break end end
          return method_ok and uri_ok
        end
        local capture_enabled = capture_matches(ngx.var.request_method or "", ngx.var.uri or "")
        if not capture_enabled then request_header_names, response_header_names, request_body_names, response_body_names = {}, {}, {}, {} end
        local function sensitive(name)
			  local segmented = name:gsub("([A-Z])([A-Z][a-z])", "%1 %2")
			  segmented = segmented:gsub("([a-z0-9])([A-Z])", "%1 %2")
			  local lowered = string.lower(segmented)
		  for token in string.gmatch(lowered, "[a-z0-9]+") do
		    if token == "secret" then return true end
		  end
		  local compact = lowered:gsub("[^a-z0-9]", "")
		  for _, marker in ipairs({"authorization","cookie","password","passwd","token","key","apikey","certificate","cert","privatekey","setcookie"}) do
            if string.find(compact, marker, 1, true) then return true end
          end
          return false
        end
        local function cleanse(value, depth, state)
          if depth > 8 then return nil, false end
          if value == null then return null, true end
          local kind = type(value)
          if kind == "string" then return #value <= max_value and value or nil, #value <= max_value end
          if kind == "number" or kind == "boolean" then return value, true end
          if kind ~= "table" then return nil, false end
          local result = {}
          for key, item in pairs(value) do
            if type(key) == "string" then
              state.keys = state.keys + 1
              if state.keys > 128 or #key == 0 or #key > 128 then return nil, false end
              if sensitive(key) then result[key] = redacted else
                local cleaned, ok = cleanse(item, depth + 1, state); if not ok then return nil, false end; result[key] = cleaned
              end
            elseif type(key) == "number" then
              local cleaned, ok = cleanse(item, depth + 1, state); if not ok then return nil, false end; result[key] = cleaned
            else return nil, false end
          end
          return result, true
        end
        local function capture_headers(source, source_error, names)
          if #names == 0 then return null, true end
          if source_error == "truncated" then return nil, false end
          local indexed = {}
          for name, value in pairs(source) do
            local lower = string.lower(name)
            if indexed[lower] ~= nil or type(value) == "table" then return nil, false end
            indexed[lower] = value
          end
          local result = {}
          for _, name in ipairs(names) do
            local value = indexed[string.lower(name)]
            if value ~= nil then
              if type(value) ~= "string" or #value > max_value then return nil, false end
              result[name] = sensitive(name) and redacted or value
            end
          end
          return result, true
        end
        local function is_json_content_type(value)
          if type(value) ~= "string" then return false end
          value = string.lower(value)
          local media_type = string.match(value, "^%s*([^;%s]+)")
          if media_type == nil or media_type == "" then return false end
          return media_type == "application/json" or
            string.match(media_type, "^application/[a-z0-9!#$&^_.+%-]+%+json$") ~= nil
        end
        local function header_value(source, name)
          if type(source) ~= "table" then return nil end
          local value
          for key, item in pairs(source) do
            if type(key) == "string" and string.lower(key) == name then
              if value ~= nil or type(item) ~= "string" then return nil end
              value = item
            end
          end
          return value
        end
        local function capture_body(raw, content_type, names)
          if #names == 0 then return null, true end
          if raw == nil or raw == "" then return {}, true end
          if not is_json_content_type(content_type) then return nil, false end
          if #raw > max_body then return nil, false end
          local decoded = cjson.decode(raw)
          if type(decoded) ~= "table" then return nil, false end
          local result, state = {}, {keys = 0}
          for _, name in ipairs(names) do
            local value = decoded[name]
            if value ~= nil then
              if sensitive(name) then result[name] = redacted else
                local cleaned, ok = cleanse(value, 0, state); if not ok then return nil, false end; result[name] = cleaned
              end
            end
          end
          local encoded = cjson.encode(result)
          return encoded ~= nil and #encoded <= max_body and result or nil, encoded ~= nil and #encoded <= max_body
        end
        local function timing(raw)
          if raw == nil or raw == "" or raw == "-" then return null, true end
          if string.find(raw, ",", 1, true) or string.find(raw, ":", 1, true) then return nil, false end
          local whole, fraction = string.match(raw, "^(%d+)%.(%d+)$")
          if whole == nil or #whole > 6 or #fraction > 6 then return nil, false end
          fraction = fraction .. string.rep("0", 6 - #fraction)
          return tonumber(whole) * 1000000 + tonumber(fraction), true
        end
		local request_headers_raw, request_headers_error = {}, nil
		if #request_header_names > 0 or #request_body_names > 0 then request_headers_raw, request_headers_error = ngx.req.get_headers(128, true) end
		local response_headers_raw, response_headers_error = {}, nil
		if #response_header_names > 0 or #response_body_names > 0 then response_headers_raw, response_headers_error = ngx.resp.get_headers(128, true) end
        local request_headers, ok1 = capture_headers(request_headers_raw, request_headers_error, request_header_names)
        local response_headers, ok2 = capture_headers(response_headers_raw, response_headers_error, response_header_names)
        local request_content_type = header_value(request_headers_raw, "content-type")
        local response_content_type = header_value(response_headers_raw, "content-type")
        local request_file = #request_body_names > 0 and ngx.req.get_body_file() or nil
		local request_raw = #request_body_names > 0 and not request_file and ngx.req.get_body_data() or nil
        local request_body, ok3 = capture_body(request_raw, request_content_type, request_body_names)
		local response_raw = #response_body_names > 0 and ngx.ctx.cdnca_capture_chunks and table.concat(ngx.ctx.cdnca_capture_chunks) or nil
        local response_body, ok4 = capture_body(response_raw, response_content_type, response_body_names)
        local origin_connect_us, ok5 = timing(ngx.var.upstream_connect_time)
        local origin_first_byte_us, ok6 = timing(ngx.var.upstream_header_time)
        local origin_total_us, ok7 = timing(ngx.var.upstream_response_time)
        -- 采集字段失败（重复/截断请求头、请求体落盘、超限）只置空该字段，整条访问事件必须保留。
        if not ok1 then request_headers = null end
        if not ok2 then response_headers = null end
        if request_file or not ok3 then request_body = null end
        if ngx.ctx.cdnca_capture_invalid or not ok4 then response_body = null end
        if not ok5 then origin_connect_us = null end
        if not ok6 then origin_first_byte_us = null end
        if not ok7 then origin_total_us = null end
        local ordered = (origin_connect_us == null or origin_first_byte_us == null or origin_connect_us <= origin_first_byte_us)
          and (origin_first_byte_us == null or origin_total_us == null or origin_first_byte_us <= origin_total_us)
          and (origin_connect_us == null or origin_total_us == null or origin_connect_us <= origin_total_us)
        if not ordered then origin_connect_us, origin_first_byte_us, origin_total_us = null, null, null end
        local ja4 = ngx.var.cdnca_ja4
        if ja4 == nil or ja4 == "" then ja4 = null end
        local common = {
          schema_version=1, occurred_at=ngx.var.time_iso8601, tenant_id=ngx.var.cdnca_tenant_id,
          site_id=ngx.var.cdnca_site_id, node_id=ngx.var.cdnca_node_id, config_version_id=ngx.var.cdnca_config_version_id,
		  installation_id="", task_id=null, request_id=ngx.var.request_id or "", trace_id=ngx.var.http_traceparent or "", host=ngx.var.host,
          path=ngx.var.uri, client_ip=ngx.var.remote_addr, status_code=tonumber(ngx.var.status),
          request_bytes=tonumber(ngx.var.request_length), response_bytes=tonumber(ngx.var.bytes_sent),
          request_headers=request_headers, response_headers=response_headers, request_body=request_body, response_body=response_body,
          ja4=ja4, origin_connect_us=origin_connect_us, origin_first_byte_us=origin_first_byte_us, origin_total_us=origin_total_us
        }
        local cdnca_blocked = ngx.var.cdnca_security_block_page == "1"
        local access, security = {}, {}
        for key, value in pairs(common) do access[key]=value; security[key]=value end
        access.type="access.v1"; access.method=ngx.var.request_method; access.protocol=ngx.var.server_protocol
		access.connection=ngx.var.connection; access.connection_requests=tonumber(ngx.var.connection_requests)
        access.cache_status=ngx.var.cdnca_telemetry_cache_status; access.blocked=cdnca_blocked
        access.duration_us=tonumber(ngx.var.cdnca_duration_us) or 0
        access.client_browser=ngx.var.cdnca_client_browser or "other"; access.client_os=ngx.var.cdnca_client_os or "other"
        local upstream_addr = ngx.var.cdnca_upstream_addr_log
        if upstream_addr ~= nil then access.upstream_addr = upstream_addr end
		security.type="security.v1"; security.security_type=ngx.var.cdnca_security_type
		security.action=ngx.var.cdnca_security_action; security.severity=ngx.var.cdnca_security_severity
		security.rule_id=ngx.var.cdnca_security_rule_id; security.method=ngx.var.request_method
		security.policy_id=ngx.var.cdnca_security_policy_id or ""; security.detector=ngx.var.cdnca_security_detector or ""
		security.matched=ngx.var.cdnca_security_matched or ""; security.user_agent=ngx.var.cdnca_security_user_agent or ""
		security.request_body_excerpt=ngx.var.cdnca_security_body or ""
		security.listen_port=tonumber(ngx.var.server_port); security.protocol=ngx.var.scheme
		security.request_class=ngx.var.cdnca_security_request_class
        local access_json, security_json = cjson.encode(access), cjson.encode(security)
        if not access_json or not security_json or #access_json > max_event or #security_json > max_event then
          for _, event in ipairs({access, security}) do
            event.request_headers, event.response_headers, event.request_body, event.response_body = null, null, null, null
          end
          access_json, security_json = cjson.encode(access), cjson.encode(security)
        end
        if not access_json or not security_json or #access_json > max_event or #security_json > max_event then
          access_json, security_json = '{"schema_version":0}', '{"schema_version":0}'
        end
        ngx.var.cdnca_access_telemetry_json = access_json
        ngx.var.cdnca_security_telemetry_json = security_json
`

func luaTelemetryArray(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = strconv.Quote(value)
	}
	return "{" + strings.Join(quoted, ",") + "}"
}

func nginxTelemetryQuote(value string) string {
	return strconv.Quote(value)
}
