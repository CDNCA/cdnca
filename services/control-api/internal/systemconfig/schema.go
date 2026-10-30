package systemconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

var (
	safeLabelPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$`)
	safeKeyPattern              = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$`)
	serverHeaderPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
	metadataCodePattern         = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	writeMetadataPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	shortConfigurationIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{7,31}$`)
	httpTokenPattern            = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)
	mimeTypePattern             = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+/[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)
	hexSHA256Pattern            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	allowedMIMETypes            = []string{"application/json", "text/html", "text/plain"}
	allowedErrorStatusCode      = []int{400, 401, 403, 404, 405, 408, 413, 429, 500, 501, 502, 503, 504}
	tlsProtocolOrder            = []string{"SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
	recommendedSSLProtocols     = []string{"TLSv1.2", "TLSv1.3"}
	legacyFullSSLProtocols      = []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}
)

const (
	recommendedSSLCipherSuites = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
	legacyTLS12CipherSuites    = recommendedSSLCipherSuites + ":ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
)

type canonicalEnvelope struct {
	Schema        string        `json:"schema"`
	Configuration Configuration `json:"configuration"`
}

type nginxWire struct {
	Worker    NginxWorkerSettings   `json:"worker"`
	HTTP      NginxHTTPSettings     `json:"http"`
	Stream    NginxStreamSettings   `json:"stream"`
	Overrides []ScopedNginxOverride `json:"overrides"`
}

func (value NginxLimits) MarshalJSON() ([]byte, error) {
	return json.Marshal(nginxWire{
		Worker: NginxWorkerSettings{
			WorkerProcesses: value.WorkerProcesses, WorkerConnections: value.WorkerConnections,
			WorkerRlimitNoFile:      value.WorkerRlimitNoFile,
			WorkerShutdownTimeoutMS: value.WorkerShutdownTimeoutMS, LogsDir: value.LogsDir,
		},
		HTTP: NginxHTTPSettings{
			GzipLevel: value.GzipLevel, GzipHTTPVersion: value.GzipHTTPVersion,
			GzipMinimumBytes: value.GzipMinimumBytes, GzipVary: value.GzipVary,
			ServerAddrOutgoing:    value.ServerAddrOutgoing,
			ProxyRequestBuffering: value.ProxyRequestBuffering, ProxyBuffering: value.ProxyBuffering,
			ProxyCacheMaxBytes: value.ProxyCacheMaxBytes, ProxyCacheMinFreeBytes: value.ProxyCacheMinFreeBytes,
			ProxyCacheMethods: slices.Clone(value.ProxyCacheMethods), ProxyHTTPVersion: value.ProxyHTTPVersion,
			ProxyMaxTempFileBytes: value.ProxyMaxTempFileBytes,
			ProxyNextUpstream:     slices.Clone(value.ProxyNextUpstream),
			ProxyConnectTimeoutMS: value.ProxyConnectTimeoutMS,
			ProxySendTimeoutMS:    value.ProxySendTimeoutMS, ProxyReadTimeoutMS: value.ProxyReadTimeoutMS,
			ClientBodyBufferSizeBytes: value.ClientBodyBufferSizeBytes, ServerHeader: value.ServerHeader,
			ClientMaxBodyBytes: value.ClientMaxBodyBytes, DefaultMIMEType: value.DefaultMIMEType,
			KeepaliveRequests: value.KeepaliveRequests, KeepaliveTimeoutMS: value.KeepaliveTimeoutMS,
			LogNotFound: value.LogNotFound, ServerTokens: value.ServerTokens,
			LargeClientHeaderBuffers:  value.LargeClientHeaderBuffers,
			ServerNamesHashMaxSize:    value.ServerNamesHashMaxSize,
			ServerNamesHashBucketSize: value.ServerNamesHashBucketSize,
		},
		Stream: NginxStreamSettings{
			ProxyConnectTimeoutMS: value.StreamProxyConnectTimeoutMS,
			ProxyTimeoutMS:        value.StreamProxyTimeoutMS,
		},
		Overrides: cloneNginxScopedOverrides(value.Overrides),
	})
}

func (value *NginxLimits) UnmarshalJSON(raw []byte) error {
	var wire nginxWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	*value = NginxLimits{
		WorkerProcesses: wire.Worker.WorkerProcesses, WorkerConnections: wire.Worker.WorkerConnections,
		WorkerRlimitNoFile:      wire.Worker.WorkerRlimitNoFile,
		WorkerShutdownTimeoutMS: wire.Worker.WorkerShutdownTimeoutMS, LogsDir: wire.Worker.LogsDir,
		GzipLevel: wire.HTTP.GzipLevel, GzipHTTPVersion: wire.HTTP.GzipHTTPVersion,
		GzipMinimumBytes: wire.HTTP.GzipMinimumBytes, GzipVary: wire.HTTP.GzipVary,
		ServerAddrOutgoing:    wire.HTTP.ServerAddrOutgoing,
		ProxyRequestBuffering: wire.HTTP.ProxyRequestBuffering, ProxyBuffering: wire.HTTP.ProxyBuffering,
		ProxyCacheMaxBytes: wire.HTTP.ProxyCacheMaxBytes, ProxyCacheMinFreeBytes: wire.HTTP.ProxyCacheMinFreeBytes,
		ProxyCacheMethods: slices.Clone(wire.HTTP.ProxyCacheMethods), ProxyHTTPVersion: wire.HTTP.ProxyHTTPVersion,
		ProxyMaxTempFileBytes: wire.HTTP.ProxyMaxTempFileBytes,
		ProxyNextUpstream:     slices.Clone(wire.HTTP.ProxyNextUpstream),
		ProxyConnectTimeoutMS: wire.HTTP.ProxyConnectTimeoutMS,
		ProxySendTimeoutMS:    wire.HTTP.ProxySendTimeoutMS, ProxyReadTimeoutMS: wire.HTTP.ProxyReadTimeoutMS,
		ClientBodyBufferSizeBytes: wire.HTTP.ClientBodyBufferSizeBytes, ServerHeader: wire.HTTP.ServerHeader,
		ClientMaxBodyBytes: wire.HTTP.ClientMaxBodyBytes, DefaultMIMEType: wire.HTTP.DefaultMIMEType,
		KeepaliveRequests: wire.HTTP.KeepaliveRequests, KeepaliveTimeoutMS: wire.HTTP.KeepaliveTimeoutMS,
		LogNotFound: wire.HTTP.LogNotFound, ServerTokens: wire.HTTP.ServerTokens,
		LargeClientHeaderBuffers:    wire.HTTP.LargeClientHeaderBuffers,
		ServerNamesHashMaxSize:      wire.HTTP.ServerNamesHashMaxSize,
		ServerNamesHashBucketSize:   wire.HTTP.ServerNamesHashBucketSize,
		StreamProxyConnectTimeoutMS: wire.Stream.ProxyConnectTimeoutMS,
		StreamProxyTimeoutMS:        wire.Stream.ProxyTimeoutMS,
		Overrides:                   cloneNginxScopedOverrides(wire.Overrides),
	}
	applyNginxRuntimeDefaults(value)
	return nil
}

type resourceWire struct {
	Site       ResourceSiteSettings       `json:"site"`
	Stream     ResourceStreamSettings     `json:"stream"`
	SiteStream ResourceSiteStreamSettings `json:"site_stream"`
	Overrides  []ScopedResourceOverride   `json:"overrides"`
}

func (value ResourceLimits) MarshalJSON() ([]byte, error) {
	return json.Marshal(resourceWire{
		Site: ResourceSiteSettings{
			MinimumRelatedConfigLimit:  value.MinimumRelatedConfigLimit,
			RelatedConfigMaxMultiplier: value.RelatedConfigMaxMultiplier,
			MaxBlacklistIPsPerSite:     value.MaxBlacklistIPsPerSite,
			MaxWhitelistIPsPerSite:     value.MaxWhitelistIPsPerSite,
			DailyURLPurgeLimit:         value.DailyURLPurgeLimit,
			DailyDirectoryPurgeLimit:   value.DailyDirectoryPurgeLimit,
			DailyPrewarmLimit:          value.DailyPrewarmLimit, DailyIPUnlockLimit: value.DailyIPUnlockLimit,
			IPUnlockPerRequestLimit: value.IPUnlockPerRequestLimit,
			MaxCCRulesPerPolicy:     value.MaxCCRulesPerPolicy, MaxDomainsPerSite: value.MaxDomainsPerSite,
			ListenDefaultHTTP80:         value.ListenDefaultHTTP80,
			DailyAccessLogDownloadLimit: value.DailyAccessLogDownloadLimit,
			AccessLogTemporaryDir:       value.AccessLogTemporaryDir,
			AccessLogRetentionHours:     value.AccessLogRetentionHours,
		},
		Stream: ResourceStreamSettings{
			CustomPortNotAllow:         slices.Clone(value.StreamCustomPortNotAllow),
			MinimumRelatedConfigLimit:  value.StreamMinimumRelatedConfigLimit,
			RelatedConfigMaxMultiplier: value.StreamRelatedConfigMaxMultiplier,
			MaxACLRulesPerPolicy:       value.MaxACLRulesPerPolicy,
		},
		SiteStream: ResourceSiteStreamSettings{
			CustomPortNotAllow: slices.Clone(value.CustomPortNotAllow),
			CustomPortAllow:    slices.Clone(value.CustomPortAllow),
		},
		Overrides: cloneResourceScopedOverrides(value.Overrides),
	})
}

func (value *ResourceLimits) UnmarshalJSON(raw []byte) error {
	var wire resourceWire
	if err := decodeStrictJSON(raw, &wire); err != nil {
		return err
	}
	*value = ResourceLimits{
		MinimumRelatedConfigLimit:  wire.Site.MinimumRelatedConfigLimit,
		RelatedConfigMaxMultiplier: wire.Site.RelatedConfigMaxMultiplier,
		MaxBlacklistIPsPerSite:     wire.Site.MaxBlacklistIPsPerSite,
		MaxWhitelistIPsPerSite:     wire.Site.MaxWhitelistIPsPerSite,
		DailyURLPurgeLimit:         wire.Site.DailyURLPurgeLimit,
		DailyDirectoryPurgeLimit:   wire.Site.DailyDirectoryPurgeLimit,
		DailyPrewarmLimit:          wire.Site.DailyPrewarmLimit, DailyIPUnlockLimit: wire.Site.DailyIPUnlockLimit,
		IPUnlockPerRequestLimit: wire.Site.IPUnlockPerRequestLimit,
		MaxCCRulesPerPolicy:     wire.Site.MaxCCRulesPerPolicy, MaxDomainsPerSite: wire.Site.MaxDomainsPerSite,
		ListenDefaultHTTP80:              wire.Site.ListenDefaultHTTP80,
		DailyAccessLogDownloadLimit:      wire.Site.DailyAccessLogDownloadLimit,
		AccessLogTemporaryDir:            wire.Site.AccessLogTemporaryDir,
		AccessLogRetentionHours:          wire.Site.AccessLogRetentionHours,
		StreamCustomPortNotAllow:         slices.Clone(wire.Stream.CustomPortNotAllow),
		StreamMinimumRelatedConfigLimit:  wire.Stream.MinimumRelatedConfigLimit,
		StreamRelatedConfigMaxMultiplier: wire.Stream.RelatedConfigMaxMultiplier,
		MaxACLRulesPerPolicy:             wire.Stream.MaxACLRulesPerPolicy,
		CustomPortNotAllow:               slices.Clone(wire.SiteStream.CustomPortNotAllow),
		CustomPortAllow:                  slices.Clone(wire.SiteStream.CustomPortAllow),
		Overrides:                        cloneResourceScopedOverrides(wire.Overrides),
	}
	applyResourceRuntimeDefaults(value)
	return nil
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidInput
	}
	return nil
}

func CanonicalSnapshot(configuration Configuration) (Configuration, []byte, string, error) {
	normalized, err := normalizeConfiguration(configuration)
	if err != nil {
		return Configuration{}, nil, "", err
	}
	encoded, err := marshalCanonicalJSON(canonicalEnvelope{Schema: canonicalSchema, Configuration: normalized})
	if err != nil {
		return Configuration{}, nil, "", ErrInvalidInput
	}
	digest := sha256.Sum256(encoded)
	return normalized, encoded, hex.EncodeToString(digest[:]), nil
}

func marshalCanonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := renderCanonicalJSON(&output, document); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func renderCanonicalJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteString(", ")
			}
			if err := renderCanonicalJSON(output, key); err != nil {
				return err
			}
			output.WriteString(": ")
			if err := renderCanonicalJSON(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteString(", ")
			}
			if err := renderCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case string:
		var encoded bytes.Buffer
		encoder := json.NewEncoder(&encoded)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(typed); err != nil {
			return err
		}
		output.Write(bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}))
	case json.Number:
		output.WriteString(typed.String())
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case nil:
		output.WriteString("null")
	default:
		return ErrInvalidInput
	}
	return nil
}

func decodeCanonicalSnapshot(raw []byte, expectedHash string) (Configuration, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !hexSHA256Pattern.MatchString(expectedHash) {
		return Configuration{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope canonicalEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return Configuration{}, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || envelope.Schema != canonicalSchema {
		return Configuration{}, ErrInvalidInput
	}
	normalized, encoded, actualHash, err := CanonicalSnapshot(envelope.Configuration)
	if err != nil || !bytes.Equal(raw, encoded) || actualHash != expectedHash {
		return Configuration{}, ErrInvalidInput
	}
	return normalized, nil
}

func normalizeConfiguration(input Configuration) (Configuration, error) {
	result := cloneConfiguration(input)
	if err := validateNginx(&result.Nginx); err != nil {
		return Configuration{}, err
	}
	if err := validateDefaults(&result.Defaults); err != nil {
		return Configuration{}, err
	}
	if err := validateResources(&result.Resources); err != nil {
		return Configuration{}, err
	}
	if err := validateErrorPages(result.ErrorPages, result.Resources.MaxCustomErrorPageBytes); err != nil {
		return Configuration{}, err
	}
	if err := validateSecrets(result.Secrets); err != nil {
		return Configuration{}, err
	}
	if result.NodeMonitoring != nil {
		if err := validateNodeMonitoring(*result.NodeMonitoring); err != nil {
			return Configuration{}, err
		}
	}
	if result.DDoSProtection != nil {
		normalized, err := edgeconfig.NormalizeDDoSProtection(*result.DDoSProtection)
		if err != nil {
			return Configuration{}, ErrInvalidInput
		}
		result.DDoSProtection = &normalized
	}
	if result.AccessLogFields != nil {
		normalized, err := edgeconfig.NormalizeAccessLogFields(*result.AccessLogFields)
		if err != nil {
			return Configuration{}, ErrInvalidInput
		}
		result.AccessLogFields = &normalized
	}
	sort.Slice(result.ErrorPages, func(i, j int) bool { return result.ErrorPages[i].StatusCode < result.ErrorPages[j].StatusCode })
	return result, nil
}

// ProjectBootstrapConfiguration is the server-owned canonical initial value
// for a fresh installation.
func ProjectBootstrapConfiguration() Configuration {
	configuration := Configuration{
		Nginx: NginxLimits{
			WorkerProcesses: 0, WorkerConnections: 4096, WorkerRlimitNoFile: 65_536,
			WorkerShutdownTimeoutMS: 30_000, LogsDir: "/var/log/cdnca/nginx",
			GzipLevel: 6, GzipHTTPVersion: "1.1", GzipMinimumBytes: 1024, GzipVary: true,
			ProxyRequestBuffering: true, ProxyBuffering: true,
			ProxyCacheMaxBytes: 100 << 30, ProxyCacheMinFreeBytes: 5 << 30,
			ProxyCacheMethods: []string{"GET", "HEAD"}, ProxyHTTPVersion: "1.1",
			ProxyMaxTempFileBytes: 1 << 30,
			ProxyNextUpstream:     []string{"error", "timeout", "invalid_header", "http_500", "http_502", "http_503", "http_504"},
			ProxyConnectTimeoutMS: 10_000, ProxySendTimeoutMS: 60_000, ProxyReadTimeoutMS: 60_000,
			ClientBodyBufferSizeBytes: 16 << 10, ServerHeader: "cdnca",
			ClientMaxBodyBytes: 100 << 20, DefaultMIMEType: "text/plain",
			KeepaliveRequests: 10_000, KeepaliveTimeoutMS: 75_000, LogNotFound: true,
			LargeClientHeaderBuffers: LargeClientHeaderBuffers{Count: 4, SizeBytes: 8 << 10},
			ServerNamesHashMaxSize:   4096, ServerNamesHashBucketSize: 64,
			StreamProxyConnectTimeoutMS: 10_000, StreamProxyTimeoutMS: 300_000,
		},
		Defaults: DefaultReferences{
			Website: DefaultWebsiteSettings{
				HTTP: DefaultWebsiteHTTPSettings{ListenPorts: []uint16{80}},
				HTTPS: DefaultWebsiteHTTPSSettings{
					ListenPorts: []uint16{443},
					SSL: DefaultSSLSettings{Mode: "legacy_tls12", Protocols: slices.Clone(recommendedSSLProtocols),
						CipherSuites: legacyTLS12CipherSuites, PreferServerCiphers: true},
					OCSPStaplingEnabled: true,
				},
				Origin: DefaultWebsiteOriginSettings{
					Scheme: "http", HTTPPort: 80, HTTPSPort: 443,
					ResponseTimeoutSeconds: 60, ConnectTimeoutSeconds: 10,
					SSLProtocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2"}, HTTPVersion: "1.1",
					KeepaliveEnabled: true, PostBodyLimitBytes: 100 << 20,
				},
				CacheRules: []DefaultCacheRule{}, OriginRequestHeaders: []DefaultOriginRequestHeader{},
				AccessLog: DefaultAccessLogSettings{CaptureRequestHeaders: true, RequestBodyLimitKB: 16},
				Security: DefaultSecuritySettings{
					WAFAutoBlock: DefaultWAFAutoBlockSettings{WindowSeconds: 60, HitThreshold: 20, BlockSeconds: 600},
					WAFModules:   defaultWAFModules("off"),
				},
				Other: DefaultWebsiteOtherSettings{
					LoadBalancing: "round_robin", GzipEnabled: true,
					GzipTypes: []string{
						"text/plain", "text/css", "text/xml", "text/javascript",
						"application/javascript", "application/x-javascript", "application/json",
					},
				},
			},
			Stream:      DefaultStreamSettings{Protocol: "tcp", LoadBalancing: "round_robin"},
			Certificate: DefaultCertificateSettings{Issuer: "lets_encrypt"},
			Overrides:   []ScopedDefaultOverride{},
		},
		Resources: ResourceLimits{
			MinimumRelatedConfigLimit: 1_000, RelatedConfigMaxMultiplier: 200,
			MaxBlacklistIPsPerSite: 50, MaxWhitelistIPsPerSite: 50,
			DailyURLPurgeLimit: 2_000, DailyDirectoryPurgeLimit: 500,
			DailyPrewarmLimit: 2_000, DailyIPUnlockLimit: 1_000, IPUnlockPerRequestLimit: 50,
			MaxCCRulesPerPolicy: 5, MaxDomainsPerSite: 100, ListenDefaultHTTP80: true,
			DailyAccessLogDownloadLimit: 10,
			AccessLogTemporaryDir:       "/data/download-temp/", AccessLogRetentionHours: 12,
			StreamCustomPortNotAllow: []PortRange{}, StreamMinimumRelatedConfigLimit: 10,
			StreamRelatedConfigMaxMultiplier: 10, MaxACLRulesPerPolicy: 1000,
			CustomPortNotAllow: []PortRange{}, CustomPortAllow: []PortRange{},
			Overrides: []ScopedResourceOverride{},
		},
		ErrorPages: []ErrorPageMetadata{}, Secrets: SensitiveReferences{},
	}
	applyNginxRuntimeDefaults(&configuration.Nginx)
	applyDefaultRuntimeProjection(&configuration.Defaults)
	applyResourceRuntimeDefaults(&configuration.Resources)
	return configuration
}

func applyNginxRuntimeDefaults(value *NginxLimits) {
	value.ResolverAddresses = []string{"1.1.1.1", "8.8.8.8"}
	value.ResolverTimeoutMS = 5_000
	value.ProxyCacheZoneBytes = 64 << 20
}

func applyDefaultRuntimeProjection(value *DefaultReferences) {
	value.ListenPort = firstPort(value.Website.HTTP.ListenPorts, 80)
	value.HTTPSPort = firstPort(value.Website.HTTPS.ListenPorts, 443)
	value.OriginScheme = value.Website.Origin.Scheme
	if value.OriginScheme != "http" && value.OriginScheme != "https" {
		value.OriginScheme = "http"
	}
	value.OriginPort = value.Website.Origin.HTTPPort
}

func firstPort(values []uint16, fallback uint16) uint16 {
	if len(values) == 0 {
		return fallback
	}
	return values[0]
}

func applyResourceRuntimeDefaults(value *ResourceLimits) {
	value.MaxSitesPerTenant = 1000
	value.MaxOriginsPerSite = 8
	value.MaxCertificatesPerTenant = 1000
	value.MaxCustomErrorPageBytes = 1 << 20
}

func defaultWAFModules(mode string) DefaultWAFModules {
	return DefaultWAFModules{SQLI: mode, XSS: mode, Upload: mode, FI: mode, CMDI: mode,
		Java: mode, JDeser: mode, PHP: mode, PHPDeser: mode, SSTI: mode}
}

func validScopedConfiguration(id, scope, scopeID string, allowNode bool) bool {
	if !shortConfigurationIDPattern.MatchString(id) || !validSafeLabel(scopeID) {
		return false
	}
	return scope == ConfigurationScopeRegion || allowNode && scope == ConfigurationScopeNode
}

func scopedLess(leftScope, leftScopeID, leftID, rightScope, rightScopeID, rightID string) bool {
	rank := func(scope string) int {
		if scope == ConfigurationScopeRegion {
			return 0
		}
		return 1
	}
	if rank(leftScope) != rank(rightScope) {
		return rank(leftScope) < rank(rightScope)
	}
	if leftScopeID != rightScopeID {
		return leftScopeID < rightScopeID
	}
	return leftID < rightID
}

func validControlledPath(value, root string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || hasControl(value) ||
		strings.Contains(value, "\\") || !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	return value == root || strings.HasPrefix(value, root+"/")
}

func validResourceAccessLogPath(value string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || hasControl(value) ||
		strings.Contains(value, "\\") || !strings.HasPrefix(value, "/") {
		return false
	}
	cleaned := strings.TrimSuffix(value, "/")
	if cleaned == "" || strings.HasSuffix(cleaned, "/") || path.Clean(cleaned) != cleaned {
		return false
	}
	return cleaned == "/data/download-temp" || strings.HasPrefix(cleaned, "/data/download-temp/") ||
		cleaned == "/var/lib/cdnca" || strings.HasPrefix(cleaned, "/var/lib/cdnca/")
}

func normalizeEnumSet(values, allowed []string, minimum int) ([]string, error) {
	if len(values) < minimum || len(values) > len(allowed) {
		return nil, ErrInvalidInput
	}
	selected := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !slices.Contains(allowed, value) {
			return nil, ErrInvalidInput
		}
		if _, duplicate := selected[value]; duplicate {
			return nil, ErrInvalidInput
		}
		selected[value] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for _, value := range allowed {
		if _, ok := selected[value]; ok {
			result = append(result, value)
		}
	}
	return result, nil
}

func normalizePorts(values []uint16) ([]uint16, error) {
	if len(values) == 0 || len(values) > 64 {
		return nil, ErrInvalidInput
	}
	result := slices.Clone(values)
	slices.Sort(result)
	for index, value := range result {
		if value == 0 || index > 0 && value == result[index-1] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func portListsOverlap(left, right []uint16) bool {
	selected := make(map[uint16]struct{}, len(left))
	for _, value := range left {
		selected[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := selected[value]; exists {
			return true
		}
	}
	return false
}

func normalizePortRanges(values []PortRange) ([]PortRange, error) {
	if len(values) > 256 {
		return nil, ErrInvalidInput
	}
	result := slices.Clone(values)
	if result == nil {
		result = []PortRange{}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].From != result[j].From {
			return result[i].From < result[j].From
		}
		return result[i].To < result[j].To
	})
	for index, value := range result {
		if value.From == 0 || value.To < value.From || index > 0 && value.From <= result[index-1].To {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func portRangesOverlap(left, right []PortRange) bool {
	for _, leftValue := range left {
		for _, rightValue := range right {
			if leftValue.From <= rightValue.To && rightValue.From <= leftValue.To {
				return true
			}
		}
	}
	return false
}

func validWAFModules(value DefaultWAFModules) bool {
	for _, mode := range []string{
		value.SQLI, value.XSS, value.Upload, value.FI, value.CMDI,
		value.Java, value.JDeser, value.PHP, value.PHPDeser, value.SSTI,
	} {
		if !slices.Contains([]string{"off", "detect", "on"}, mode) {
			return false
		}
	}
	return true
}

func normalizeMIMETypes(values []string) ([]string, error) {
	if len(values) > 128 {
		return nil, ErrInvalidInput
	}
	result := slices.Clone(values)
	slices.Sort(result)
	for index, value := range result {
		if len(value) > 128 || !mimeTypePattern.MatchString(value) || index > 0 && value == result[index-1] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func normalizeCacheRules(values *[]DefaultCacheRule) error {
	if values == nil || len(*values) > 100 {
		return ErrInvalidInput
	}
	result := make([]DefaultCacheRule, len(*values))
	seenID := make(map[string]struct{}, len(*values))
	seenPosition := make(map[int]struct{}, len(*values))
	for index, value := range *values {
		if !shortConfigurationIDPattern.MatchString(value.ID) || value.Match == "" ||
			!utf8.ValidString(value.Match) || hasControl(value.Match) || utf8.RuneCountInString(value.Match) > 64 ||
			value.TTLSeconds < 0 || value.TTLSeconds > 31_536_000 || value.Position < 0 || value.Position >= 100 {
			return ErrInvalidInput
		}
		if value.Content != nil && (!utf8.ValidString(*value.Content) || hasControl(*value.Content) || utf8.RuneCountInString(*value.Content) > 2048) {
			return ErrInvalidInput
		}
		if len(value.NoCache) > 100 {
			return ErrInvalidInput
		}
		if value.NoCache == nil {
			value.NoCache = []DefaultCacheNoCacheCondition{}
		}
		for _, condition := range value.NoCache {
			if !utf8.ValidString(condition.Variable) || hasControl(condition.Variable) ||
				utf8.RuneCountInString(condition.Variable) < 1 || utf8.RuneCountInString(condition.Variable) > 256 ||
				!utf8.ValidString(condition.String) || hasControl(condition.String) ||
				utf8.RuneCountInString(condition.String) < 1 || utf8.RuneCountInString(condition.String) > 2048 {
				return ErrInvalidInput
			}
		}
		if _, duplicate := seenID[value.ID]; duplicate {
			return ErrInvalidInput
		}
		if _, duplicate := seenPosition[value.Position]; duplicate {
			return ErrInvalidInput
		}
		seenID[value.ID], seenPosition[value.Position] = struct{}{}, struct{}{}
		result[index] = cloneCacheRule(value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Position != result[j].Position {
			return result[i].Position < result[j].Position
		}
		return result[i].ID < result[j].ID
	})
	*values = result
	return nil
}

func normalizeOriginHeaders(values *[]DefaultOriginRequestHeader) error {
	if values == nil || len(*values) > 100 {
		return ErrInvalidInput
	}
	result := make([]DefaultOriginRequestHeader, len(*values))
	seenID := make(map[string]struct{}, len(*values))
	seenPosition := make(map[int]struct{}, len(*values))
	for index, value := range *values {
		if !shortConfigurationIDPattern.MatchString(value.ID) || !httpTokenPattern.MatchString(value.Name) ||
			!slices.Contains([]string{"set", "append", "delete"}, value.Action) ||
			value.Position < 0 || value.Position >= 100 ||
			value.Action == "delete" && value.Value != nil || value.Action != "delete" && value.Value == nil {
			return ErrInvalidInput
		}
		if value.Value != nil && (!utf8.ValidString(*value.Value) || hasControl(*value.Value) || utf8.RuneCountInString(*value.Value) > 4096) {
			return ErrInvalidInput
		}
		if _, duplicate := seenID[value.ID]; duplicate {
			return ErrInvalidInput
		}
		if _, duplicate := seenPosition[value.Position]; duplicate {
			return ErrInvalidInput
		}
		seenID[value.ID], seenPosition[value.Position] = struct{}{}, struct{}{}
		result[index] = cloneOriginHeader(value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Position != result[j].Position {
			return result[i].Position < result[j].Position
		}
		return result[i].ID < result[j].ID
	})
	*values = result
	return nil
}

func cloneCacheRule(input DefaultCacheRule) DefaultCacheRule {
	result := input
	if input.Content != nil {
		content := *input.Content
		result.Content = &content
	}
	result.NoCache = slices.Clone(input.NoCache)
	return result
}

func validDefaultSSLSettings(value DefaultSSLSettings) bool {
	switch value.Mode {
	case "recommended":
		return slices.Equal(value.Protocols, recommendedSSLProtocols) &&
			value.CipherSuites == recommendedSSLCipherSuites && !value.PreferServerCiphers
	case "legacy_tls12":
		return slices.Equal(value.Protocols, recommendedSSLProtocols) &&
			value.CipherSuites == legacyTLS12CipherSuites && value.PreferServerCiphers
	case "legacy_full":
		return slices.Equal(value.Protocols, legacyFullSSLProtocols) &&
			value.CipherSuites == "DEFAULT:@SECLEVEL=0" && value.PreferServerCiphers
	default:
		return false
	}
}

func cloneOriginHeader(input DefaultOriginRequestHeader) DefaultOriginRequestHeader {
	result := input
	if input.Value != nil {
		value := *input.Value
		result.Value = &value
	}
	return result
}

func clonePointer[T any](input *T) *T {
	if input == nil {
		return nil
	}
	result := *input
	return &result
}

func cloneSlicePointer[T any](input *[]T) *[]T {
	if input == nil {
		return nil
	}
	result := slices.Clone(*input)
	return &result
}

func cloneNginxOverride(input NginxOverride) NginxOverride {
	result := NginxOverride{}
	if input.Worker != nil {
		worker := *input.Worker
		worker.WorkerProcesses = clonePointer(input.Worker.WorkerProcesses)
		worker.WorkerConnections = clonePointer(input.Worker.WorkerConnections)
		worker.WorkerRlimitNoFile = clonePointer(input.Worker.WorkerRlimitNoFile)
		worker.WorkerShutdownTimeoutMS = clonePointer(input.Worker.WorkerShutdownTimeoutMS)
		worker.LogsDir = clonePointer(input.Worker.LogsDir)
		result.Worker = &worker
	}
	if input.HTTP != nil {
		http := *input.HTTP
		http.GzipLevel = clonePointer(input.HTTP.GzipLevel)
		http.GzipHTTPVersion = clonePointer(input.HTTP.GzipHTTPVersion)
		http.GzipMinimumBytes = clonePointer(input.HTTP.GzipMinimumBytes)
		http.GzipVary = clonePointer(input.HTTP.GzipVary)
		http.ServerAddrOutgoing = clonePointer(input.HTTP.ServerAddrOutgoing)
		http.ProxyRequestBuffering = clonePointer(input.HTTP.ProxyRequestBuffering)
		http.ProxyBuffering = clonePointer(input.HTTP.ProxyBuffering)
		http.ProxyCacheMaxBytes = clonePointer(input.HTTP.ProxyCacheMaxBytes)
		http.ProxyCacheMinFreeBytes = clonePointer(input.HTTP.ProxyCacheMinFreeBytes)
		http.ProxyCacheMethods = cloneSlicePointer(input.HTTP.ProxyCacheMethods)
		http.ProxyHTTPVersion = clonePointer(input.HTTP.ProxyHTTPVersion)
		http.ProxyMaxTempFileBytes = clonePointer(input.HTTP.ProxyMaxTempFileBytes)
		http.ProxyNextUpstream = cloneSlicePointer(input.HTTP.ProxyNextUpstream)
		http.ProxyConnectTimeoutMS = clonePointer(input.HTTP.ProxyConnectTimeoutMS)
		http.ProxySendTimeoutMS = clonePointer(input.HTTP.ProxySendTimeoutMS)
		http.ProxyReadTimeoutMS = clonePointer(input.HTTP.ProxyReadTimeoutMS)
		http.ClientBodyBufferSizeBytes = clonePointer(input.HTTP.ClientBodyBufferSizeBytes)
		http.ServerHeader = clonePointer(input.HTTP.ServerHeader)
		http.ClientMaxBodyBytes = clonePointer(input.HTTP.ClientMaxBodyBytes)
		http.DefaultMIMEType = clonePointer(input.HTTP.DefaultMIMEType)
		http.KeepaliveRequests = clonePointer(input.HTTP.KeepaliveRequests)
		http.KeepaliveTimeoutMS = clonePointer(input.HTTP.KeepaliveTimeoutMS)
		http.LogNotFound = clonePointer(input.HTTP.LogNotFound)
		http.ServerTokens = clonePointer(input.HTTP.ServerTokens)
		http.LargeClientHeaderBuffers = clonePointer(input.HTTP.LargeClientHeaderBuffers)
		http.ServerNamesHashMaxSize = clonePointer(input.HTTP.ServerNamesHashMaxSize)
		http.ServerNamesHashBucketSize = clonePointer(input.HTTP.ServerNamesHashBucketSize)
		result.HTTP = &http
	}
	if input.Stream != nil {
		stream := *input.Stream
		stream.ProxyConnectTimeoutMS = clonePointer(input.Stream.ProxyConnectTimeoutMS)
		stream.ProxyTimeoutMS = clonePointer(input.Stream.ProxyTimeoutMS)
		result.Stream = &stream
	}
	return result
}

func cloneNginxScopedOverrides(input []ScopedNginxOverride) []ScopedNginxOverride {
	result := make([]ScopedNginxOverride, len(input))
	for index, override := range input {
		result[index] = override
		result[index].Values = cloneNginxOverride(override.Values)
	}
	return result
}

func nginxOverrideEmpty(value NginxOverride) bool {
	workerEmpty := value.Worker == nil || *value.Worker == (NginxWorkerOverride{})
	httpEmpty := value.HTTP == nil ||
		value.HTTP.GzipLevel == nil && value.HTTP.GzipHTTPVersion == nil && value.HTTP.GzipMinimumBytes == nil &&
			value.HTTP.GzipVary == nil && value.HTTP.ServerAddrOutgoing == nil && value.HTTP.ProxyRequestBuffering == nil &&
			value.HTTP.ProxyBuffering == nil && value.HTTP.ProxyCacheMinFreeBytes == nil && value.HTTP.ProxyCacheMaxBytes == nil &&
			value.HTTP.ProxyCacheMethods == nil && value.HTTP.ProxyHTTPVersion == nil && value.HTTP.ProxyMaxTempFileBytes == nil &&
			value.HTTP.ProxyNextUpstream == nil && value.HTTP.ProxyConnectTimeoutMS == nil && value.HTTP.ProxySendTimeoutMS == nil &&
			value.HTTP.ProxyReadTimeoutMS == nil && value.HTTP.ClientBodyBufferSizeBytes == nil && value.HTTP.ServerHeader == nil &&
			value.HTTP.ClientMaxBodyBytes == nil && value.HTTP.DefaultMIMEType == nil && value.HTTP.KeepaliveRequests == nil &&
			value.HTTP.KeepaliveTimeoutMS == nil && value.HTTP.LogNotFound == nil && value.HTTP.ServerTokens == nil &&
			value.HTTP.LargeClientHeaderBuffers == nil && value.HTTP.ServerNamesHashMaxSize == nil &&
			value.HTTP.ServerNamesHashBucketSize == nil
	streamEmpty := value.Stream == nil || *value.Stream == (NginxStreamOverride{})
	return workerEmpty && httpEmpty && streamEmpty
}

func cloneNginx(input NginxLimits) NginxLimits {
	result := input
	result.ResolverAddresses = slices.Clone(input.ResolverAddresses)
	result.ProxyCacheMethods = slices.Clone(input.ProxyCacheMethods)
	result.ProxyNextUpstream = slices.Clone(input.ProxyNextUpstream)
	result.Overrides = cloneNginxScopedOverrides(input.Overrides)
	return result
}

func cloneNullableString(input **string) **string {
	if input == nil {
		return nil
	}
	if *input == nil {
		var value *string
		return &value
	}
	value := **input
	pointer := &value
	return &pointer
}

func cloneDefaultWebsite(input DefaultWebsiteSettings) DefaultWebsiteSettings {
	result := input
	result.HTTP.ListenPorts = slices.Clone(input.HTTP.ListenPorts)
	result.HTTPS.ListenPorts = slices.Clone(input.HTTPS.ListenPorts)
	result.HTTPS.SSL.Protocols = slices.Clone(input.HTTPS.SSL.Protocols)
	result.Origin.SSLProtocols = slices.Clone(input.Origin.SSLProtocols)
	result.CacheRules = make([]DefaultCacheRule, len(input.CacheRules))
	for index, rule := range input.CacheRules {
		result.CacheRules[index] = cloneCacheRule(rule)
	}
	result.OriginRequestHeaders = make([]DefaultOriginRequestHeader, len(input.OriginRequestHeaders))
	for index, header := range input.OriginRequestHeaders {
		result.OriginRequestHeaders[index] = cloneOriginHeader(header)
	}
	result.Security = input.Security
	result.Security.DefaultCCPolicyID = clonePointer(input.Security.DefaultCCPolicyID)
	result.Other.GzipTypes = slices.Clone(input.Other.GzipTypes)
	return result
}

func cloneDefaultOverrides(input DefaultOverrides) DefaultOverrides {
	result := DefaultOverrides{}
	if input.Website != nil {
		website := *input.Website
		website.HTTPListenPorts = cloneSlicePointer(input.Website.HTTPListenPorts)
		website.HTTPSListenPorts = cloneSlicePointer(input.Website.HTTPSListenPorts)
		website.HSTSEnabled = clonePointer(input.Website.HSTSEnabled)
		website.HTTP2Enabled = clonePointer(input.Website.HTTP2Enabled)
		website.HTTP3Enabled = clonePointer(input.Website.HTTP3Enabled)
		website.ForceHTTPS = clonePointer(input.Website.ForceHTTPS)
		if input.Website.SSL != nil {
			ssl := *input.Website.SSL
			ssl.Protocols = slices.Clone(input.Website.SSL.Protocols)
			website.SSL = &ssl
		}
		website.OCSPStaplingEnabled = clonePointer(input.Website.OCSPStaplingEnabled)
		if input.Website.Origin != nil {
			origin := *input.Website.Origin
			origin.Scheme = clonePointer(input.Website.Origin.Scheme)
			origin.HTTPPort = clonePointer(input.Website.Origin.HTTPPort)
			origin.HTTPSPort = clonePointer(input.Website.Origin.HTTPSPort)
			origin.ResponseTimeoutSeconds = clonePointer(input.Website.Origin.ResponseTimeoutSeconds)
			origin.ConnectTimeoutSeconds = clonePointer(input.Website.Origin.ConnectTimeoutSeconds)
			origin.SSLProtocols = cloneSlicePointer(input.Website.Origin.SSLProtocols)
			origin.HTTPVersion = clonePointer(input.Website.Origin.HTTPVersion)
			origin.KeepaliveEnabled = clonePointer(input.Website.Origin.KeepaliveEnabled)
			origin.PostBodyLimitBytes = clonePointer(input.Website.Origin.PostBodyLimitBytes)
			website.Origin = &origin
		}
		if input.Website.CacheRules != nil {
			rules := make([]DefaultCacheRule, len(*input.Website.CacheRules))
			for index, rule := range *input.Website.CacheRules {
				rules[index] = cloneCacheRule(rule)
			}
			website.CacheRules = &rules
		}
		if input.Website.OriginRequestHeaders != nil {
			headers := make([]DefaultOriginRequestHeader, len(*input.Website.OriginRequestHeaders))
			for index, header := range *input.Website.OriginRequestHeaders {
				headers[index] = cloneOriginHeader(header)
			}
			website.OriginRequestHeaders = &headers
		}
		website.DefaultCCPolicyID = cloneNullableString(input.Website.DefaultCCPolicyID)
		website.WAFEnabled = clonePointer(input.Website.WAFEnabled)
		website.WAFModules = clonePointer(input.Website.WAFModules)
		if input.Website.Other != nil {
			other := *input.Website.Other
			other.GzipTypes = slices.Clone(input.Website.Other.GzipTypes)
			website.Other = &other
		}
		result.Website = &website
	}
	if input.Stream != nil {
		stream := *input.Stream
		stream.Protocol = clonePointer(input.Stream.Protocol)
		stream.LoadBalancing = clonePointer(input.Stream.LoadBalancing)
		stream.ProxyProtocolEnabled = clonePointer(input.Stream.ProxyProtocolEnabled)
		result.Stream = &stream
	}
	if input.Certificate != nil {
		certificate := *input.Certificate
		certificate.Issuer = clonePointer(input.Certificate.Issuer)
		result.Certificate = &certificate
	}
	return result
}

func cloneDefaultScopedOverrides(input []ScopedDefaultOverride) []ScopedDefaultOverride {
	result := make([]ScopedDefaultOverride, len(input))
	for index, override := range input {
		result[index] = override
		result[index].Values = cloneDefaultOverrides(override.Values)
	}
	return result
}

// defaultOverrideGzipOnly: the override sets website.other (gzip switch and
// types, rendered by the edge per node) and nothing else.
func defaultOverrideGzipOnly(value DefaultOverrides) bool {
	return value.Stream == nil && value.Certificate == nil && value.Website != nil &&
		reflect.DeepEqual(*value.Website, DefaultWebsiteOverride{Other: value.Website.Other}) &&
		value.Website.Other != nil
}

func cloneDefaults(input DefaultReferences) DefaultReferences {
	result := input
	result.Website = cloneDefaultWebsite(input.Website)
	result.Overrides = cloneDefaultScopedOverrides(input.Overrides)
	result.SiteTemplate = cloneReference(input.SiteTemplate)
	result.CachePolicy = cloneReference(input.CachePolicy)
	result.WAFPolicy = cloneReference(input.WAFPolicy)
	result.CCPolicy = cloneReference(input.CCPolicy)
	result.ACLPolicy = cloneReference(input.ACLPolicy)
	return result
}

func cloneResourceOverrides(input ResourceOverrides) ResourceOverrides {
	result := ResourceOverrides{}
	if input.Site != nil {
		site := *input.Site
		site.MaxBlacklistIPsPerSite = clonePointer(input.Site.MaxBlacklistIPsPerSite)
		site.MaxWhitelistIPsPerSite = clonePointer(input.Site.MaxWhitelistIPsPerSite)
		site.ListenDefaultHTTP80 = clonePointer(input.Site.ListenDefaultHTTP80)
		result.Site = &site
	}
	if input.Stream != nil {
		stream := *input.Stream
		stream.CustomPortNotAllow = cloneSlicePointer(input.Stream.CustomPortNotAllow)
		result.Stream = &stream
	}
	if input.SiteStream != nil {
		siteStream := *input.SiteStream
		siteStream.CustomPortNotAllow = cloneSlicePointer(input.SiteStream.CustomPortNotAllow)
		siteStream.CustomPortAllow = cloneSlicePointer(input.SiteStream.CustomPortAllow)
		result.SiteStream = &siteStream
	}
	return result
}

func cloneResourceScopedOverrides(input []ScopedResourceOverride) []ScopedResourceOverride {
	result := make([]ScopedResourceOverride, len(input))
	for index, override := range input {
		result[index] = override
		result[index].Values = cloneResourceOverrides(override.Values)
	}
	return result
}

func cloneResources(input ResourceLimits) ResourceLimits {
	result := input
	result.StreamCustomPortNotAllow = slices.Clone(input.StreamCustomPortNotAllow)
	result.CustomPortNotAllow = slices.Clone(input.CustomPortNotAllow)
	result.CustomPortAllow = slices.Clone(input.CustomPortAllow)
	result.Overrides = cloneResourceScopedOverrides(input.Overrides)
	return result
}

func effectiveNodeMonitoring(value *NodeMonitoringConfiguration) NodeMonitoringConfiguration {
	if value != nil {
		return cloneNodeMonitoring(*value)
	}
	return NodeMonitoringConfiguration{
		PortMode: PortModeDefault, ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000,
		FailureThreshold: 3, RecoveryThreshold: 3, RecoveryNotificationEnabled: true,
	}
}

func validateNodeMonitoring(value NodeMonitoringConfiguration) error {
	validPort := value.PortMode == PortModeDefault && value.CustomPort == nil ||
		value.PortMode == PortModeCustom && value.CustomPort != nil && *value.CustomPort > 0
	if !validPort || value.ProbeIntervalMS < 1_000 || value.ProbeIntervalMS > 300_000 ||
		value.ProbeTimeoutMS < 100 || value.ProbeTimeoutMS > 60_000 || value.ProbeTimeoutMS > value.ProbeIntervalMS ||
		value.FailureThreshold < 1 || value.FailureThreshold > 20 ||
		value.RecoveryThreshold < 1 || value.RecoveryThreshold > 20 ||
		value.FailureDebounceMS < 0 || value.FailureDebounceMS > 3_600_000 ||
		value.RecoveryDebounceMS < 0 || value.RecoveryDebounceMS > 3_600_000 {
		return ErrInvalidInput
	}
	if value.Protocol != "" && value.Protocol != "http" && value.Protocol != "tcp" && value.Protocol != "ping" {
		return ErrInvalidInput
	}
	if value.MonitorPort != nil && *value.MonitorPort == 0 {
		return ErrInvalidInput
	}
	if value.MonitorGroups != nil {
		groups := *value.MonitorGroups
		if len(groups) == 0 {
			return ErrInvalidInput
		}
		seen := make(map[string]struct{}, len(groups))
		for _, group := range groups {
			if group != "domestic" && group != "telecom" && group != "unicom" && group != "mobile" && group != "overseas" {
				return ErrInvalidInput
			}
			if _, ok := seen[group]; ok {
				return ErrInvalidInput
			}
			seen[group] = struct{}{}
		}
	}
	if value.MonitorAction != "" && value.MonitorAction != "none" && value.MonitorAction != "pause" {
		return ErrInvalidInput
	}
	if value.FailureRatio != nil && (*value.FailureRatio < 1 || *value.FailureRatio > 100) {
		return ErrInvalidInput
	}
	if value.BandwidthOverLimit != nil && (*value.BandwidthOverLimit < 1 || *value.BandwidthOverLimit > 20) {
		return ErrInvalidInput
	}
	return nil
}

func validateNginx(value *NginxLimits) error {
	applyNginxRuntimeDefaults(value)
	if value.Overrides == nil {
		value.Overrides = []ScopedNginxOverride{}
	}
	if err := validateNginxCore(value); err != nil {
		return err
	}
	seenID, seenScope := map[string]struct{}{}, map[string]struct{}{}
	for index := range value.Overrides {
		override := &value.Overrides[index]
		if !validScopedConfiguration(override.ID, override.Scope, override.ScopeID, true) || nginxOverrideEmpty(override.Values) {
			return ErrInvalidInput
		}
		if _, duplicate := seenID[override.ID]; duplicate {
			return ErrInvalidInput
		}
		key := override.Scope + "\x00" + override.ScopeID
		if _, duplicate := seenScope[key]; duplicate {
			return ErrInvalidInput
		}
		seenID[override.ID], seenScope[key] = struct{}{}, struct{}{}
		candidate := cloneNginx(*value)
		candidate.Overrides = nil
		mergeNginx(&candidate, override.Values)
		if err := validateNginxCore(&candidate); err != nil {
			return err
		}
	}
	sort.Slice(value.Overrides, func(i, j int) bool {
		return scopedLess(value.Overrides[i].Scope, value.Overrides[i].ScopeID, value.Overrides[i].ID, value.Overrides[j].Scope, value.Overrides[j].ScopeID, value.Overrides[j].ID)
	})
	return nil
}

func validateNginxCore(value *NginxLimits) error {
	if value.WorkerProcesses < 0 || value.WorkerProcesses > 256 ||
		value.WorkerRlimitNoFile < 1024 || value.WorkerRlimitNoFile > 1_048_576 ||
		value.WorkerShutdownTimeoutMS < 1_000 || value.WorkerShutdownTimeoutMS > 300_000 ||
		value.WorkerConnections < 128 || value.WorkerConnections > value.WorkerRlimitNoFile ||
		value.GzipLevel < 1 || value.GzipLevel > 9 ||
		value.GzipMinimumBytes < 0 || value.GzipMinimumBytes > 1<<30 ||
		value.ProxyCacheMaxBytes < 0 || value.ProxyCacheMaxBytes > 1<<50 ||
		value.ProxyMaxTempFileBytes < 0 || value.ProxyMaxTempFileBytes > 1<<40 ||
		value.ProxyConnectTimeoutMS < 100 || value.ProxyConnectTimeoutMS > 75_000 ||
		value.ProxySendTimeoutMS < 100 || value.ProxySendTimeoutMS > 3_600_000 ||
		value.ProxyReadTimeoutMS < 100 || value.ProxyReadTimeoutMS > 3_600_000 ||
		value.StreamProxyConnectTimeoutMS < 100 || value.StreamProxyConnectTimeoutMS > 75_000 ||
		value.StreamProxyTimeoutMS < 100 || value.StreamProxyTimeoutMS > 86_400_000 ||
		value.ClientBodyBufferSizeBytes < 1_024 || value.ClientBodyBufferSizeBytes > 1<<30 ||
		value.ClientMaxBodyBytes < 1_024 || value.ClientMaxBodyBytes > 10<<30 ||
		value.KeepaliveRequests < 1 || value.KeepaliveRequests > 1_000_000 ||
		value.KeepaliveTimeoutMS < 100 || value.KeepaliveTimeoutMS > 3_600_000 ||
		value.ServerNamesHashMaxSize < 512 || value.ServerNamesHashMaxSize > 65_536 ||
		value.ServerNamesHashMaxSize&(value.ServerNamesHashMaxSize-1) != 0 ||
		value.ServerNamesHashBucketSize < 32 || value.ServerNamesHashBucketSize > 1024 ||
		value.ServerNamesHashBucketSize&(value.ServerNamesHashBucketSize-1) != 0 ||
		value.LargeClientHeaderBuffers.Count < 1 || value.LargeClientHeaderBuffers.Count > 32 ||
		value.LargeClientHeaderBuffers.SizeBytes < 1_024 || value.LargeClientHeaderBuffers.SizeBytes > 1<<20 ||
		(value.GzipHTTPVersion != "1.0" && value.GzipHTTPVersion != "1.1") ||
		(value.ProxyHTTPVersion != "1.0" && value.ProxyHTTPVersion != "1.1") ||
		!validControlledPath(value.LogsDir, "/var/log/cdnca") ||
		value.ProxyCacheMinFreeBytes < 0 || value.ProxyCacheMinFreeBytes > 16<<40 || value.ProxyCacheMinFreeBytes%(1<<20) != 0 {
		return ErrInvalidInput
	}
	if value.ServerHeader != "" && (!serverHeaderPattern.MatchString(value.ServerHeader) || hasControl(value.ServerHeader)) {
		return ErrInvalidInput
	}
	if len(value.DefaultMIMEType) > 128 || !mimeTypePattern.MatchString(value.DefaultMIMEType) {
		return ErrInvalidInput
	}
	methods, err := normalizeEnumSet(value.ProxyCacheMethods, []string{"GET", "HEAD"}, 1)
	if err != nil {
		return ErrInvalidInput
	}
	value.ProxyCacheMethods = methods
	upstream, err := normalizeEnumSet(value.ProxyNextUpstream, []string{
		"error", "timeout", "invalid_header", "http_500", "http_502", "http_503", "http_504",
		"http_403", "http_404", "http_429", "non_idempotent", "off",
	}, 1)
	if err != nil || slices.Contains(upstream, "off") && len(upstream) != 1 {
		return ErrInvalidInput
	}
	value.ProxyNextUpstream = upstream
	return nil
}

func validateDefaults(value *DefaultReferences) error {
	if value.Overrides == nil {
		value.Overrides = []ScopedDefaultOverride{}
	}
	if err := validateDefaultsCore(value); err != nil {
		return err
	}
	seenID, seenScope := map[string]struct{}{}, map[string]struct{}{}
	for index := range value.Overrides {
		override := &value.Overrides[index]
		if !validScopedConfiguration(override.ID, override.Scope, override.ScopeID, false) {
			return ErrInvalidInput
		}
		if !defaultOverrideGzipOnly(override.Values) {
			return ErrRegionOverrideUnsupported
		}
		// website.other is one block on the wire; only its gzip switch and
		// types are per node, the rest follows the global value.
		override.Values.Website.Other.LoadBalancing = value.Website.Other.LoadBalancing
		override.Values.Website.Other.WebsocketEnabled = value.Website.Other.WebsocketEnabled
		if _, duplicate := seenID[override.ID]; duplicate {
			return ErrInvalidInput
		}
		if _, duplicate := seenScope[override.ScopeID]; duplicate {
			return ErrInvalidInput
		}
		seenID[override.ID], seenScope[override.ScopeID] = struct{}{}, struct{}{}
		candidate := cloneDefaults(*value)
		candidate.Overrides = nil
		mergeDefaults(&candidate, override.Values)
		if err := validateDefaultsCore(&candidate); err != nil {
			return err
		}
	}
	sort.Slice(value.Overrides, func(i, j int) bool {
		return scopedLess(value.Overrides[i].Scope, value.Overrides[i].ScopeID, value.Overrides[i].ID, value.Overrides[j].Scope, value.Overrides[j].ScopeID, value.Overrides[j].ID)
	})
	applyDefaultRuntimeProjection(value)
	return nil
}

func validateDefaultsCore(value *DefaultReferences) error {
	var err error
	value.Website.HTTP.ListenPorts, err = normalizePorts(value.Website.HTTP.ListenPorts)
	if err != nil {
		return err
	}
	value.Website.HTTPS.ListenPorts, err = normalizePorts(value.Website.HTTPS.ListenPorts)
	if err != nil || portListsOverlap(value.Website.HTTP.ListenPorts, value.Website.HTTPS.ListenPorts) {
		return ErrInvalidInput
	}
	value.Website.HTTPS.SSL.Protocols, err = normalizeEnumSet(value.Website.HTTPS.SSL.Protocols, tlsProtocolOrder, 1)
	if err != nil || len(value.Website.HTTPS.SSL.CipherSuites) > 4096 || hasControl(value.Website.HTTPS.SSL.CipherSuites) {
		return ErrInvalidInput
	}
	if !validDefaultSSLSettings(value.Website.HTTPS.SSL) {
		return ErrInvalidInput
	}
	value.Website.Origin.SSLProtocols, err = normalizeEnumSet(value.Website.Origin.SSLProtocols, tlsProtocolOrder, 1)
	if err != nil || !slices.Contains([]string{"http", "https", "follow", "follow_with_port"}, value.Website.Origin.Scheme) ||
		value.Website.Origin.HTTPPort == 0 || value.Website.Origin.HTTPSPort == 0 ||
		value.Website.Origin.ResponseTimeoutSeconds < 1 || value.Website.Origin.ResponseTimeoutSeconds > 3600 ||
		value.Website.Origin.ConnectTimeoutSeconds < 1 || value.Website.Origin.ConnectTimeoutSeconds > 75 {
		return ErrInvalidInput
	}
	if !slices.Contains([]string{"1.0", "1.1"}, value.Website.Origin.HTTPVersion) ||
		value.Website.Origin.PostBodyLimitBytes < 1_024 || value.Website.Origin.PostBodyLimitBytes > 10<<30 {
		return ErrInvalidInput
	}
	if err := normalizeCacheRules(&value.Website.CacheRules); err != nil {
		return err
	}
	if err := normalizeOriginHeaders(&value.Website.OriginRequestHeaders); err != nil {
		return err
	}
	if value.Website.AccessLog.RequestBodyLimitKB < 0 || value.Website.AccessLog.RequestBodyLimitKB > 10_240 ||
		value.Website.AccessLog.CaptureRequestBody && value.Website.AccessLog.RequestBodyLimitKB == 0 {
		return ErrInvalidInput
	}
	auto := value.Website.Security.WAFAutoBlock
	if auto.WindowSeconds < 1 || auto.WindowSeconds > 86_400 || auto.HitThreshold < 1 || auto.HitThreshold > 1_000_000 ||
		auto.BlockSeconds < 1 || auto.BlockSeconds > 604_800 || !validWAFModules(value.Website.Security.WAFModules) {
		return ErrInvalidInput
	}
	if value.Website.Security.DefaultCCPolicyID != nil && !validSafeLabel(*value.Website.Security.DefaultCCPolicyID) {
		return ErrInvalidInput
	}
	other := &value.Website.Other
	if !slices.Contains([]string{"round_robin", "ip_hash", "url_hash", "least_conn", "random"}, other.LoadBalancing) {
		return ErrInvalidInput
	}
	other.GzipTypes, err = normalizeMIMETypes(other.GzipTypes)
	if err != nil || other.GzipEnabled && len(other.GzipTypes) == 0 {
		return ErrInvalidInput
	}
	if !slices.Contains([]string{"tcp", "udp"}, value.Stream.Protocol) ||
		!slices.Contains([]string{"round_robin", "ip_hash"}, value.Stream.LoadBalancing) ||
		!slices.Contains(CertificateIssuers, value.Certificate.Issuer) {
		return ErrInvalidInput
	}
	return nil
}

func validateResources(value *ResourceLimits) error {
	applyResourceRuntimeDefaults(value)
	if value.Overrides == nil {
		value.Overrides = []ScopedResourceOverride{}
	}
	if err := validateResourcesCore(value); err != nil {
		return err
	}
	if len(value.Overrides) != 0 {
		return ErrRegionOverrideUnsupported
	}
	return nil
}

func validateResourcesCore(value *ResourceLimits) error {
	if value.MaxDomainsPerSite < 1 || value.MaxDomainsPerSite > 100 ||
		value.MaxBlacklistIPsPerSite < 1 || value.MaxBlacklistIPsPerSite > 1_000_000 ||
		value.MaxWhitelistIPsPerSite < 1 || value.MaxWhitelistIPsPerSite > 1_000_000 ||
		value.DailyURLPurgeLimit < 1 || value.DailyURLPurgeLimit > 10_000_000 ||
		value.DailyDirectoryPurgeLimit < 1 || value.DailyDirectoryPurgeLimit > 1_000_000 ||
		value.DailyPrewarmLimit < 1 || value.DailyPrewarmLimit > 10_000_000 ||
		value.DailyIPUnlockLimit < 1 || value.DailyIPUnlockLimit > 10_000_000 ||
		value.IPUnlockPerRequestLimit < 1 || value.IPUnlockPerRequestLimit > 100_000 ||
		value.MaxACLRulesPerPolicy < 1 || value.MaxACLRulesPerPolicy > 100_000 ||
		value.MaxCCRulesPerPolicy < 1 || value.MaxCCRulesPerPolicy > 100_000 ||
		value.MinimumRelatedConfigLimit < 1 || value.MinimumRelatedConfigLimit > 100_000 ||
		value.RelatedConfigMaxMultiplier < 1 || value.RelatedConfigMaxMultiplier > 1_000 ||
		value.StreamMinimumRelatedConfigLimit < 1 || value.StreamMinimumRelatedConfigLimit > 100_000 ||
		value.StreamRelatedConfigMaxMultiplier < 1 || value.StreamRelatedConfigMaxMultiplier > 100 ||
		value.DailyAccessLogDownloadLimit < 1 || value.DailyAccessLogDownloadLimit > 100_000 ||
		value.AccessLogRetentionHours < 1 || value.AccessLogRetentionHours > 720 ||
		!validResourceAccessLogPath(value.AccessLogTemporaryDir) {
		return ErrInvalidInput
	}
	var err error
	value.StreamCustomPortNotAllow, err = normalizePortRanges(value.StreamCustomPortNotAllow)
	if err != nil {
		return err
	}
	value.CustomPortNotAllow, err = normalizePortRanges(value.CustomPortNotAllow)
	if err != nil {
		return err
	}
	value.CustomPortAllow, err = normalizePortRanges(value.CustomPortAllow)
	if err != nil || portRangesOverlap(value.CustomPortNotAllow, value.CustomPortAllow) {
		return ErrInvalidInput
	}
	return nil
}

func validateErrorPages(values []ErrorPageMetadata, maxBytes int64) error {
	if len(values) > len(allowedErrorStatusCode) {
		return ErrInvalidInput
	}
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if !slices.Contains(allowedErrorStatusCode, value.StatusCode) ||
			!slices.Contains(allowedMIMETypes, value.MIMEType) ||
			value.SizeBytes < 1 || value.SizeBytes > maxBytes ||
			!hexSHA256Pattern.MatchString(value.SHA256) || !validObjectKey(value.StorageObjectKey) {
			return ErrInvalidInput
		}
		if _, duplicate := seen[value.StatusCode]; duplicate {
			return ErrInvalidInput
		}
		seen[value.StatusCode] = struct{}{}
	}
	return nil
}

func validateSecrets(value SensitiveReferences) error {
	if value.ErrorPageStorage == nil {
		return nil
	}
	secret := value.ErrorPageStorage
	if secret.Masked ||
		(secret.Provider != SecretProviderVault && secret.Provider != SecretProviderKMSEnvelope) ||
		!validSafeLabel(secret.Reference) || !validSafeLabel(secret.KeyID) ||
		(secret.Algorithm != EnvelopeAES256GCM && secret.Algorithm != EnvelopeChaCha20Poly1305 && secret.Algorithm != EnvelopeKMSManaged) ||
		!hexSHA256Pattern.MatchString(secret.CiphertextSHA256) {
		return ErrInvalidInput
	}
	return nil
}

func validObjectKey(value string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || hasControl(value) ||
		!safeKeyPattern.MatchString(value) || strings.Contains(value, "//") || strings.Contains(value, "\\") ||
		strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." || part == "" {
			return false
		}
	}
	return true
}

func validSafeLabel(value string) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) && !hasControl(value) &&
		safeLabelPattern.MatchString(value) && !strings.Contains(value, "..") && !strings.Contains(value, "//")
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}

func validWriteMetadata(key, requestID string) bool {
	return writeMetadataPattern.MatchString(key) && writeMetadataPattern.MatchString(requestID)
}

func normalizeChecks(values []PreflightCheck) ([]PreflightCheck, bool, error) {
	if len(values) != 5 {
		return nil, false, ErrInvalidInput
	}
	result := slices.Clone(values)
	seen := make(map[string]struct{}, len(result))
	passed := true
	for _, check := range result {
		if !slices.Contains([]string{PreflightSchema, PreflightReferences, PreflightCapacity, PreflightNginxSafety, PreflightErrorPages}, check.Name) ||
			(check.Status != CheckPass && check.Status != CheckFail) ||
			!utf8.ValidString(check.Detail) || hasControl(check.Detail) || utf8.RuneCountInString(check.Detail) > 512 ||
			(check.Code != "" && !metadataCodePattern.MatchString(check.Code)) ||
			(check.Status == CheckPass && check.Code != "") || (check.Status == CheckFail && check.Code == "") {
			return nil, false, ErrInvalidInput
		}
		if _, duplicate := seen[check.Name]; duplicate {
			return nil, false, ErrInvalidInput
		}
		seen[check.Name] = struct{}{}
		passed = passed && check.Status == CheckPass
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxPreflightChecksJSONBytes {
		return nil, false, ErrInvalidInput
	}
	return result, passed, nil
}

const maxPreflightChecksJSONBytes = 8192

func redactConfiguration(input Configuration) Configuration {
	result := cloneConfiguration(input)
	if result.Secrets.ErrorPageStorage != nil {
		result.Secrets.ErrorPageStorage.Reference = maskReference(result.Secrets.ErrorPageStorage.Reference)
		result.Secrets.ErrorPageStorage.Masked = true
	}
	return result
}

func maskReference(value string) string {
	if len(value) <= 4 {
		return "****"
	}
	return "****" + value[len(value)-4:]
}

func cloneConfiguration(input Configuration) Configuration {
	result := input
	result.Nginx = cloneNginx(input.Nginx)
	result.Defaults = cloneDefaults(input.Defaults)
	result.Resources = cloneResources(input.Resources)
	result.ErrorPages = slices.Clone(input.ErrorPages)
	if input.Secrets.ErrorPageStorage != nil {
		secret := *input.Secrets.ErrorPageStorage
		result.Secrets.ErrorPageStorage = &secret
	}
	result.DDoSProtection = cloneDDoSProtection(input.DDoSProtection)
	result.AccessLogFields = cloneAccessLogFields(input.AccessLogFields)
	if input.NodeMonitoring != nil {
		nodeMonitoring := cloneNodeMonitoring(*input.NodeMonitoring)
		result.NodeMonitoring = &nodeMonitoring
	}
	return result
}

func cloneNodeMonitoring(input NodeMonitoringConfiguration) NodeMonitoringConfiguration {
	result := input
	if input.CustomPort != nil {
		customPort := *input.CustomPort
		result.CustomPort = &customPort
	}
	if input.MonitorEnabled != nil {
		monitorEnabled := *input.MonitorEnabled
		result.MonitorEnabled = &monitorEnabled
	}
	if input.MonitorPort != nil {
		monitorPort := *input.MonitorPort
		result.MonitorPort = &monitorPort
	}
	if input.FailureRatio != nil {
		failureRatio := *input.FailureRatio
		result.FailureRatio = &failureRatio
	}
	if input.BandwidthOverLimit != nil {
		bandwidthOverLimit := *input.BandwidthOverLimit
		result.BandwidthOverLimit = &bandwidthOverLimit
	}
	if input.MonitorGroups != nil {
		groups := slices.Clone(*input.MonitorGroups)
		result.MonitorGroups = &groups
	}
	return result
}

func cloneReference(input *RevisionReference) *RevisionReference {
	if input == nil {
		return nil
	}
	result := *input
	return &result
}

func MergeSiteOverride(global Configuration, override SiteOverride) (Configuration, error) {
	result := cloneConfiguration(global)
	mergeNginx(&result.Nginx, override.Nginx)
	mergeDefaults(&result.Defaults, override.Defaults)
	mergeResources(&result.Resources, override.Resources)
	if err := validateErrorPages(override.ErrorPages, result.Resources.MaxCustomErrorPageBytes); err != nil {
		return Configuration{}, err
	}
	byStatus := make(map[int]ErrorPageMetadata, len(result.ErrorPages)+len(override.ErrorPages))
	for _, item := range result.ErrorPages {
		byStatus[item.StatusCode] = item
	}
	for _, item := range override.ErrorPages {
		byStatus[item.StatusCode] = item
	}
	result.ErrorPages = result.ErrorPages[:0]
	for _, item := range byStatus {
		result.ErrorPages = append(result.ErrorPages, item)
	}
	return normalizeConfiguration(result)
}

// ResolveScopedConfiguration materializes the effective control-plane values
// for one region/node without changing the canonical global document. Region
// values are applied first and node values last.
func ResolveScopedConfiguration(global Configuration, regionID, nodeID string) (Configuration, error) {
	normalized, _, _, err := CanonicalSnapshot(global)
	if err != nil {
		return Configuration{}, err
	}
	result := cloneConfiguration(normalized)
	for _, override := range normalized.Nginx.Overrides {
		if override.Scope == ConfigurationScopeRegion && override.ScopeID == regionID {
			mergeNginx(&result.Nginx, override.Values)
		}
	}
	for _, override := range normalized.Nginx.Overrides {
		if override.Scope == ConfigurationScopeNode && override.ScopeID == nodeID {
			mergeNginx(&result.Nginx, override.Values)
		}
	}
	// Region defaults overrides carry only the gzip switch and types (the
	// edge renders them per node, validateDefaults).
	for _, override := range normalized.Defaults.Overrides {
		if override.ScopeID == regionID {
			other := override.Values.Website.Other
			result.Defaults.Website.Other.GzipEnabled = other.GzipEnabled
			result.Defaults.Website.Other.GzipTypes = slices.Clone(other.GzipTypes)
		}
	}
	result.Nginx.Overrides = []ScopedNginxOverride{}
	result.Defaults.Overrides = []ScopedDefaultOverride{}
	result.Resources.Overrides = []ScopedResourceOverride{}
	if err := validateNginxCore(&result.Nginx); err != nil {
		return Configuration{}, err
	}
	if err := validateDefaultsCore(&result.Defaults); err != nil {
		return Configuration{}, err
	}
	if err := validateResourcesCore(&result.Resources); err != nil {
		return Configuration{}, err
	}
	return result, nil
}

func mergeNginx(target *NginxLimits, value NginxOverride) {
	if value.Worker != nil {
		set(value.Worker.WorkerProcesses, &target.WorkerProcesses)
		set(value.Worker.WorkerConnections, &target.WorkerConnections)
		set(value.Worker.WorkerRlimitNoFile, &target.WorkerRlimitNoFile)
		set(value.Worker.WorkerShutdownTimeoutMS, &target.WorkerShutdownTimeoutMS)
		set(value.Worker.LogsDir, &target.LogsDir)
	}
	if value.HTTP != nil {
		set(value.HTTP.GzipLevel, &target.GzipLevel)
		set(value.HTTP.GzipHTTPVersion, &target.GzipHTTPVersion)
		set(value.HTTP.GzipMinimumBytes, &target.GzipMinimumBytes)
		set(value.HTTP.GzipVary, &target.GzipVary)
		set(value.HTTP.ServerAddrOutgoing, &target.ServerAddrOutgoing)
		set(value.HTTP.ProxyRequestBuffering, &target.ProxyRequestBuffering)
		set(value.HTTP.ProxyBuffering, &target.ProxyBuffering)
		set(value.HTTP.ProxyCacheMaxBytes, &target.ProxyCacheMaxBytes)
		set(value.HTTP.ProxyCacheMinFreeBytes, &target.ProxyCacheMinFreeBytes)
		if value.HTTP.ProxyCacheMethods != nil {
			target.ProxyCacheMethods = slices.Clone(*value.HTTP.ProxyCacheMethods)
		}
		set(value.HTTP.ProxyHTTPVersion, &target.ProxyHTTPVersion)
		set(value.HTTP.ProxyMaxTempFileBytes, &target.ProxyMaxTempFileBytes)
		if value.HTTP.ProxyNextUpstream != nil {
			target.ProxyNextUpstream = slices.Clone(*value.HTTP.ProxyNextUpstream)
		}
		set(value.HTTP.ProxyConnectTimeoutMS, &target.ProxyConnectTimeoutMS)
		set(value.HTTP.ProxySendTimeoutMS, &target.ProxySendTimeoutMS)
		set(value.HTTP.ProxyReadTimeoutMS, &target.ProxyReadTimeoutMS)
		set(value.HTTP.ClientBodyBufferSizeBytes, &target.ClientBodyBufferSizeBytes)
		set(value.HTTP.ServerHeader, &target.ServerHeader)
		set(value.HTTP.ClientMaxBodyBytes, &target.ClientMaxBodyBytes)
		set(value.HTTP.DefaultMIMEType, &target.DefaultMIMEType)
		set(value.HTTP.KeepaliveRequests, &target.KeepaliveRequests)
		set(value.HTTP.KeepaliveTimeoutMS, &target.KeepaliveTimeoutMS)
		set(value.HTTP.LogNotFound, &target.LogNotFound)
		set(value.HTTP.ServerTokens, &target.ServerTokens)
		set(value.HTTP.LargeClientHeaderBuffers, &target.LargeClientHeaderBuffers)
		set(value.HTTP.ServerNamesHashMaxSize, &target.ServerNamesHashMaxSize)
		set(value.HTTP.ServerNamesHashBucketSize, &target.ServerNamesHashBucketSize)
	}
	if value.Stream != nil {
		set(value.Stream.ProxyConnectTimeoutMS, &target.StreamProxyConnectTimeoutMS)
		set(value.Stream.ProxyTimeoutMS, &target.StreamProxyTimeoutMS)
	}
}

func mergeDefaults(target *DefaultReferences, value DefaultOverrides) {
	if value.Website != nil {
		website := value.Website
		if website.HTTPListenPorts != nil {
			target.Website.HTTP.ListenPorts = slices.Clone(*website.HTTPListenPorts)
		}
		if website.HTTPSListenPorts != nil {
			target.Website.HTTPS.ListenPorts = slices.Clone(*website.HTTPSListenPorts)
		}
		set(website.HSTSEnabled, &target.Website.HTTPS.HSTSEnabled)
		set(website.HTTP2Enabled, &target.Website.HTTPS.HTTP2Enabled)
		set(website.HTTP3Enabled, &target.Website.HTTPS.HTTP3Enabled)
		set(website.ForceHTTPS, &target.Website.HTTPS.ForceHTTPS)
		if website.SSL != nil {
			target.Website.HTTPS.SSL = *website.SSL
			target.Website.HTTPS.SSL.Protocols = slices.Clone(website.SSL.Protocols)
		}
		set(website.OCSPStaplingEnabled, &target.Website.HTTPS.OCSPStaplingEnabled)
		if website.Origin != nil {
			origin := website.Origin
			set(origin.Scheme, &target.Website.Origin.Scheme)
			set(origin.HTTPPort, &target.Website.Origin.HTTPPort)
			set(origin.HTTPSPort, &target.Website.Origin.HTTPSPort)
			set(origin.ResponseTimeoutSeconds, &target.Website.Origin.ResponseTimeoutSeconds)
			set(origin.ConnectTimeoutSeconds, &target.Website.Origin.ConnectTimeoutSeconds)
			if origin.SSLProtocols != nil {
				target.Website.Origin.SSLProtocols = slices.Clone(*origin.SSLProtocols)
			}
			set(origin.HTTPVersion, &target.Website.Origin.HTTPVersion)
			set(origin.KeepaliveEnabled, &target.Website.Origin.KeepaliveEnabled)
			set(origin.PostBodyLimitBytes, &target.Website.Origin.PostBodyLimitBytes)
		}
		if website.CacheRules != nil {
			target.Website.CacheRules = make([]DefaultCacheRule, len(*website.CacheRules))
			for index, rule := range *website.CacheRules {
				target.Website.CacheRules[index] = cloneCacheRule(rule)
			}
		}
		if website.OriginRequestHeaders != nil {
			target.Website.OriginRequestHeaders = make([]DefaultOriginRequestHeader, len(*website.OriginRequestHeaders))
			for index, header := range *website.OriginRequestHeaders {
				target.Website.OriginRequestHeaders[index] = cloneOriginHeader(header)
			}
		}
		if website.DefaultCCPolicyID != nil {
			target.Website.Security.DefaultCCPolicyID = clonePointer(*website.DefaultCCPolicyID)
		}
		set(website.WAFEnabled, &target.Website.Security.WAFEnabled)
		set(website.WAFModules, &target.Website.Security.WAFModules)
		if website.Other != nil {
			target.Website.Other = *website.Other
			target.Website.Other.GzipTypes = slices.Clone(website.Other.GzipTypes)
		}
	}
	if value.Stream != nil {
		set(value.Stream.Protocol, &target.Stream.Protocol)
		set(value.Stream.LoadBalancing, &target.Stream.LoadBalancing)
		set(value.Stream.ProxyProtocolEnabled, &target.Stream.ProxyProtocolEnabled)
	}
	if value.Certificate != nil {
		set(value.Certificate.Issuer, &target.Certificate.Issuer)
	}
	applyDefaultRuntimeProjection(target)
}

func mergeResources(target *ResourceLimits, value ResourceOverrides) {
	if value.Site != nil {
		set(value.Site.MaxBlacklistIPsPerSite, &target.MaxBlacklistIPsPerSite)
		set(value.Site.MaxWhitelistIPsPerSite, &target.MaxWhitelistIPsPerSite)
		set(value.Site.ListenDefaultHTTP80, &target.ListenDefaultHTTP80)
	}
	if value.Stream != nil && value.Stream.CustomPortNotAllow != nil {
		target.StreamCustomPortNotAllow = slices.Clone(*value.Stream.CustomPortNotAllow)
	}
	if value.SiteStream != nil {
		if value.SiteStream.CustomPortNotAllow != nil {
			target.CustomPortNotAllow = slices.Clone(*value.SiteStream.CustomPortNotAllow)
		}
		if value.SiteStream.CustomPortAllow != nil {
			target.CustomPortAllow = slices.Clone(*value.SiteStream.CustomPortAllow)
		}
	}
}

func set[T any](source *T, target *T) {
	if source != nil {
		*target = *source
	}
}

var uuidNil = [16]byte{}
