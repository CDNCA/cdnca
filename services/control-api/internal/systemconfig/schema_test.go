package systemconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCanonicalSnapshotDeterministicAndStrict(t *testing.T) {
	first := validConfiguration()
	second := validConfiguration()
	second.Nginx.ResolverAddresses = []string{"2001:db8::53", "1.1.1.1"}
	second.Nginx.ProxyCacheMethods = []string{"HEAD", "GET"}
	second.ErrorPages[0], second.ErrorPages[1] = second.ErrorPages[1], second.ErrorPages[0]

	firstNormalized, firstBytes, firstHash, err := CanonicalSnapshot(first)
	if err != nil {
		t.Fatal(err)
	}
	secondNormalized, secondBytes, secondHash, err := CanonicalSnapshot(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || firstHash != secondHash {
		t.Fatalf("semantically equal inputs produced different snapshots\n%s\n%s", firstBytes, secondBytes)
	}
	if firstNormalized.Nginx.ResolverAddresses[0] != "1.1.1.1" ||
		secondNormalized.ErrorPages[0].StatusCode != 404 {
		t.Fatal("canonical collections were not sorted")
	}
	if _, err := decodeCanonicalSnapshot(firstBytes, firstHash); err != nil {
		t.Fatalf("decode canonical snapshot: %v", err)
	}
	tampered := bytes.Replace(firstBytes, []byte(`"worker_connections": 4096`), []byte(`"worker_connections": 4097`), 1)
	if _, err := decodeCanonicalSnapshot(tampered, firstHash); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("tampered snapshot error = %v, want ErrInvalidInput", err)
	}
}

func TestProjectBootstrapResourcesMatchObservedCanonical(t *testing.T) {
	resources := ProjectBootstrapConfiguration().Resources
	for _, test := range []struct {
		name string
		got  any
		want any
	}{
		{name: "site related minimum", got: resources.MinimumRelatedConfigLimit, want: 1_000},
		{name: "site related multiplier", got: resources.RelatedConfigMaxMultiplier, want: 200},
		{name: "blacklist limit", got: resources.MaxBlacklistIPsPerSite, want: 50},
		{name: "whitelist limit", got: resources.MaxWhitelistIPsPerSite, want: 50},
		{name: "daily URL purge", got: resources.DailyURLPurgeLimit, want: 2_000},
		{name: "daily directory purge", got: resources.DailyDirectoryPurgeLimit, want: 500},
		{name: "daily prewarm", got: resources.DailyPrewarmLimit, want: 2_000},
		{name: "daily IP unlock", got: resources.DailyIPUnlockLimit, want: 1_000},
		{name: "IP unlock per request", got: resources.IPUnlockPerRequestLimit, want: 50},
		{name: "CC rule limit", got: resources.MaxCCRulesPerPolicy, want: 5},
		{name: "domain limit", got: resources.MaxDomainsPerSite, want: 100},
		{name: "default HTTP 80", got: resources.ListenDefaultHTTP80, want: true},
		{name: "daily log downloads", got: resources.DailyAccessLogDownloadLimit, want: 10},
		{name: "log temporary directory", got: resources.AccessLogTemporaryDir, want: "/data/download-temp/"},
		{name: "log retention", got: resources.AccessLogRetentionHours, want: 12},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("bootstrap value = %#v, want %#v", test.got, test.want)
			}
		})
	}
	if _, _, _, err := CanonicalSnapshot(ProjectBootstrapConfiguration()); err != nil {
		t.Fatalf("bootstrap must remain canonical: %v", err)
	}
}

func TestProjectBootstrapDefaultsMatchObservedCanonical(t *testing.T) {
	website := ProjectBootstrapConfiguration().Defaults.Website
	if website.HTTPS.HTTP2Enabled || website.HTTPS.SSL.Mode != "legacy_tls12" ||
		!website.HTTPS.SSL.PreferServerCiphers || website.HTTPS.SSL.CipherSuites != legacyTLS12CipherSuites ||
		!slices.Equal(website.HTTPS.SSL.Protocols, []string{"TLSv1.2", "TLSv1.3"}) {
		t.Fatalf("bootstrap HTTPS defaults drifted: %#v", website.HTTPS)
	}
	if !slices.Equal(website.Origin.SSLProtocols, []string{"TLSv1", "TLSv1.1", "TLSv1.2"}) {
		t.Fatalf("bootstrap origin TLS defaults = %#v", website.Origin.SSLProtocols)
	}
	if !website.AccessLog.CaptureRequestHeaders || website.AccessLog.CaptureResponseHeaders ||
		website.AccessLog.CaptureRequestBody || website.AccessLog.RequestBodyLimitKB != 16 {
		t.Fatalf("bootstrap access-log defaults drifted: %#v", website.AccessLog)
	}
	if website.Other.LoadBalancing != "round_robin" || website.Other.WebsocketEnabled || !website.Other.GzipEnabled ||
		!slices.Equal(website.Other.GzipTypes, []string{
			"text/plain", "text/css", "text/xml", "text/javascript",
			"application/javascript", "application/x-javascript", "application/json",
		}) {
		t.Fatalf("bootstrap other defaults drifted: %#v", website.Other)
	}
	if _, _, _, err := CanonicalSnapshot(ProjectBootstrapConfiguration()); err != nil {
		t.Fatalf("bootstrap must remain canonical: %v", err)
	}
}

func TestResourceAccessLogTemporaryPathValidation(t *testing.T) {
	for _, value := range []string{
		"/data/download-temp", "/data/download-temp/", "/data/download-temp/tenant-1",
		"/data/download-temp/tenant-1/", "/var/lib/cdnca", "/var/lib/cdnca/",
		"/var/lib/cdnca/access-log-downloads", "/var/lib/cdnca/access-log-downloads/",
	} {
		t.Run("accept "+value, func(t *testing.T) {
			configuration := ProjectBootstrapConfiguration()
			configuration.Resources.AccessLogTemporaryDir = value
			if _, _, _, err := CanonicalSnapshot(configuration); err != nil {
				t.Fatalf("CanonicalSnapshot(%q): %v", value, err)
			}
		})
	}
	for _, value := range []string{
		"/data/download-temp-copy/", "/data/download-temp//tenant", "/data/download-temp/../escape",
		"/data/download-temp\\escape", "/data/download-temp/\n", "/var/lib/cdnca//access-logs",
	} {
		t.Run("reject "+value, func(t *testing.T) {
			configuration := ProjectBootstrapConfiguration()
			configuration.Resources.AccessLogTemporaryDir = value
			if _, _, _, err := CanonicalSnapshot(configuration); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("CanonicalSnapshot(%q) error = %v, want ErrInvalidInput", value, err)
			}
		})
	}
}

func TestConfigurationRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Configuration)
	}{
		{"nginx directive injection", func(value *Configuration) { value.Nginx.ServerHeader = "cdn\nreturn 200;" }},
		{"nginx log path escape", func(value *Configuration) { value.Nginx.LogsDir = "/var/log/cdnca/../nginx" }},
		{"nginx cache min free not whole MiB", func(value *Configuration) { value.Nginx.ProxyCacheMinFreeBytes = 1<<20 + 1 }},
		{"nginx cache min free negative", func(value *Configuration) { value.Nginx.ProxyCacheMinFreeBytes = -1 }},
		{"unsafe object path", func(value *Configuration) { value.ErrorPages[0].StorageObjectKey = "errors/../nginx.conf" }},
		{"mime control", func(value *Configuration) { value.ErrorPages[0].MIMEType = "text/html\r\nX: y" }},
		{"unsupported status", func(value *Configuration) { value.ErrorPages[0].StatusCode = 200 }},
		{"oversize page", func(value *Configuration) { value.ErrorPages[0].SizeBytes = 1<<20 + 1 }},
		{"secret locator injection", func(value *Configuration) { value.Secrets.ErrorPageStorage.Reference = "vault:secret;cat" }},
		{"masked write", func(value *Configuration) { value.Secrets.ErrorPageStorage.Masked = true }},
		{"unsafe connection limit", func(value *Configuration) { value.Nginx.WorkerConnections = value.Nginx.WorkerRlimitNoFile + 1 }},
		{"invalid origin scheme", func(value *Configuration) { value.Defaults.Website.Origin.Scheme = "ftp" }},
		{"invalid origin HTTP version", func(value *Configuration) { value.Defaults.Website.Origin.HTTPVersion = "2" }},
		{"invalid origin POST limit", func(value *Configuration) { value.Defaults.Website.Origin.PostBodyLimitBytes = 1023 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validConfiguration()
			test.mutate(&value)
			if _, _, _, err := CanonicalSnapshot(value); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("CanonicalSnapshot error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestSecretReferenceIsMaskedOnRead(t *testing.T) {
	value := validConfiguration()
	masked := redactConfiguration(value)
	if masked.Secrets.ErrorPageStorage == nil || !masked.Secrets.ErrorPageStorage.Masked ||
		masked.Secrets.ErrorPageStorage.Reference != "****html" {
		t.Fatalf("masked reference = %#v", masked.Secrets.ErrorPageStorage)
	}
	if value.Secrets.ErrorPageStorage.Reference != "vault:error-pages/prod-html" || value.Secrets.ErrorPageStorage.Masked {
		t.Fatal("redaction mutated the source configuration")
	}
	encoded, err := json.Marshal(masked)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("vault:error-pages/prod-html")) || bytes.Contains(encoded, []byte("plaintext")) {
		t.Fatalf("redacted response leaked sensitive value: %s", encoded)
	}
}

func TestMergeSiteOverrideUsesOverrideThenGlobalInheritance(t *testing.T) {
	global := validConfiguration()
	connections := 2048
	maxBlacklist := 12_000
	originScheme := "https"
	page := global.ErrorPages[0]
	page.StorageObjectKey = "errors/site-404.html"
	page.SHA256 = strings.Repeat("c", 64)
	merged, err := MergeSiteOverride(global, SiteOverride{
		Nginx: NginxOverride{Worker: &NginxWorkerOverride{WorkerConnections: &connections}},
		Defaults: DefaultOverrides{Website: &DefaultWebsiteOverride{
			Origin: &DefaultWebsiteOriginOverride{Scheme: &originScheme},
		}},
		Resources:  ResourceOverrides{Site: &ResourceSiteOverride{MaxBlacklistIPsPerSite: &maxBlacklist}},
		ErrorPages: []ErrorPageMetadata{page},
	})
	if err != nil {
		t.Fatal(err)
	}
	if merged.Nginx.WorkerConnections != connections || merged.Nginx.GzipLevel != global.Nginx.GzipLevel ||
		merged.Defaults.OriginScheme != "https" || merged.Defaults.ListenPort != global.Defaults.ListenPort ||
		merged.Resources.MaxBlacklistIPsPerSite != maxBlacklist || merged.Resources.MaxSitesPerTenant != global.Resources.MaxSitesPerTenant {
		t.Fatalf("unexpected merged configuration: %#v", merged)
	}
	if merged.ErrorPages[0].StorageObjectKey != "errors/site-404.html" || len(merged.ErrorPages) != 2 {
		t.Fatalf("error-page precedence failed: %#v", merged.ErrorPages)
	}
	if global.Nginx.WorkerConnections == connections || global.ErrorPages[0].StorageObjectKey == page.StorageObjectKey {
		t.Fatal("merge mutated the global configuration")
	}

	badHeader := "cdn; include /tmp/x"
	if _, err := MergeSiteOverride(global, SiteOverride{Nginx: NginxOverride{HTTP: &NginxHTTPOverride{ServerHeader: &badHeader}}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsafe override error = %v, want ErrInvalidInput", err)
	}
}

func TestCanonicalV2ScopedResolutionUsesNodeThenRegionThenGlobal(t *testing.T) {
	configuration := validConfiguration()
	regionConnections, nodeConnections := 8_192, 16_384
	configuration.Nginx.Overrides = []ScopedNginxOverride{
		{ID: "region01", Scope: ConfigurationScopeRegion, ScopeID: "east", Values: NginxOverride{
			Worker: &NginxWorkerOverride{WorkerConnections: &regionConnections},
		}},
		{ID: "node0001", Scope: ConfigurationScopeNode, ScopeID: "edge-a", Values: NginxOverride{
			Worker: &NginxWorkerOverride{WorkerConnections: &nodeConnections},
		}},
	}
	configuration.Defaults.Overrides = []ScopedDefaultOverride{{
		ID: "default1", Scope: ConfigurationScopeRegion, ScopeID: "east",
		Values: DefaultOverrides{Website: &DefaultWebsiteOverride{Other: &DefaultWebsiteOtherSettings{
			LoadBalancing: "ip_hash", GzipEnabled: false, WebsocketEnabled: true,
		}}},
	}}

	effective, err := ResolveScopedConfiguration(configuration, "east", "edge-a")
	if err != nil {
		t.Fatal(err)
	}
	// Only the gzip switch follows the region; load balancing and WebSocket in
	// the same block stay global (normalized to the global values).
	if effective.Nginx.WorkerConnections != nodeConnections || effective.Defaults.Website.Other.GzipEnabled ||
		effective.Defaults.Website.Other.LoadBalancing != configuration.Defaults.Website.Other.LoadBalancing ||
		effective.Defaults.Website.Other.WebsocketEnabled != configuration.Defaults.Website.Other.WebsocketEnabled {
		t.Fatalf("unexpected effective configuration: %#v", effective)
	}
	if len(effective.Nginx.Overrides) != 0 || len(effective.Defaults.Overrides) != 0 || len(effective.Resources.Overrides) != 0 {
		t.Fatal("effective configuration retained canonical override metadata")
	}
	if configuration.Nginx.WorkerConnections == nodeConnections || !configuration.Defaults.Website.Other.GzipEnabled {
		t.Fatal("scoped resolution mutated the canonical source")
	}

	regionOnly, err := ResolveScopedConfiguration(configuration, "east", "missing")
	if err != nil {
		t.Fatal(err)
	}
	if regionOnly.Nginx.WorkerConnections != regionConnections {
		t.Fatalf("region precedence = %d, want %d", regionOnly.Nginx.WorkerConnections, regionConnections)
	}
}

// Settings read when a site/forward/certificate is created
// have no single region, so their region overrides are refused; only the
// defaults' gzip switch and types (rendered per node) remain.
func TestCanonicalV2RefusesBuildTimeRegionOverrides(t *testing.T) {
	blacklist, whitelist, on := 20_000, 30_000, true
	ports := []PortRange{{From: 8000, To: 8100}}
	listen := []uint16{8080}
	scheme, port, issuer, protocol := "https", uint16(8443), "zerossl", "udp"
	region := func(values ResourceOverrides) []ScopedResourceOverride {
		return []ScopedResourceOverride{{ID: "resource01", Scope: ConfigurationScopeRegion, ScopeID: "east", Values: values}}
	}
	for name, values := range map[string]ResourceOverrides{
		"black_ip_limit":                    {Site: &ResourceSiteOverride{MaxBlacklistIPsPerSite: &blacklist}},
		"white_ip_limit":                    {Site: &ResourceSiteOverride{MaxWhitelistIPsPerSite: &whitelist}},
		"listen_default_http_80":            {Site: &ResourceSiteOverride{ListenDefaultHTTP80: &on}},
		"stream.custom_port_not_allow":      {Stream: &ResourceStreamOverride{CustomPortNotAllow: &ports}},
		"site_stream.custom_port_not_allow": {SiteStream: &ResourceSiteStreamOverride{CustomPortNotAllow: &ports}},
		"site_stream.custom_port_allow":     {SiteStream: &ResourceSiteStreamOverride{CustomPortAllow: &ports}},
	} {
		configuration := validConfiguration()
		configuration.Resources.Overrides = region(values)
		if _, _, _, err := CanonicalSnapshot(configuration); !errors.Is(err, ErrRegionOverrideUnsupported) || !errors.Is(err, ErrInvalidInput) {
			t.Errorf("resources %s: error = %v, want ErrRegionOverrideUnsupported", name, err)
		}
	}
	gzipOther := &DefaultWebsiteOtherSettings{LoadBalancing: "round_robin", GzipEnabled: true, GzipTypes: []string{"text/css"}}
	for name, values := range map[string]DefaultOverrides{
		"http_listen_ports":  {Website: &DefaultWebsiteOverride{HTTPListenPorts: &listen}},
		"https_listen_ports": {Website: &DefaultWebsiteOverride{HTTPSListenPorts: &listen}},
		"hsts_enabled":       {Website: &DefaultWebsiteOverride{HSTSEnabled: &on}},
		"force_https":        {Website: &DefaultWebsiteOverride{ForceHTTPS: &on}},
		"origin.scheme":      {Website: &DefaultWebsiteOverride{Origin: &DefaultWebsiteOriginOverride{Scheme: &scheme}}},
		"origin.http_port":   {Website: &DefaultWebsiteOverride{Origin: &DefaultWebsiteOriginOverride{HTTPPort: &port}}},
		"waf_enabled":        {Website: &DefaultWebsiteOverride{WAFEnabled: &on}},
		"stream.protocol":    {Stream: &DefaultStreamOverride{Protocol: &protocol}},
		"certificate.issuer": {Certificate: &DefaultCertificateOverride{Issuer: &issuer}},
		"gzip_with_hsts":     {Website: &DefaultWebsiteOverride{Other: gzipOther, HSTSEnabled: &on}},
		"empty":              {},
	} {
		configuration := validConfiguration()
		configuration.Defaults.Overrides = []ScopedDefaultOverride{{ID: "default01", Scope: ConfigurationScopeRegion, ScopeID: "east", Values: values}}
		if _, _, _, err := CanonicalSnapshot(configuration); !errors.Is(err, ErrRegionOverrideUnsupported) {
			t.Errorf("defaults %s: error = %v, want ErrRegionOverrideUnsupported", name, err)
		}
	}

	configuration := validConfiguration()
	configuration.Defaults.Overrides = []ScopedDefaultOverride{{ID: "default01", Scope: ConfigurationScopeRegion, ScopeID: "east",
		Values: DefaultOverrides{Website: &DefaultWebsiteOverride{Other: &DefaultWebsiteOtherSettings{
			LoadBalancing: "least_conn", GzipEnabled: true, GzipTypes: []string{"text/css"}, WebsocketEnabled: true}}}}}
	normalized, _, _, err := CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatalf("gzip region override: %v", err)
	}
	other := normalized.Defaults.Overrides[0].Values.Website.Other
	if other.LoadBalancing != configuration.Defaults.Website.Other.LoadBalancing ||
		other.WebsocketEnabled != configuration.Defaults.Website.Other.WebsocketEnabled ||
		!other.GzipEnabled || !slices.Equal(other.GzipTypes, []string{"text/css"}) {
		t.Fatalf("gzip override not normalized to gzip only: %#v", other)
	}
}

func TestCanonicalV2WireRejectsUnknownAndLegacyFields(t *testing.T) {
	configuration := validConfiguration()
	_, snapshot, hash, err := CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range [][]byte{
		bytes.Replace(snapshot, []byte(`"worker": {`), []byte(`"worker": {"unknown": 1, `), 1),
		bytes.Replace(snapshot, []byte(`"nginx": {`), []byte(`"nginx": {"worker_connections": 4096, `), 1),
	} {
		if bytes.Equal(mutation, snapshot) {
			t.Fatal("test mutation did not change canonical bytes")
		}
		if _, err := decodeCanonicalSnapshot(mutation, hash); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("unknown/legacy field error = %v, want ErrInvalidInput", err)
		}
	}
	if !bytes.Contains(snapshot, []byte(`"schema": "cdnca.system-configuration/v2"`)) ||
		!bytes.Contains(snapshot, []byte(`"nginx": {"http":`)) ||
		bytes.Contains(snapshot, []byte(`"server_header"`)) {
		t.Fatalf("unexpected v2 wire: %s", snapshot)
	}
}

func TestCanonicalV2DefaultSSLAndCacheContract(t *testing.T) {
	for _, ssl := range []DefaultSSLSettings{
		{Mode: "recommended", Protocols: []string{"TLSv1.2", "TLSv1.3"}, CipherSuites: recommendedSSLCipherSuites},
		{Mode: "legacy_tls12", Protocols: []string{"TLSv1.2", "TLSv1.3"}, CipherSuites: legacyTLS12CipherSuites, PreferServerCiphers: true},
		{Mode: "legacy_full", Protocols: []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}, CipherSuites: "DEFAULT:@SECLEVEL=0", PreferServerCiphers: true},
	} {
		configuration := validConfiguration()
		configuration.Defaults.Website.HTTPS.SSL = ssl
		if _, _, _, err := CanonicalSnapshot(configuration); err != nil {
			t.Fatalf("valid SSL mode %q: %v", ssl.Mode, err)
		}
	}

	for _, mutate := range []func(*DefaultSSLSettings){
		func(value *DefaultSSLSettings) { value.Mode = "preset" },
		func(value *DefaultSSLSettings) { value.PreferServerCiphers = false },
		func(value *DefaultSSLSettings) { value.CipherSuites = "HIGH:!aNULL:!MD5" },
		func(value *DefaultSSLSettings) { value.Protocols = []string{"TLSv1.1", "TLSv1.2", "TLSv1.3"} },
		func(value *DefaultSSLSettings) { value.Mode = "custom"; value.Protocols = []string{"SSLv2", "SSLv2"} },
		func(value *DefaultSSLSettings) { value.Mode = "custom"; value.Protocols = []string{"TLSv1.4"} },
		// ge-tls: "custom" (a free cipher string nothing could check) is gone;
		// new sites inherit one of the three presets.
		func(value *DefaultSSLSettings) {
			value.Mode, value.Protocols, value.CipherSuites = "custom", []string{"TLSv1.3"}, "TLS_AES_128_GCM_SHA256"
		},
	} {
		configuration := validConfiguration()
		mutate(&configuration.Defaults.Website.HTTPS.SSL)
		if _, _, _, err := CanonicalSnapshot(configuration); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid SSL preset error = %v, want ErrInvalidInput", err)
		}
	}

	configuration := validConfiguration()
	configuration.Defaults.Website.Origin.SSLProtocols = []string{"SSLv3", "SSLv2"}
	normalized, snapshot, _, err := CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatalf("valid origin SSLv2/SSLv3 protocols: %v", err)
	}
	if !slices.Equal(normalized.Defaults.Website.Origin.SSLProtocols, []string{"SSLv2", "SSLv3"}) ||
		!bytes.Contains(snapshot, []byte(`"ssl_protocols": ["SSLv2", "SSLv3"]`)) {
		t.Fatalf("origin SSL protocols were not canonically persisted: %#v %s",
			normalized.Defaults.Website.Origin.SSLProtocols, snapshot)
	}
	for _, protocols := range [][]string{{"SSLv3", "SSLv3"}, {"TLSv1.4"}} {
		configuration := validConfiguration()
		configuration.Defaults.Website.Origin.SSLProtocols = protocols
		if _, _, _, err := CanonicalSnapshot(configuration); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid origin SSL protocols %#v error = %v, want ErrInvalidInput", protocols, err)
		}
	}

	content := "/"
	configuration = validConfiguration()
	configuration.Defaults.Website.CacheRules = []DefaultCacheRule{{
		ID: "cache001", Match: "dir", Content: &content, TTLSeconds: 259_200,
		IgnoreQuery: true, ForceCache: true, Range: true, IgnoreVary: true,
		NoCache: []DefaultCacheNoCacheCondition{{Variable: "$http_cookie", String: "wordpress_logged_in"}},
		Enabled: true, Position: 0,
	}}
	normalized, snapshot, _, err = CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatalf("valid cache rule: %v", err)
	}
	if len(normalized.Defaults.Website.CacheRules[0].NoCache) != 1 ||
		!bytes.Contains(snapshot, []byte(`"range": true`)) ||
		!bytes.Contains(snapshot, []byte(`"ignore_vary": true`)) ||
		!bytes.Contains(snapshot, []byte(`"no_cache": [{"string": "wordpress_logged_in", "variable": "$http_cookie"}]`)) {
		t.Fatalf("cache rule extensions missing from canonical snapshot: %s", snapshot)
	}

	for _, condition := range []DefaultCacheNoCacheCondition{
		{Variable: "", String: "wordpress_logged_in"},
		{Variable: "$http_cookie\n", String: "wordpress_logged_in"},
		{Variable: "$http_cookie", String: ""},
		{Variable: "$http_cookie", String: "wordpress\nlogged_in"},
	} {
		configuration := validConfiguration()
		configuration.Defaults.Website.CacheRules = []DefaultCacheRule{{
			ID: "cache001", Match: "dir", NoCache: []DefaultCacheNoCacheCondition{condition}, Enabled: true,
		}}
		if _, _, _, err := CanonicalSnapshot(configuration); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid no-cache condition %#v error = %v, want ErrInvalidInput", condition, err)
		}
	}
}

func TestPreflightChecksAreTypedAndDeterministic(t *testing.T) {
	checks := []PreflightCheck{
		{Name: PreflightNginxSafety, Status: CheckPass},
		{Name: PreflightSchema, Status: CheckFail, Code: "schema.invalid", Detail: "字段无效"},
		{Name: PreflightReferences, Status: CheckPass},
		{Name: PreflightCapacity, Status: CheckPass},
		{Name: PreflightErrorPages, Status: CheckPass},
	}
	normalized, passed, err := normalizeChecks(checks)
	if err != nil {
		t.Fatal(err)
	}
	if passed || normalized[0].Name != PreflightCapacity || normalized[1].Name != PreflightErrorPages ||
		normalized[2].Name != PreflightNginxSafety || normalized[3].Name != PreflightReferences ||
		normalized[4].Name != PreflightSchema {
		t.Fatalf("unexpected normalized checks: %#v, passed=%v", normalized, passed)
	}
	if _, _, err := normalizeChecks([]PreflightCheck{{Name: "shell", Status: CheckFail, Code: "x"}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("arbitrary check error = %v, want ErrInvalidInput", err)
	}
	if _, _, err := normalizeChecks([]PreflightCheck{{Name: PreflightSchema, Status: CheckFail, Code: "bad;code"}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsafe check code error = %v, want ErrInvalidInput", err)
	}
	large := passingChecks()
	for index := range large {
		large[index].Detail = strings.Repeat("𐀀", 512)
	}
	if _, _, err := normalizeChecks(large); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized final checks JSON error = %v, want ErrInvalidInput", err)
	}
}

func TestRevisionAndTimestampBounds(t *testing.T) {
	service := &Service{}
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	if _, err := service.CreateDraft(context.Background(), actor,
		createDraftRequest(maxRevision, "head-overflow", validConfiguration())); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("head overflow error = %v, want ErrInvalidInput", err)
	}
	if _, err := service.RecordPreflight(context.Background(), actor, RecordPreflightRequest{
		Revision: math.MaxInt64, ExpectedStatus: StatusDraft, SnapshotSHA256: strings.Repeat("a", 64),
		Checks: passingChecks(), IdempotencyKey: "revision-overflow", RequestID: "revision-overflow",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("preflight revision overflow error = %v, want ErrInvalidInput", err)
	}
	if _, err := service.Activate(context.Background(), actor, ActivateRequest{
		Revision: math.MaxInt64, IdempotencyKey: "activate-overflow", RequestID: "activate-overflow",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("activate revision overflow error = %v, want ErrInvalidInput", err)
	}
	if _, err := service.Rollback(context.Background(), actor, RollbackRequest{
		TargetRevision: 1, ExpectedHeadRevision: maxRevision, ExpectedActiveRevision: 1,
		IdempotencyKey: "rollback-overflow", RequestID: "rollback-overflow",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("rollback head overflow error = %v, want ErrInvalidInput", err)
	}

	if _, err := checkedStoreTime(time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("lower timestamp bound error = %v, want ErrInvalidInput", err)
	}
	latest := time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	if _, err := checkedPreflightExpiry(latest); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("preflight timestamp overflow error = %v, want ErrInvalidInput", err)
	}
}

func passingChecks() []PreflightCheck {
	return []PreflightCheck{
		{Name: PreflightSchema, Status: CheckPass},
		{Name: PreflightReferences, Status: CheckPass},
		{Name: PreflightCapacity, Status: CheckPass},
		{Name: PreflightNginxSafety, Status: CheckPass},
		{Name: PreflightErrorPages, Status: CheckPass},
	}
}

func validConfiguration() Configuration {
	configuration := ProjectBootstrapConfiguration()
	configuration.ErrorPages = []ErrorPageMetadata{
		{StatusCode: 404, MIMEType: "text/html", SizeBytes: 512, SHA256: strings.Repeat("a", 64), StorageObjectKey: "errors/404.html"},
		{StatusCode: 502, MIMEType: "text/html", SizeBytes: 1024, SHA256: strings.Repeat("b", 64), StorageObjectKey: "errors/502.html"},
	}
	configuration.Secrets = SensitiveReferences{ErrorPageStorage: &SecretEnvelopeReference{
		Provider: SecretProviderVault, Reference: "vault:error-pages/prod-html", KeyID: "error-pages-key-v1",
		Algorithm: EnvelopeAES256GCM, CiphertextSHA256: strings.Repeat("d", 64),
	}}
	return configuration
}

func TestNodeMonitoringLegacyCanonicalSnapshotCompatibilityAndDefaults(t *testing.T) {
	configuration := validConfiguration()
	normalized, snapshot, hash, err := CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.NodeMonitoring != nil || bytes.Contains(snapshot, []byte(`"node_monitoring"`)) {
		t.Fatalf("legacy snapshot unexpectedly materialized node monitoring: %s", snapshot)
	}
	decoded, err := decodeCanonicalSnapshot(snapshot, hash)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.NodeMonitoring != nil {
		t.Fatalf("decoded legacy node monitoring = %#v, want nil", decoded.NodeMonitoring)
	}
	if got := effectiveNodeMonitoring(decoded.NodeMonitoring); got != (NodeMonitoringConfiguration{
		PortMode: PortModeDefault, ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000,
		FailureThreshold: 3, RecoveryThreshold: 3, RecoveryNotificationEnabled: true,
	}) {
		t.Fatalf("effective defaults = %#v", got)
	}
	_, encodedAgain, hashAgain, err := CanonicalSnapshot(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot, encodedAgain) || hash != hashAgain {
		t.Fatal("legacy canonical bytes or digest changed after round trip")
	}
}

func TestNodeMonitoringCanonicalValidation(t *testing.T) {
	port := uint16(8443)
	valid := NodeMonitoringConfiguration{
		PortMode: PortModeCustom, CustomPort: &port, ProbeIntervalMS: 10_000,
		ProbeTimeoutMS: 3_000, FailureThreshold: 3, RecoveryThreshold: 3,
		RecoveryNotificationEnabled: true,
	}
	configuration := validConfiguration()
	configuration.NodeMonitoring = &valid
	normalized, snapshot, hash, err := CanonicalSnapshot(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.NodeMonitoring == nil || normalized.NodeMonitoring.CustomPort == nil ||
		*normalized.NodeMonitoring.CustomPort != port || !bytes.Contains(snapshot, []byte(`"node_monitoring"`)) {
		t.Fatalf("explicit node monitoring was not canonicalized: %#v %s", normalized.NodeMonitoring, snapshot)
	}
	decoded, err := decodeCanonicalSnapshot(snapshot, hash)
	if err != nil || decoded.NodeMonitoring == nil || decoded.NodeMonitoring.CustomPort == nil ||
		*decoded.NodeMonitoring.CustomPort != port {
		t.Fatalf("explicit round trip = %#v, err=%v", decoded.NodeMonitoring, err)
	}

	tests := []struct {
		name   string
		mutate func(*NodeMonitoringConfiguration)
	}{
		{"unknown port mode", func(value *NodeMonitoringConfiguration) { value.PortMode = "automatic" }},
		{"default with custom port", func(value *NodeMonitoringConfiguration) { value.PortMode = PortModeDefault }},
		{"custom without port", func(value *NodeMonitoringConfiguration) { value.CustomPort = nil }},
		{"interval too low", func(value *NodeMonitoringConfiguration) { value.ProbeIntervalMS = 999 }},
		{"interval too high", func(value *NodeMonitoringConfiguration) { value.ProbeIntervalMS = 300_001 }},
		{"timeout too low", func(value *NodeMonitoringConfiguration) { value.ProbeTimeoutMS = 99 }},
		{"timeout too high", func(value *NodeMonitoringConfiguration) { value.ProbeTimeoutMS = 60_001 }},
		{"timeout exceeds interval", func(value *NodeMonitoringConfiguration) { value.ProbeIntervalMS, value.ProbeTimeoutMS = 1_000, 1_001 }},
		{"failure threshold too low", func(value *NodeMonitoringConfiguration) { value.FailureThreshold = 0 }},
		{"failure threshold too high", func(value *NodeMonitoringConfiguration) { value.FailureThreshold = 21 }},
		{"recovery threshold too low", func(value *NodeMonitoringConfiguration) { value.RecoveryThreshold = 0 }},
		{"recovery threshold too high", func(value *NodeMonitoringConfiguration) { value.RecoveryThreshold = 21 }},
		{"failure debounce too high", func(value *NodeMonitoringConfiguration) { value.FailureDebounceMS = 3_600_001 }},
		{"recovery debounce too high", func(value *NodeMonitoringConfiguration) { value.RecoveryDebounceMS = 3_600_001 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			configuration := validConfiguration()
			configuration.NodeMonitoring = &candidate
			if _, _, _, err := CanonicalSnapshot(configuration); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}
