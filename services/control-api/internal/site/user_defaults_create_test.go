package site

import (
	"slices"
	"strings"
	"testing"
)

// fp-site SITE-CURRENT-01: a create that leaves the listen ports out takes
// the owner's defaults, and an enabled HTTPS without ports takes the HTTPS
// default (443 without one); ports the request names win.
func TestCreationUserDefaultsFillOmittedPorts(t *testing.T) {
	defaults := siteCreationUserDefaults{SiteDefaultHTTPListenPort: "8080 8081", SiteDefaultHTTPSListenPort: "8443"}
	for _, tc := range []struct {
		name     string
		fields   SiteFields
		http     []string
		https    []string
		defaults siteCreationUserDefaults
	}{
		{"omitted", SiteFields{HTTPSEnabled: true}, []string{"8080", "8081"}, []string{"8443"}, defaults},
		{"empty lists", SiteFields{HTTPPorts: []string{}, HTTPSPorts: []string{}, HTTPSEnabled: true}, []string{"8080", "8081"}, []string{"8443"}, defaults},
		{"explicit wins", SiteFields{HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"}, HTTPSEnabled: true}, []string{"80"}, []string{"443"}, defaults},
		{"https off keeps none", SiteFields{}, []string{"8080", "8081"}, nil, defaults},
		{"no defaults", SiteFields{HTTPSEnabled: true}, nil, []string{"443"}, siteCreationUserDefaults{}},
	} {
		fields := tc.fields
		tc.defaults.applyFields(&fields)
		if !slices.Equal(fields.HTTPPorts, tc.http) || !slices.Equal(fields.HTTPSPorts, tc.https) {
			t.Errorf("%s: ports %v / %v, want %v / %v", tc.name, fields.HTTPPorts, fields.HTTPSPorts, tc.http, tc.https)
		}
	}
}

// A requested pool without a load balancing takes the owner's default; with
// none it is marked to follow the platform default (store.Create).
func TestCreateRequestedPoolWithoutBalanceFollowsDefaults(t *testing.T) {
	pool := OriginPool{}
	if !(siteCreationUserDefaults{SiteDefaultBalanceWay: BalanceIPHash}).applyPool(&pool, false) || pool.BalanceMethod != BalanceIPHash {
		t.Fatalf("owner default balance = %q", pool.BalanceMethod)
	}
	pool = OriginPool{BalanceMethod: BalanceLeastConn}
	if (siteCreationUserDefaults{SiteDefaultBalanceWay: BalanceIPHash}).applyPool(&pool, false) || pool.BalanceMethod != BalanceLeastConn {
		t.Fatalf("explicit balance overwritten: %q", pool.BalanceMethod)
	}
}

// fp-site3（36 项第二批）：TLS 协议/套件、回源协议/端口/超时默认只填请求没写的字段；
// 端口默认只用于该回源协议实际使用的端口（http 回源时 HTTPS 端口须是 443，否则建站被拒）。
func TestCreationUserDefaultsSimpleFields(t *testing.T) {
	defaults := siteCreationUserDefaults{
		SiteDefaultSSLProtocols: "TLSv1.2 TLSv1.3", SiteDefaultSSLCipherPreset: "compatible",
		SiteDefaultOriginProtocol: OriginSchemeHTTPS, SiteDefaultBackendHTTPPort: "8080", SiteDefaultBackendHTTPSPort: "8443",
		SiteDefaultOriginConnectTimeout: "5", SiteDefaultOriginReadTimeout: "60",
	}
	fields := SiteFields{}
	defaults.applyFields(&fields)
	if !slices.Equal(fields.TLSProtocols, []string{"TLSv1.2", "TLSv1.3"}) || fields.TLSCipherPreset == nil || *fields.TLSCipherPreset != "compatible" {
		t.Fatalf("tls defaults: %v %v", fields.TLSProtocols, fields.TLSCipherPreset)
	}
	modern := "modern"
	explicit := SiteFields{TLSProtocols: []string{"TLSv1.3"}, TLSCipherPreset: &modern}
	defaults.applyFields(&explicit)
	if !slices.Equal(explicit.TLSProtocols, []string{"TLSv1.3"}) || *explicit.TLSCipherPreset != "modern" {
		t.Fatalf("explicit tls overwritten: %v %v", explicit.TLSProtocols, *explicit.TLSCipherPreset)
	}

	pool := defaultOriginPool(nil)
	defaults.applyPool(&pool, true)
	if pool.Scheme != OriginSchemeHTTPS || pool.HTTPSPort != 8443 || pool.HTTPPort != 80 ||
		pool.ConnectTimeoutMS != 5000 || pool.ReadTimeoutMS != 60000 {
		t.Fatalf("https pool: %+v", pool)
	}
	// http 回源：HTTPS 端口默认不套用（原 backend_https_port 在此会让建站校验失败）
	httpOnly := siteCreationUserDefaults{SiteDefaultBackendHTTPSPort: "8443", SiteDefaultBackendHTTPPort: "8080"}
	pool = defaultOriginPool(nil)
	httpOnly.applyPool(&pool, true)
	if pool.Scheme != OriginSchemeHTTP || pool.HTTPSPort != 443 || pool.HTTPPort != 8080 {
		t.Fatalf("http pool: %+v", pool)
	}
	requested := OriginPool{ConnectTimeoutMS: 2000}
	defaults.applyPool(&requested, false)
	if requested.ConnectTimeoutMS != 2000 || requested.ReadTimeoutMS != 60000 || requested.Scheme != OriginSchemeHTTPS {
		t.Fatalf("requested pool: %+v", requested)
	}
}

func TestSiteDefaultSimpleFieldValues(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
		ok                bool
	}{
		{SiteDefaultSSLProtocols, "TLSv1.2  TLSv1.3", "TLSv1.2 TLSv1.3", true},
		{SiteDefaultSSLProtocols, "SSLv3", "", false},
		{SiteDefaultSSLProtocols, "TLSv1 TLSv1.3", "", false},
		{SiteDefaultSSLCipherPreset, "legacy", "legacy", true},
		{SiteDefaultSSLCipherPreset, "ECDHE-RSA-AES128-GCM-SHA256", "", false},
		{SiteDefaultOriginProtocol, "follow", "follow", true},
		{SiteDefaultOriginProtocol, "ftp", "", false},
		{SiteDefaultBackendHTTPPort, "8080", "8080", true},
		{SiteDefaultBackendHTTPPort, "0", "", false},
		{SiteDefaultOriginConnectTimeout, "31", "", false},
		{SiteDefaultOriginReadTimeout, "300", "300", true},
	} {
		got, ok := normalizeSiteDefaultValue(tc.name, tc.value)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%s=%q: %q %v", tc.name, tc.value, got, ok)
		}
	}
}

// fp-site4（36 项第三批）：IPv6 只填建站请求未写的；Gzip 交给建站事务；
// DNS API 默认只在请求未选账号且创建者可写解析时带入。
func TestCreationUserDefaultsThirdBatch(t *testing.T) {
	defaults := siteCreationUserDefaults{SiteDefaultIPv6: "1", SiteDefaultGzip: "0",
		SiteDefaultDNSProvider: "0190b1d6-3c8e-7a51-9f00-000000000001"}
	omitted := SiteFields{IPv6Omitted: true}
	defaults.applyFields(&omitted)
	if !omitted.IPv6Enabled || omitted.gzipDefault == nil || *omitted.gzipDefault {
		t.Fatalf("omitted: ipv6 %v gzip %v", omitted.IPv6Enabled, omitted.gzipDefault)
	}
	explicit := SiteFields{}
	defaults.applyFields(&explicit)
	if explicit.IPv6Enabled {
		t.Fatal("explicit ipv6_enabled=false overwritten")
	}

	request := CreateRequest{DefaultDNSAllowed: true}
	defaults.applyDNSProvider(&request)
	if request.DNSProviderID == nil || request.DNSProviderID.String() != defaults[SiteDefaultDNSProvider] || !request.dnsProviderDefaulted {
		t.Fatalf("default dns provider: %v %v", request.DNSProviderID, request.dnsProviderDefaulted)
	}
	denied := CreateRequest{}
	defaults.applyDNSProvider(&denied)
	if denied.DNSProviderID != nil {
		t.Fatal("dns default applied without dns.manage")
	}
	named := request.DNSProviderID
	chosen := CreateRequest{DefaultDNSAllowed: true, DNSProviderID: named}
	other := siteCreationUserDefaults{SiteDefaultDNSProvider: "0190b1d6-3c8e-7a51-9f00-000000000002"}
	other.applyDNSProvider(&chosen)
	if chosen.DNSProviderID != named || chosen.dnsProviderDefaulted {
		t.Fatal("requested dns provider overwritten")
	}
}

func TestSiteDefaultThirdBatchValues(t *testing.T) {
	for _, tc := range []struct {
		name, value, want string
		ok                bool
	}{
		{SiteDefaultCCBanSeconds, "3600", "3600", true},
		{SiteDefaultCCBanSeconds, "0", "", false},
		{SiteDefaultCCBanSeconds, "86401", "", false},
		{SiteDefaultCCPassSeconds, "59", "", false},
		{SiteDefaultCCPassSeconds, "604800", "604800", true},
		{SiteDefaultGzip, "1", "1", true},
		{SiteDefaultIPv6, "yes", "", false},
		{SiteDefaultDNSProvider, "0190B1D6-3C8E-7A51-9F00-000000000001", "0190b1d6-3c8e-7a51-9f00-000000000001", true},
		{SiteDefaultDNSProvider, "00000000-0000-0000-0000-000000000000", "", false},
		{SiteDefaultDNSProvider, "aliyun", "", false},
	} {
		got, ok := normalizeSiteDefaultValue(tc.name, tc.value)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%s=%q: %q %v", tc.name, tc.value, got, ok)
		}
	}
	if got := canonicalGzipTypes([]string{"text/plain", "Application/JSON", "text/plain"}); !slices.Equal(got, []string{"application/json", "text/plain"}) {
		t.Fatalf("gzip types %v", got)
	}
}

// fp-site4：recv_real_time「数据实时返回」= 不缓冲响应，send_real_time「数据实时发送」= 不缓冲请求体，
// 与站点编辑页 SiteEdgeOptionsSection 一致（原映射相反）。
func TestRealTimeDefaultsMapLikeTheCompetitor(t *testing.T) {
	pool := OriginPool{}
	siteCreationUserDefaults{SiteDefaultRecvRealTime: "1", SiteDefaultSendRealTime: "0"}.applyPool(&pool, false)
	if pool.ResponseBuffering == nil || *pool.ResponseBuffering || pool.RequestBuffering == nil || !*pool.RequestBuffering {
		t.Fatalf("response %v request %v", pool.ResponseBuffering, pool.RequestBuffering)
	}
}

// tls-custom #11: ssl_cipher_suites keeps whitelisted names only (stored
// colon separated), and a custom preset default applies only together with
// a suites default; a request's own preset wins.
func TestSiteDefaultCustomCipherSuites(t *testing.T) {
	if value, ok := normalizeSiteDefaultValue(SiteDefaultSSLCipherSuites, " ECDHE-RSA-AES128-GCM-SHA256, ECDHE-ECDSA-CHACHA20-POLY1305 "); !ok ||
		value != "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305" {
		t.Fatalf("suites default = %q %v", value, ok)
	}
	for _, bad := range []string{"", "RC4-SHA", "ECDHE-RSA-AES128-GCM-SHA256:ALL", "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA"} {
		if _, ok := normalizeSiteDefaultValue(SiteDefaultSSLCipherSuites, bad); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, ok := normalizeSiteDefaultValue(SiteDefaultSSLCipherPreset, "custom"); !ok {
		t.Fatal("custom preset default refused")
	}
	if !slices.Contains(siteDefaultNames, SiteDefaultSSLCipherSuites) {
		t.Fatal("ssl_cipher_suites not listed")
	}
	suites := "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305"
	fields := SiteFields{}
	siteCreationUserDefaults{SiteDefaultSSLCipherPreset: "custom", SiteDefaultSSLCipherSuites: suites}.applyFields(&fields)
	if fields.TLSCipherPreset == nil || *fields.TLSCipherPreset != "custom" || strings.Join(fields.TLSCipherSuites, ":") != suites {
		t.Fatalf("custom default: %v %v", fields.TLSCipherPreset, fields.TLSCipherSuites)
	}
	fields = SiteFields{}
	siteCreationUserDefaults{SiteDefaultSSLCipherPreset: "custom"}.applyFields(&fields)
	if fields.TLSCipherPreset != nil || fields.TLSCipherSuites != nil {
		t.Fatal("custom default without suites applied")
	}
	compatible := "compatible"
	fields = SiteFields{TLSCipherPreset: &compatible}
	siteCreationUserDefaults{SiteDefaultSSLCipherPreset: "custom", SiteDefaultSSLCipherSuites: suites}.applyFields(&fields)
	if *fields.TLSCipherPreset != "compatible" || fields.TLSCipherSuites != nil {
		t.Fatal("request preset lost to the default")
	}
}
