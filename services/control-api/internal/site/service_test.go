package site

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestNormalizeOriginAcceptsLetterT(t *testing.T) {
	origin, host, err := normalizeOrigin("origin.test.example:443")
	if err != nil {
		t.Fatalf("normalizeOrigin() error = %v", err)
	}
	if origin != "origin.test.example:443" || host != "origin.test.example" {
		t.Fatalf("normalizeOrigin() = (%q, %q)", origin, host)
	}
}

func TestNormalizeOriginAndCNAMERejectWildcard(t *testing.T) {
	if _, _, err := normalizeOrigin("*.origin.example:443"); err == nil {
		t.Fatal("normalizeOrigin() accepted a wildcard host")
	}
	if _, err := normalizeDomain("*.cname.example", false); err == nil {
		t.Fatal("normalizeDomain(..., false) accepted a wildcard host")
	}
	if domain, err := normalizeDomain("*.site.example", true); err != nil || domain != "*.site.example" {
		t.Fatalf("normalizeDomain(..., true) = (%q, %v)", domain, err)
	}
}

func TestNormalizeFieldsRejectsListenerProtocolCollision(t *testing.T) {
	fields := SiteFields{
		Domain:       "listener.example",
		HTTPPorts:    []string{"80", "0443"},
		HTTPSPorts:   []string{"443"},
		Origins:      []string{"192.0.2.10"},
		HTTPSEnabled: true,
		Enabled:      true,
	}
	if err := normalizeFields(&fields); err == nil {
		t.Fatal("normalizeFields() accepted one port for both HTTP and HTTPS")
	}

	fields.HTTPPorts = []string{"80"}
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("normalizeFields() rejected distinct HTTP and HTTPS ports: %v", err)
	}
}

func TestNormalizeOriginPoolSupportsEdgeBalanceMethodsAndHosts(t *testing.T) {
	methods := []string{BalanceRoundRobin, BalanceIPHash, BalanceURLHash, BalanceLeastConn, BalanceRandom}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			pool := OriginPool{
				Origins: []Origin{
					{Host: "ORIGIN.Example.COM.", Port: 80, Weight: 100, Enabled: true},
					{Host: "2001:0DB8::1", Port: 443, Weight: 1, Enabled: false},
				},
				BalanceMethod: method, FailoverTries: 1, ConnectTimeoutMS: 50, ReadTimeoutMS: 300_000,
			}
			if err := normalizeOriginPool(&pool); err != nil {
				t.Fatalf("normalizeOriginPool() error = %v", err)
			}
			if pool.Origins[0].Host != "origin.example.com" || pool.Origins[1].Host != "2001:db8::1" {
				t.Fatalf("normalized hosts = %#v", pool.Origins)
			}
		})
	}
}

func TestNormalizeOriginPoolRejectsInvalidState(t *testing.T) {
	valid := OriginPool{
		Origins:          []Origin{{Host: "192.0.2.1", Port: 80, Weight: 1, Enabled: true}},
		BalanceMethod:    BalanceRoundRobin,
		FailoverTries:    1,
		ConnectTimeoutMS: 3000,
		ReadTimeoutMS:    30000,
	}
	tests := map[string]func(*OriginPool){
		"invalid host":       func(pool *OriginPool) { pool.Origins[0].Host = "https://origin.example" },
		"invalid port":       func(pool *OriginPool) { pool.Origins[0].Port = 0 },
		"invalid weight":     func(pool *OriginPool) { pool.Origins[0].Weight = 101 },
		"duplicate endpoint": func(pool *OriginPool) { pool.Origins = append(pool.Origins, pool.Origins[0]) },
		"all disabled":       func(pool *OriginPool) { pool.Origins[0].Enabled = false },
		"failover too high":  func(pool *OriginPool) { pool.FailoverTries = 2 },
		"connect timeout":    func(pool *OriginPool) { pool.ConnectTimeoutMS = 49 },
		"read timeout":       func(pool *OriginPool) { pool.ReadTimeoutMS = 300_001 },
		"unknown balance":    func(pool *OriginPool) { pool.BalanceMethod = "rr" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			pool := valid
			pool.Origins = append([]Origin(nil), valid.Origins...)
			mutate(&pool)
			if err := normalizeOriginPool(&pool); err == nil {
				t.Fatal("normalizeOriginPool() accepted invalid state")
			}
		})
	}
}

func TestNormalizeCreateOriginPoolDefaultsAndRequiresExactBasicProjection(t *testing.T) {
	fields := SiteFields{
		Domains: []string{"create.example"}, HTTPPorts: []string{"80"},
		Origins: []string{"ORIGIN.Example:8080", "[2001:0db8::1]:443"}, Enabled: true,
	}
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("normalizeFields() error = %v", err)
	}

	defaulted, err := normalizeCreateOriginPool(fields, nil)
	if err != nil {
		t.Fatalf("normalizeCreateOriginPool(nil) error = %v", err)
	}
	wantDefault := defaultOriginPool(fields.originItems)
	if !reflect.DeepEqual(defaulted, wantDefault) {
		t.Fatalf("default pool = %#v, want %#v", defaulted, wantDefault)
	}

	explicit := OriginPool{
		Origins: []Origin{
			{Host: "ORIGIN.Example.", Port: 8080, Weight: 75, Enabled: true},
			{Host: "2001:0DB8::1", Port: 443, Weight: 25, Enabled: true},
		},
		BalanceMethod: BalanceLeastConn, FailoverTries: 2, ConnectTimeoutMS: 500, ReadTimeoutMS: 5000,
	}
	got, err := normalizeCreateOriginPool(fields, &explicit)
	if err != nil {
		t.Fatalf("normalizeCreateOriginPool(explicit) error = %v", err)
	}
	if got.BalanceMethod != BalanceLeastConn || got.Origins[0].Host != "origin.example" || got.Origins[1].Host != "2001:db8::1" {
		t.Fatalf("normalized explicit pool = %#v", got)
	}

	mismatch := explicit
	mismatch.Origins = append([]Origin(nil), explicit.Origins...)
	mismatch.Origins[1].Port = 8443
	if _, err := normalizeCreateOriginPool(fields, &mismatch); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("projection mismatch error = %v, want ErrInvalidInput", err)
	}

	reordered := explicit
	reordered.Origins = []Origin{explicit.Origins[1], explicit.Origins[0]}
	if _, err := normalizeCreateOriginPool(fields, &reordered); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("reordered projection error = %v, want ErrInvalidInput", err)
	}
}

func TestOriginFromLegacyUsesDefaultPortAndCanonicalIPv6(t *testing.T) {
	tests := []struct {
		raw      string
		host     string
		port     int
		endpoint string
	}{
		{"192.0.2.10", "192.0.2.10", 80, "192.0.2.10"},
		{"origin.example:8080", "origin.example", 8080, "origin.example:8080"},
		{"2001:0db8::1", "2001:db8::1", 80, "2001:db8::1"},
		{"[2001:db8::2]:443", "2001:db8::2", 443, "[2001:db8::2]:443"},
	}
	for _, test := range tests {
		_, host, port, err := originFromLegacy(test.raw)
		if err != nil {
			t.Fatalf("originFromLegacy(%q) error = %v", test.raw, err)
		}
		origin := Origin{Host: host, Port: port, Weight: 1, Enabled: true}
		if host != test.host || port != test.port || originCompatibilityEndpoint(origin) != test.endpoint {
			t.Fatalf("originFromLegacy(%q) = host %q port %d endpoint %q", test.raw, host, port, originCompatibilityEndpoint(origin))
		}
	}
}

func TestOriginFromLegacyRejectsUnsafeAddresses(t *testing.T) {
	for _, raw := range []string{"0.0.0.0", "[::]:443", "224.0.0.1", "[ff02::1]:8080"} {
		t.Run(raw, func(t *testing.T) {
			if _, _, _, err := originFromLegacy(raw); err == nil {
				t.Fatalf("originFromLegacy(%q) accepted an unsafe address", raw)
			}
		})
	}
}

func TestDecodeStoredSiteDerivesOnlyMissingLegacyOriginPool(t *testing.T) {
	legacy := []byte(`{"id":"00000000-0000-0000-0000-000000000001","version":7,"domain":"old.example","origins":["192.0.2.10","[2001:db8::1]:8443"]}`)
	var decoded Site
	if err := decodeStoredSite(legacy, &decoded); err != nil {
		t.Fatalf("decodeStoredSite() error = %v", err)
	}
	if decoded.Revision != 7 || decoded.Domain != "old.example" || decoded.OriginPool.BalanceMethod != BalanceRoundRobin ||
		decoded.OriginPool.FailoverTries != 1 || decoded.OriginPool.ConnectTimeoutMS != 3000 || decoded.OriginPool.ReadTimeoutMS != 30000 {
		t.Fatalf("decoded legacy site = %#v", decoded)
	}
	if got := decoded.OriginPool.Origins; len(got) != 2 || got[0] != (Origin{Host: "192.0.2.10", Port: 80, Weight: 1, Enabled: true}) ||
		got[1] != (Origin{Host: "2001:db8::1", Port: 8443, Weight: 1, Enabled: true}) {
		t.Fatalf("derived origins = %#v", got)
	}
}

func TestDecodeStoredSiteRejectsUnsafeLegacyOriginsAndInvalidRichPool(t *testing.T) {
	for name, encoded := range map[string][]byte{
		"unsafe legacy": []byte(`{"origins":["https://origin.example/path"]}`),
		"invalid rich":  []byte(`{"origins":["origin.example"],"origin_pool":{"origins":[],"balance_method":"round_robin","failover_tries":1,"connect_timeout_ms":3000,"read_timeout_ms":30000}}`),
	} {
		t.Run(name, func(t *testing.T) {
			var decoded Site
			if err := decodeStoredSite(encoded, &decoded); err == nil {
				t.Fatal("decodeStoredSite() accepted unsafe stored response")
			}
		})
	}
}

func TestDecodeStoredSitePreservesRichOriginPool(t *testing.T) {
	want := Site{
		Origins: []string{"origin.example:8443"},
		OriginPool: OriginPool{
			Origins:          []Origin{{Host: "origin.example", Port: 8443, Weight: 25, Enabled: true}},
			BalanceMethod:    BalanceLeastConn,
			FailoverTries:    1,
			ConnectTimeoutMS: 500,
			ReadTimeoutMS:    5000,
		},
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var got Site
	if err := decodeStoredSite(encoded, &got); err != nil {
		t.Fatalf("decodeStoredSite() error = %v", err)
	}
	if got.OriginPool.BalanceMethod != BalanceLeastConn || got.OriginPool.Origins[0].Weight != 25 {
		t.Fatalf("decoded rich origin pool = %#v", got.OriginPool)
	}
}

// NF01: origin keepalive defaults to the node nginx default (on, 60s) for
// clients that do not send it; the idle timeout is bounded and can be off.
func TestNormalizeOriginPoolKeepalive(t *testing.T) {
	base := OriginPool{
		Origins:       []Origin{{Host: "192.0.2.1", Port: 80, Weight: 1, Enabled: true}},
		BalanceMethod: BalanceRoundRobin, FailoverTries: 1, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000,
	}
	pool := base
	if err := normalizeOriginPool(&pool); err != nil || !pool.KeepsDefaultOriginReuse() {
		t.Fatalf("legacy pool keepalive = %v/%d (%v), want default reuse", pool.KeepaliveEnabled, pool.KeepaliveIdleTimeoutMS, err)
	}
	if got := defaultOriginPool(base.Origins); !got.KeepsDefaultOriginReuse() {
		t.Fatalf("default pool keepalive = %v/%d", got.KeepaliveEnabled, got.KeepaliveIdleTimeoutMS)
	}
	enabled, disabled := true, false
	for _, idle := range []int{999, 300_001, -1} {
		pool := base
		pool.KeepaliveEnabled, pool.KeepaliveIdleTimeoutMS = &enabled, idle
		if err := normalizeOriginPool(&pool); err == nil {
			t.Fatalf("idle timeout %d accepted", idle)
		}
	}
	pool = base
	pool.KeepaliveEnabled, pool.KeepaliveIdleTimeoutMS = &enabled, 15000
	if err := normalizeOriginPool(&pool); err != nil || pool.KeepaliveIdleTimeoutMS != 15000 || pool.KeepsDefaultOriginReuse() {
		t.Fatalf("custom keepalive: %v", err)
	}
	pool = base
	pool.KeepaliveEnabled = &disabled
	if err := normalizeOriginPool(&pool); err != nil || *pool.KeepaliveEnabled || pool.KeepsDefaultOriginReuse() {
		t.Fatalf("keepalive off: %v", err)
	}
	var decoded OriginPool
	if err := json.Unmarshal([]byte(`{"origins":[{"host":"192.0.2.1","port":80,"weight":1,"enabled":true}],"balance_method":"round_robin","failover_tries":1,"connect_timeout_ms":3000,"read_timeout_ms":30000}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if err := normalizeOriginPool(&decoded); err != nil || !decoded.KeepsDefaultOriginReuse() {
		t.Fatalf("request without keepalive fields does not keep the default: %v", err)
	}
}

// FX07: forced HTTPS needs HTTPS; the redirect port is one of the HTTPS ports
// (0 follows the lowest one).
func TestNormalizeFieldsForceHTTPS(t *testing.T) {
	base := func() SiteFields {
		return SiteFields{Domains: []string{"secure.example"}, HTTPPorts: []string{"80"}, HTTPSPorts: []string{"8443", "443"},
			HTTPSEnabled: true, Origins: []string{"192.0.2.1"}, Enabled: true}
	}
	enabled, disabled := true, false
	port := func(value int) *int { return &value }
	fields := base()
	fields.ForceHTTPS, fields.HTTPSRedirectPort = &enabled, port(8443)
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("valid forced HTTPS rejected: %v", err)
	}
	for name, mutate := range map[string]func(*SiteFields){
		"without HTTPS":     func(f *SiteFields) { f.ForceHTTPS, f.HTTPSEnabled, f.HTTPSPorts = &enabled, false, nil },
		"port not HTTPS":    func(f *SiteFields) { f.ForceHTTPS, f.HTTPSRedirectPort = &enabled, port(80) },
		"port out of range": func(f *SiteFields) { f.ForceHTTPS, f.HTTPSRedirectPort = &enabled, port(70000) },
		"negative port":     func(f *SiteFields) { f.HTTPSRedirectPort = port(-1) },
	} {
		fields := base()
		mutate(&fields)
		if err := normalizeFields(&fields); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	fields = base()
	fields.ForceHTTPS, fields.HTTPSRedirectPort = &disabled, port(0)
	if err := normalizeFields(&fields); err != nil {
		t.Fatalf("forced HTTPS off rejected: %v", err)
	}
}

// CU-SITE-02：带回源池建站省略回源超时（0）时，用户默认优先，没有默认则
// 回落内置池的系统默认（3000/30000），不再因 0 被 normalizeOriginPool 拒成 400；
// 显式值原样保留。
func TestCreatePoolTimeoutsFallBackToUserDefaultsThenSystemDefaults(t *testing.T) {
	for _, test := range []struct {
		name                  string
		defaults              siteCreationUserDefaults
		connect, read         int
		wantConnect, wantRead int
	}{
		{"omitted without defaults", nil, 0, 0, 3000, 30000},
		{"omitted with user defaults", siteCreationUserDefaults{SiteDefaultOriginConnectTimeout: "5", SiteDefaultOriginReadTimeout: "60"}, 0, 0, 5000, 60000},
		{"explicit wins over defaults", siteCreationUserDefaults{SiteDefaultOriginConnectTimeout: "5", SiteDefaultOriginReadTimeout: "60"}, 800, 9000, 800, 9000},
		{"only connect omitted", nil, 0, 9000, 3000, 9000},
	} {
		pool := OriginPool{Origins: []Origin{{Host: "origin.example", Port: 80, Weight: 1, Enabled: true}},
			BalanceMethod: BalanceRoundRobin, FailoverTries: 1, ConnectTimeoutMS: test.connect, ReadTimeoutMS: test.read}
		applyCreatePoolDefaults(test.defaults, &pool)
		if pool.ConnectTimeoutMS != test.wantConnect || pool.ReadTimeoutMS != test.wantRead {
			t.Errorf("%s: timeouts=%d/%d, want %d/%d", test.name, pool.ConnectTimeoutMS, pool.ReadTimeoutMS, test.wantConnect, test.wantRead)
		}
		if err := normalizeOriginPool(&pool); err != nil {
			t.Errorf("%s: normalizeOriginPool error = %v", test.name, err)
		}
	}
}
