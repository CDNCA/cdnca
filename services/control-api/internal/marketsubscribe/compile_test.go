package marketsubscribe

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

func baseSite() site.Site {
	on := true
	return site.Site{
		Domains: []string{"www.example.test", "example.test"}, HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"},
		Enabled: true, HTTPSEnabled: true, TLSCipherPreset: "modern", TLSClientAuth: "off", HTTP2Enabled: true, Revision: 7,
		OriginPool: site.OriginPool{
			Origins: []site.Origin{
				{Host: "203.0.113.10", Port: 8080, Weight: 3, Enabled: true},
				{Host: "203.0.113.11", Port: 80, Weight: 1, Enabled: true, Level: 1},
				{Host: "203.0.113.12", Port: 80, Weight: 1, Enabled: false},
			},
			BalanceMethod: site.BalanceIPHash, ConnectTimeoutMS: 3000, ReadTimeoutMS: 30000, Scheme: site.OriginSchemeHTTP,
			KeepaliveEnabled: &on, KeepaliveIdleTimeoutMS: site.DefaultKeepaliveIdleTimeoutMS,
			RequestHost: site.OriginRequestHost{Mode: site.OriginRequestHostVisitor},
			TLS:         site.OriginTLS{Trust: site.OriginTrustSystem},
			WebSocket:   &site.OriginWebSocket{Enabled: false},
		},
	}
}

// E2: the config comes from the saved site (domains, ports, enabled origins
// with level and weight, scheme, balance, timeouts), not from typed JSON.
func TestCompileSiteMapsSavedSite(t *testing.T) {
	cfg, unsupported := CompileSite(baseSite())
	if len(unsupported) != 0 {
		t.Fatalf("unsupported = %v", unsupported)
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if !slices.Equal(cfg.Domains, []string{"example.test", "www.example.test"}) || !slices.Equal(cfg.HTTPPorts, []int{80}) ||
		!slices.Equal(cfg.HTTPSPorts, []int{443}) || cfg.BalanceMethod != "ip_hash" || cfg.OriginScheme != "http" ||
		cfg.ConnectTimeoutMS != 3000 || cfg.ReadTimeoutMS != 30000 || cfg.WebSocket || cfg.HTTP3 {
		t.Fatalf("config = %+v", cfg)
	}
	want := []siteconf.Origin{{Host: "203.0.113.10", Port: 8080, Weight: 3}, {Host: "203.0.113.11", Port: 80, Weight: 1, Level: 1}}
	if !slices.Equal(cfg.Origins, want) {
		t.Fatalf("origins = %+v", cfg.Origins)
	}
}

func TestCompileSiteHTTPSOffDropsHTTPSPortsAndHTTP3(t *testing.T) {
	s := baseSite()
	s.HTTPSEnabled, s.HTTP3Enabled = false, true
	cfg, _ := CompileSite(s)
	if len(cfg.HTTPSPorts) != 0 || cfg.HTTP3 {
		t.Fatalf("https off: %+v", cfg)
	}
	s.HTTPSEnabled = true
	if cfg, _ = CompileSite(s); !cfg.HTTP3 || len(cfg.HTTPSPorts) != 1 {
		t.Fatalf("https on: %+v", cfg)
	}
}

// The site's own settings are compiled into the revision instead of
// blocking it (fix-mktsiteconf); only a disabled site still blocks.
func TestCompileSiteCarriesSiteOptions(t *testing.T) {
	s := baseSite()
	off := false
	s.ForceHTTPS, s.HTTPSRedirectPort, s.HTTP3Enabled = true, 443, true
	s.TLSClientAuth, s.TLSClientCAPEM = "required", "ca-pem"
	s.OriginPool.BalanceMethod = site.BalanceSticky
	s.OriginPool.Sticky = &site.OriginSticky{Source: site.OriginStickyCookie, Name: "uid"}
	s.OriginPool.RequestHost = site.OriginRequestHost{Mode: site.OriginRequestHostCustom, Value: "origin.example.test"}
	s.OriginPool.Scheme, s.OriginPool.HTTPSPort = site.OriginSchemeHTTPS, 8443
	s.OriginPool.TLS = site.OriginTLS{SNI: "origin.example.test", Trust: site.OriginTrustCustom, CAPEM: "origin-ca"}
	s.OriginPool.SearchEngineOrigin = "203.0.113.20"
	s.OriginPool.WebSocket = &site.OriginWebSocket{Enabled: true, AllowedOrigins: []string{"https://example.test"}}
	s.OriginPool.FollowRedirect = &site.OriginFollowRedirect{Enabled: true, MaxHops: 2}
	s.OriginPool.TrustedProxyCIDRs = []string{"192.0.2.0/24"}
	s.OriginPool.ResponseBuffering, s.OriginPool.KeepaliveEnabled = &off, &off
	s.OriginPool.FailbackMode, s.OriginPool.HealthCheckPath = site.FailbackManual, "/healthz"
	s.OriginPool.Origins[0].MaxConns = 10
	cfg, unsupported := CompileSite(s)
	if len(unsupported) != 0 {
		t.Fatalf("unsupported = %v", unsupported)
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	f := cfg.Forwarding
	if !cfg.ForceHTTPS || cfg.HTTPSRedirectPort != 443 || !cfg.HTTP3 || !cfg.WebSocket || cfg.BalanceMethod != "sticky" ||
		cfg.OriginScheme != "https" || cfg.ClientAuth == nil || cfg.ClientAuth.Mode != "required" || cfg.ClientAuth.CAPEM != "ca-pem" ||
		cfg.Origins[0].MaxConns != 10 || f == nil || f.Sticky == nil || f.Sticky.Name != "uid" || f.RequestHost != "custom" ||
		f.RequestHostValue != "origin.example.test" || f.HTTPSPort != 8443 || f.TLSSNI != "origin.example.test" ||
		f.TLSCAPEM != "origin-ca" || f.SearchEngineOrigin != "203.0.113.20" || !slices.Equal(f.WebSocketOrigins, []string{"https://example.test"}) ||
		f.FollowRedirect == nil || f.FollowRedirect.MaxHops != 2 || !slices.Equal(f.TrustedProxyCIDRs, []string{"192.0.2.0/24"}) ||
		f.ResponseBuffering == nil || *f.ResponseBuffering || !f.KeepaliveDisabled || !f.FailbackManual || f.HealthCheckPath != "/healthz" {
		t.Fatalf("config = %+v forwarding = %+v", cfg, f)
	}
}

// Defaults compile to no forwarding block, so a default site's revision
// does not change digest because of the new fields.
func TestCompileSiteDefaultsHaveNoForwarding(t *testing.T) {
	cfg, _ := CompileSite(baseSite())
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.Forwarding != nil || cfg.ClientAuth != nil || cfg.ForceHTTPS {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestCompileSiteDisabledStillBlocks(t *testing.T) {
	s := baseSite()
	s.Enabled = false
	_, unsupported := CompileSite(s)
	if len(unsupported) != 1 || unsupported[0].Code != "site_disabled" {
		t.Fatalf("unsupported = %v", unsupported)
	}
}

func TestCompileSiteWebSocketDefaultOn(t *testing.T) {
	s := baseSite()
	s.OriginPool.WebSocket = nil
	if cfg, _ := CompileSite(s); !cfg.WebSocket {
		t.Fatal("absent websocket setting means on (site default)")
	}
}
