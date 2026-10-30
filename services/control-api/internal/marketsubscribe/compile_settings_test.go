package marketsubscribe

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// fix-mktsiteconf2 ①: the HTTPS profile, IPv6, cache switches and L2 mode are
// compiled from the saved site and survive Normalize.
func TestCompileSiteCarriesSiteSettings(t *testing.T) {
	on := true
	s := baseSite()
	s.TLSProtocols = []string{"TLSv1", "TLSv1.1", "TLSv1.2"}
	s.TLSCipherPreset, s.TLSCipherSuites = "custom", []string{"ECDHE-RSA-AES128-GCM-SHA256"}
	s.TLSOCSPStapling, s.TLSPreferServerCiphers, s.HTTP2Enabled = true, &on, false
	s.ListenerState.IPv6DesiredEnabled, s.CacheSharedAcrossDomains, s.CacheStatusHeader = true, true, false
	s.OriginPool.L2Mode = site.SiteL2Off
	cfg, unsupported := CompileSite(s)
	if len(unsupported) != 0 {
		t.Fatalf("unsupported = %v", unsupported)
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	tls := cfg.TLS
	if tls == nil || !slices.Equal(tls.Protocols, s.TLSProtocols) || tls.CipherPreset != "custom" ||
		!slices.Equal(tls.CipherSuites, s.TLSCipherSuites) || !tls.OCSPStapling || tls.PreferServerCiphers == nil || !tls.HTTP2Off {
		t.Fatalf("tls = %+v", tls)
	}
	if !cfg.IPv6 || !cfg.CacheSharedAcrossDomains || !cfg.CacheStatusHeaderOff || cfg.Forwarding == nil || !cfg.Forwarding.L2Off {
		t.Fatalf("config = %+v forwarding %+v", cfg, cfg.Forwarding)
	}
}

func TestCompileSiteDefaultSettingsAreAbsent(t *testing.T) {
	s := baseSite()
	s.TLSProtocols, s.CacheStatusHeader = []string{"TLSv1.2", "TLSv1.3"}, true
	cfg, _ := CompileSite(s)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	if cfg.TLS != nil || cfg.IPv6 || cfg.CacheStatusHeaderOff || cfg.Forwarding != nil {
		t.Fatalf("defaults carried: tls=%+v forwarding=%+v", cfg.TLS, cfg.Forwarding)
	}
}

// A custom L2 configuration names the subscriber's own L2 nodes.
func TestCompileSiteCustomL2Blocks(t *testing.T) {
	s := baseSite()
	s.OriginPool.L2Mode = site.SiteL2Custom
	if _, unsupported := CompileSite(s); !slices.Equal(unsupported, []Unsupported{{Code: "site_l2_custom"}}) {
		t.Fatalf("unsupported = %v", unsupported)
	}
}

// Basic auth is carried as the stored salted hashes (site independent), so
// the leaf checks the same passwords; it no longer blocks.
func TestSiteAccessBlockCarriesBasicAuthHashes(t *testing.T) {
	alice := edgeconfig.BasicAuthUserWithSalt("alice", strings.Repeat("ab", 16), "correct horse")
	access := edgeconfig.SiteAccess{BasicAuth: &edgeconfig.SiteBasicAuth{Realm: "staff",
		Users: []edgeconfig.BasicAuthUser{alice}, ExcludePathPrefixes: []string{"/public/"}}}
	raw, err := siteAccessBlock(access, 301, nil)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		BasicAuth edgeconfig.SiteBasicAuth `json:"basic_auth"`
	}
	if err := json.Unmarshal(raw, &back); err != nil || back.BasicAuth.Realm != "staff" || len(back.BasicAuth.Users) != 1 ||
		back.BasicAuth.Users[0] != alice || back.BasicAuth.ExcludePathPrefixes[0] != "/public/" || strings.Contains(string(raw), "password") {
		t.Fatalf("block = %s (%v)", raw, err)
	}
}
