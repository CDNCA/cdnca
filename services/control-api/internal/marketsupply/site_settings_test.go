package marketsupply

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/cdnca/cdnca/services/control-api/internal/siteaccess"
)

func settingsConfig() siteconf.Config {
	return siteconf.Config{Schema: siteconf.SchemaV1, Domains: []string{"a.example.test"}, HTTPPorts: []int{80},
		HTTPSPorts: []int{443}, Origins: []siteconf.Origin{{Host: "203.0.113.9", Port: 80}}}
}

// fix-mktsiteconf2 ①: the leaf writes the HTTPS profile, IPv6, the cache
// switches and the L2 mode onto its site.
func TestSiteFieldsCarrySiteSettings(t *testing.T) {
	off := false
	cfg := settingsConfig()
	cfg.TLS = &siteconf.TLSOptions{Protocols: []string{"TLSv1.2"}, CipherPreset: "custom",
		CipherSuites: []string{"ECDHE-RSA-AES128-GCM-SHA256"}, OCSPStapling: true, PreferServerCiphers: &off, HTTP2Off: true}
	cfg.IPv6, cfg.CacheSharedAcrossDomains, cfg.CacheStatusHeaderOff = true, true, true
	cfg.Forwarding = &siteconf.Forwarding{L2Off: true}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	fields, pool := siteFields(cfg, true)
	if !slices.Equal(fields.TLSProtocols, []string{"TLSv1.2"}) || *fields.TLSCipherPreset != "custom" ||
		!slices.Equal(fields.TLSCipherSuites, cfg.TLS.CipherSuites) || !*fields.TLSOCSPStapling || *fields.HTTP2Enabled ||
		fields.TLSPreferServerCiphers == nil || *fields.TLSPreferServerCiphers || fields.TLSPreferServerCiphersReset {
		t.Fatalf("tls fields = %+v", fields)
	}
	if !fields.IPv6Enabled || !*fields.CacheSharedAcrossDomains || *fields.CacheStatusHeader || pool.L2Mode != site.SiteL2Off {
		t.Fatalf("fields = %+v l2 = %q", fields, pool.L2Mode)
	}
}

// Absent settings write the site defaults (not "keep"), so a revision that
// turns a setting back off reaches the leaf.
func TestSiteFieldsWriteDefaultSettings(t *testing.T) {
	cfg := settingsConfig()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	fields, pool := siteFields(cfg, true)
	if !slices.Equal(fields.TLSProtocols, edgeconfig.BaselineTLSProtocols()) || *fields.TLSCipherPreset != edgeconfig.TLSCipherModern ||
		fields.TLSCipherSuites != nil || *fields.TLSOCSPStapling || !*fields.HTTP2Enabled || !fields.TLSPreferServerCiphersReset ||
		fields.IPv6Enabled || *fields.CacheSharedAcrossDomains || !*fields.CacheStatusHeader || pool.L2Mode != site.SiteL2Package {
		t.Fatalf("fields = %+v l2 = %q", fields, pool.L2Mode)
	}
}

func TestSiteAccessSettingsDecode(t *testing.T) {
	cfg := settingsConfig()
	cfg.SiteAccess = json.RawMessage(`{"hsts":{"max_age_seconds":600},"force_https":{"status":308,"exclude_hosts":["a.example.test"]}}`)
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	settings, _, err := siteAccessWrite(cfg)
	if err != nil || settings.HSTS == nil || settings.HSTS.MaxAgeSeconds != 600 || settings.ForceHTTPS.Status != 308 {
		t.Fatalf("settings = %+v %v", settings, err)
	}
	service := &Service{}
	if blockers := service.siteAccessBlockers(cfg); len(blockers) != 1 || blockers[0].Code != "unsupported_site_access" {
		t.Fatalf("leaf without site access: %v", blockers)
	}
	for _, raw := range []string{`{"basic_auth":{"realm":"x","users":[]}}`, `{"unknown":1}`,
		`{"basic_auth":{"realm":"x","users":[{"username":"a","password":"plaintext1"}]}}`,
		`{"basic_auth":{"realm":"x","users":[{"username":"a","salt":"00","sha256":"00"}]}}`} {
		cfg.SiteAccess = json.RawMessage(raw)
		if blockers := service.siteAccessBlockers(cfg); len(blockers) == 0 || blockers[0].Code != "site_access_invalid" {
			t.Fatalf("%s: %v", raw, blockers)
		}
	}
}

// Basic auth travels as the subscriber's salted hashes: the leaf lists the
// users without passwords and writes the hashes as they are.
func TestSiteAccessBasicAuthHashes(t *testing.T) {
	alice := edgeconfig.BasicAuthUserWithSalt("alice", strings.Repeat("ef", 16), "correct horse")
	raw, _ := json.Marshal(map[string]any{"basic_auth": map[string]any{"realm": "staff",
		"users": []edgeconfig.BasicAuthUser{alice}, "exclude_path_prefixes": []string{"/public/"}}})
	cfg := settingsConfig()
	cfg.SiteAccess = raw
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	settings, hashed, err := siteAccessWrite(cfg)
	if err != nil || settings.BasicAuth == nil || settings.BasicAuth.Realm != "staff" ||
		len(settings.BasicAuth.Users) != 1 || settings.BasicAuth.Users[0] != (siteaccess.BasicAuthUser{Username: "alice"}) ||
		len(hashed) != 1 || hashed[0] != alice || settings.BasicAuth.ExcludePathPrefixes[0] != "/public/" {
		t.Fatalf("settings = %+v hashed = %+v err = %v", settings.BasicAuth, hashed, err)
	}
	if blockers := (&Service{access: noAccess{}}).siteAccessBlockers(cfg); len(blockers) != 0 {
		t.Fatalf("blockers = %v", blockers)
	}
	// the same hashes stored are the same settings; another salt is not
	stored := siteaccess.State{Settings: settings, BasicAuthUsers: []edgeconfig.BasicAuthUser{alice}}
	if !sameSiteAccessState(stored, settings, hashed) {
		t.Fatal("same hashes differ")
	}
	stored.BasicAuthUsers = []edgeconfig.BasicAuthUser{edgeconfig.BasicAuthUserWithSalt("alice", strings.Repeat("01", 16), "correct horse")}
	if sameSiteAccessState(stored, settings, hashed) {
		t.Fatal("new hash missed")
	}
}

type noAccess struct{ SiteAccessSettings }

func TestSameSiteAccessIgnoresEmptyForms(t *testing.T) {
	stored := siteaccess.Settings{HostRedirects: []edgeconfig.HostRedirect{}, ResponseRules: []edgeconfig.SiteResponseRule{},
		ForceHTTPS: siteaccess.ForceHTTPS{Status: 301, ExcludeHosts: []string{}}}
	if !sameSiteAccess(stored, siteaccess.Settings{}) {
		t.Fatal("empty forms differ")
	}
	if sameSiteAccess(stored, siteaccess.Settings{HSTS: &edgeconfig.SiteHSTS{MaxAgeSeconds: 60}}) {
		t.Fatal("HSTS change missed")
	}
}
