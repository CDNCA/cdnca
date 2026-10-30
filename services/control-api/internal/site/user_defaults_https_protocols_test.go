package site

import (
	"errors"
	"testing"
)

// fp-site5a: the defaults http2 / http3 / ssl_prefer_server_ciphers fill a
// create that leaves the site fields out; fields the request names win.
func TestCreationUserDefaultsHTTPSProtocols(t *testing.T) {
	on, off := true, false
	defaults := siteCreationUserDefaults{SiteDefaultHTTP2: "0", SiteDefaultHTTP3: "0", SiteDefaultSSLPreferServerCiph: "1"}
	fields := SiteFields{}
	defaults.applyFields(&fields)
	if fields.HTTP2Enabled == nil || *fields.HTTP2Enabled || fields.HTTP3Enabled == nil || *fields.HTTP3Enabled ||
		fields.TLSPreferServerCiphers == nil || !*fields.TLSPreferServerCiphers {
		t.Fatalf("defaults not applied: %+v %+v %+v", fields.HTTP2Enabled, fields.HTTP3Enabled, fields.TLSPreferServerCiphers)
	}
	explicit := SiteFields{HTTP2Enabled: &on, HTTP3Enabled: &on, TLSPreferServerCiphers: &off}
	defaults.applyFields(&explicit)
	if !*explicit.HTTP2Enabled || !*explicit.HTTP3Enabled || *explicit.TLSPreferServerCiphers {
		t.Fatal("request values overwritten by defaults")
	}
	reset := SiteFields{TLSPreferServerCiphersReset: true}
	defaults.applyFields(&reset)
	if reset.TLSPreferServerCiphers != nil {
		t.Fatal("an explicit by-preset request took the default")
	}
	none := SiteFields{}
	siteCreationUserDefaults{}.applyFields(&none)
	if none.HTTP2Enabled != nil || none.HTTP3Enabled != nil || none.TLSPreferServerCiphers != nil {
		t.Fatal("no defaults must leave the fields to the store (on, on, by preset)")
	}
	for _, name := range []string{SiteDefaultHTTP2, SiteDefaultHTTP3, SiteDefaultSSLPreferServerCiph} {
		for value, valid := range map[string]bool{"1": true, "0": true, "on": false, "": false, "2": false} {
			if _, ok := normalizeSiteDefaultValue(name, value); ok != valid {
				t.Errorf("%s=%q valid=%v, want %v", name, value, ok, valid)
			}
		}
	}
}

func TestNormalizeTLSProfilePreferReset(t *testing.T) {
	on := true
	if err := normalizeTLSProfile(&SiteFields{TLSPreferServerCiphers: &on}); err != nil {
		t.Fatal(err)
	}
	if err := normalizeTLSProfile(&SiteFields{TLSPreferServerCiphersReset: true}); err != nil {
		t.Fatal(err)
	}
	if err := normalizeTLSProfile(&SiteFields{TLSPreferServerCiphers: &on, TLSPreferServerCiphersReset: true}); !errors.Is(err, ErrTLSProfileInvalid) {
		t.Fatalf("value with reset: %v", err)
	}
}
