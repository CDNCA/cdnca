package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// fp-site5a: http2_enabled / http3_enabled omitted keep the stored value;
// tls_prefer_server_ciphers omitted keeps it, null is "by preset" again.
func TestSiteBasicHTTPSProtocolsPayload(t *testing.T) {
	decode := func(raw string) site.SiteFields {
		t.Helper()
		payload := siteBasicPayload{}
		if err := json.Unmarshal([]byte(`{"domains":["h2.example"],"http_enabled":true,"ipv6_enabled":false`+raw+`}`), &payload); err != nil {
			t.Fatal(err)
		}
		fields, err := fieldsFromBasic(payload)
		if err != nil {
			t.Fatal(err)
		}
		return fields
	}
	omitted := decode("")
	if omitted.HTTP2Enabled != nil || omitted.HTTP3Enabled != nil || omitted.TLSPreferServerCiphers != nil || omitted.TLSPreferServerCiphersReset {
		t.Fatalf("omitted: %+v", omitted)
	}
	set := decode(`,"http2_enabled":false,"http3_enabled":false,"tls_prefer_server_ciphers":true`)
	if set.HTTP2Enabled == nil || *set.HTTP2Enabled || set.HTTP3Enabled == nil || *set.HTTP3Enabled ||
		set.TLSPreferServerCiphers == nil || !*set.TLSPreferServerCiphers || set.TLSPreferServerCiphersReset {
		t.Fatalf("set: %+v", set)
	}
	if reset := decode(`,"tls_prefer_server_ciphers":null`); reset.TLSPreferServerCiphers != nil || !reset.TLSPreferServerCiphersReset {
		t.Fatalf("null: %+v", reset)
	}

	encoded, err := json.Marshal(siteDetail(site.Site{HTTP2Enabled: false, HTTP3Enabled: true}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"http2_enabled":false`, `"http3_enabled":true`, `"tls_prefer_server_ciphers":null`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("response lacks %s: %s", want, encoded)
		}
	}
}
