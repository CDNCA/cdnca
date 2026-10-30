package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"gopkg.in/yaml.v3"
)

func TestSiteBasicTLSProtocolsPayloadAndResponse(t *testing.T) {
	canonical := site.CanonicalTLSProtocols()
	for _, test := range []struct {
		name      string
		encoded   string
		protocols []string
	}{
		{name: "omitted", encoded: `{}`},
		{name: "canonical", encoded: `{"tls_protocols":["TLSv1.2","TLSv1.3"]}`,
			protocols: canonical},
	} {
		t.Run(test.name, func(t *testing.T) {
			var payload siteBasicPayload
			if err := decodeSiteJSON([]byte(test.encoded), &payload); err != nil {
				t.Fatalf("decodeSiteJSON() error = %v", err)
			}
			fields, err := fieldsFromBasic(siteBasicPayload{
				Domains: []string{"tls.example"}, HTTPEnabled: true, TLSProtocols: payload.TLSProtocols,
			})
			if err != nil {
				t.Fatalf("fieldsFromBasic() error = %v", err)
			}
			if !slices.Equal(fields.TLSProtocols, test.protocols) {
				t.Fatalf("fields TLSProtocols = %#v, want %#v", fields.TLSProtocols, test.protocols)
			}
		})
	}

	for _, protocols := range [][]string{
		{"SSLv2", site.TLSProtocol12, site.TLSProtocol13},
		{"SSLv3", site.TLSProtocol12, site.TLSProtocol13},
		{"TLSv1", site.TLSProtocol12, site.TLSProtocol13},
		{"TLSv1.1", site.TLSProtocol12, site.TLSProtocol13},
		canonical,
	} {
		response := siteDetail(site.Site{TLSProtocols: protocols})
		if !slices.Equal([]string(response.Basic.TLSProtocols), protocols) {
			t.Fatalf("response TLSProtocols = %#v, want durable fact %#v", response.Basic.TLSProtocols, protocols)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if !json.Valid(encoded) {
			t.Fatalf("site response is not valid JSON: %s", encoded)
		}
	}
}

func TestSiteBasicTLSProtocolsRejectsNull(t *testing.T) {
	var payload siteBasicPayload
	if err := decodeSiteJSON([]byte(`{"tls_protocols":null}`), &payload); !errors.Is(err, site.ErrTLSProtocolsInvalid) {
		t.Fatalf("decodeSiteJSON() error = %v, want ErrTLSProtocolsInvalid", err)
	}
}

func TestCreateSiteOriginPoolPayloadUsesStrictJSON(t *testing.T) {
	encoded := []byte(`{
		"basic":{"domains":["create.example"],"http_enabled":true,"http_listen_ports":["80"],"https_listen_ports":[],"origins":["origin.example:8080"],"cname":"","https_enabled":false,"enabled":true,"status":"active","is_default":false},
		"origin_pool":{"origins":[{"host":"origin.example","port":8080,"weight":75,"enabled":true}],"balance_method":"url_hash","failover_tries":1,"connect_timeout_ms":500,"read_timeout_ms":5000}
	}`)
	var request createSiteRequest
	if err := decodeSiteJSON(encoded, &request); err != nil {
		t.Fatalf("decodeSiteJSON() error = %v", err)
	}
	if request.OriginPool == nil || request.OriginPool.BalanceMethod != site.BalanceURLHash || request.OriginPool.Origins[0].Weight != 75 {
		t.Fatalf("decoded origin pool = %#v", request.OriginPool)
	}

	unknown := bytes.Replace(encoded, []byte(`"read_timeout_ms":5000`), []byte(`"read_timeout_ms":5000,"unknown":true`), 1)
	if err := decodeSiteJSON(unknown, &request); err == nil {
		t.Fatal("decodeSiteJSON() accepted an unknown origin_pool field")
	}
}

// PJ-C02：sync_status 只由服务端派生（497），建站/改站请求体带它（任何值）都拒绝，
// 不再"缺省 synced 入库"。
func TestSiteBasicPayloadRefusesClientSyncStatus(t *testing.T) {
	for _, value := range []string{`"synced"`, `"failed"`, `null`} {
		var payload siteBasicPayload
		if err := decodeSiteJSON([]byte(`{"domains":["a.example"],"sync_status":`+value+`}`), &payload); err == nil {
			t.Fatalf("sync_status=%s accepted", value)
		}
	}
	var payload siteBasicPayload
	if err := decodeSiteJSON([]byte(`{"domains":["a.example"]}`), &payload); err != nil || payload.SyncStatus != nil {
		t.Fatalf("payload without sync_status: %v %+v", err, payload.SyncStatus)
	}
}

func TestWriteSiteTLSErrorUsesStableCodes(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code string
	}{
		{name: "legacy", err: site.ErrTLSLegacyProtocolBlocked, code: "site_tls_legacy_protocol_blocked"},
		{name: "invalid", err: site.ErrTLSProtocolsInvalid, code: "site_tls_protocols_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/v1/sites", nil)
			(&Server{}).writeSiteError(recorder, request, test.err)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
			var response struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if response.Error.Code != test.code {
				t.Fatalf("error code = %q, want %q", response.Error.Code, test.code)
			}
		})
	}
}

func TestSITE15OpenAPISplitsCanonicalWritesFromRemediationReads(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve SITE-15 contract test path")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../../../../api/openapi/v1/sites.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]struct {
				AllOf []struct {
					Ref        string               `yaml:"$ref"`
					Required   []string             `yaml:"required"`
					Properties map[string]tlsSchema `yaml:"properties"`
				} `yaml:"allOf"`
				Required   []string             `yaml:"required"`
				Properties map[string]tlsSchema `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatalf("parse sites OpenAPI: %v", err)
	}
	request := document.Components.Schemas["SiteBasicRequest"]
	response := document.Components.Schemas["SiteBasicResponse"]
	base := document.Components.Schemas["SiteBasic"]
	if len(request.AllOf) != 2 || request.AllOf[0].Ref != "#/components/schemas/SiteBasic" ||
		len(response.AllOf) != 2 || response.AllOf[0].Ref != "#/components/schemas/SiteBasic" ||
		// fp-site SITE-CURRENT-01: a create may leave the listen ports out
		// (they follow the site defaults); a response always has them.
		// fp-site4: ipv6_enabled likewise (默认设置 > IPv6).
		!slices.Equal(response.AllOf[1].Required, []string{"tls_protocols", "http_listen_ports", "https_listen_ports", "ipv6_enabled"}) ||
		slices.Contains(base.Required, "http_listen_ports") || slices.Contains(base.Required, "https_listen_ports") ||
		slices.Contains(base.Required, "ipv6_enabled") {
		t.Fatalf("SITE-15 request/response schema split is incomplete: request=%+v response=%+v", request, response)
	}
	// A write is any ascending contiguous range of TLSv1..TLSv1.3.
	requestTLS := request.AllOf[1].Properties["tls_protocols"]
	if requestTLS.Const != nil || requestTLS.MinItems != 1 || requestTLS.MaxItems != 4 || requestTLS.Items == nil ||
		!slices.Equal(requestTLS.Items.Enum, []string{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}) ||
		!strings.Contains(requestTLS.Description, "contiguous range") {
		t.Fatalf("write TLS schema = %+v, want the contiguous range contract", requestTLS)
	}
	responseTLS := base.Properties["tls_protocols"]
	if responseTLS.Const != nil || responseTLS.MinItems != 1 || responseTLS.MaxItems != 8 ||
		!responseTLS.UniqueItems || responseTLS.Items == nil ||
		responseTLS.Items.Pattern != `^(?:SSLv2|SSLv3|TLSv[0-9]+(?:\.[0-9]+)?)$` ||
		!strings.Contains(responseTLS.Description, "remediation") || strings.Contains(responseTLS.Description, "always") {
		t.Fatalf("response remediation TLS schema = %+v", responseTLS)
	}
	for schema, property := range map[string]string{
		"CreateSiteRequest":      "basic",
		"UpdateSiteBasicRequest": "changes",
		"SiteDetail":             "basic",
	} {
		want := "#/components/schemas/SiteBasicRequest"
		if schema == "SiteDetail" {
			want = "#/components/schemas/SiteBasicResponse"
		}
		if got := document.Components.Schemas[schema].Properties[property].Ref; got != want {
			t.Errorf("%s.%s ref = %q, want %q", schema, property, got, want)
		}
	}
	create := document.Components.Schemas["CreateSiteRequest"]
	if got := create.Properties["origin_pool"].Ref; got != "#/components/schemas/OriginPool" {
		t.Fatalf("CreateSiteRequest.origin_pool ref = %q", got)
	}
	// The documented whitelist is the code's.
	suites := base.Properties["tls_cipher_suites"]
	if !slices.Contains(base.Properties["tls_cipher_preset"].Enum, edgeconfig.TLSCipherCustom) || suites.Items == nil ||
		!slices.Equal(suites.Items.Enum, edgeconfig.TLSCustomCipherSuites) || suites.MaxItems != edgeconfig.MaxTLSCipherSuites ||
		suites.MinItems != 1 || !suites.UniqueItems {
		t.Fatalf("tls_cipher_suites schema = %+v, want edgeconfig.TLSCustomCipherSuites", suites)
	}
}

type tlsSchema struct {
	Ref         string     `yaml:"$ref"`
	Const       any        `yaml:"const"`
	Default     any        `yaml:"default"`
	MinItems    int        `yaml:"minItems"`
	MaxItems    int        `yaml:"maxItems"`
	UniqueItems bool       `yaml:"uniqueItems"`
	Items       *tlsSchema `yaml:"items"`
	Pattern     string     `yaml:"pattern"`
	Enum        []string   `yaml:"enum"`
	Description string     `yaml:"description"`
}

func siteTLSStringListEquals(value any, expected ...string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	for index, item := range items {
		if item != expected[index] {
			return false
		}
	}
	return true
}
