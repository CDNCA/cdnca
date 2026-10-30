package dnsproviderremote

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// hubTXTValue has a space and an equals sign: what SPF / site verification
// TXT text looks like, outside the DNS-01 alphabet.
const hubTXTValue = "v=spf1 include:_spf.example.test -all"

// The hub listing returns TXT next to A/AAAA/CNAME for every HTTP adapter;
// the reconcile listing (ListZoneRecords) still never does.
func TestListHubRecordsIncludesTXTAcrossProviders(t *testing.T) {
	for _, provider := range []string{providerCloudflare, providerAliyun, providerHuawei, providerDNSPodCN, providerDNSCom, providerDNSLA} {
		t.Run(provider, func(t *testing.T) {
			fixture := &recordListFixture{reconcileHTTPFixture: reconcileHTTPFixture{t: t, provider: provider}}
			config := reconcileHTTPProviderConfig(provider)
			adapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
			hub := hubRemote{remote: &providerReconcileRemote{adapter: adapter}}
			config = completeTestConfig(config)

			owned, skipped, err := hub.ListHubRecords(t.Context(), config, "www."+testZone+".")
			if err != nil {
				t.Fatalf("ListHubRecords() error = %v", err)
			}
			var txt []ZoneRecord
			for _, record := range owned {
				if record.Type == dnscheck.RecordTXT {
					txt = append(txt, record)
				}
			}
			if skipped != 0 || len(owned) != 2 || len(txt) != 1 || txt[0].Value != "v=spf1 -all" || txt[0].ID != "txt-1" ||
				txt[0].Name != "www."+testZone+"." {
				t.Fatalf("hub records = %+v", owned)
			}
			legacy, err := (&providerReconcileRemote{adapter: adapter}).ListZoneRecords(t.Context(), config, "www."+testZone+".")
			if err != nil || len(legacy) != 1 || legacy[0].Type != dnscheck.RecordA {
				t.Fatalf("ListZoneRecords() = %+v, %v (must stay A/AAAA/CNAME)", legacy, err)
			}
		})
	}
}

func TestUnquoteTXT(t *testing.T) {
	for raw, want := range map[string]string{
		`"v=spf1 -all"`:   "v=spf1 -all",
		`"part1" "part2"`: "part1part2",
		`plain text`:      "plain text",
		`"`:               `"`,
	} {
		if got := unquoteTXT(raw); got != want {
			t.Errorf("unquoteTXT(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestHubTXTWritable(t *testing.T) {
	for value, want := range map[string]bool{
		hubTXTValue:                  true,
		"google-site-verification=x": true,
		"":                           false,
		" leading":                   false,
		`has "quote"`:                false,
		`back\slash`:                 false,
		"line\nbreak":                false,
		strings.Repeat("a", 255):     true,
		strings.Repeat("a", 256):     false,
	} {
		if got := HubTXTWritable(value); got != want {
			t.Errorf("HubTXTWritable(%q) = %v, want %v", value, got, want)
		}
	}
}

// hubWriteFixture answers the create call of each provider and records the
// TXT value it was sent.
type hubWriteFixture struct {
	t        *testing.T
	provider string
	sent     string
	typeSent string
}

func (fixture *hubWriteFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zones := reconcileHTTPFixture{t: fixture.t, provider: fixture.provider}
	if zones.writeZoneResponse(w, r) {
		return
	}
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	switch fixture.provider {
	case providerCloudflare:
		fixture.sent, _ = decoded["content"].(string)
		fixture.typeSent, _ = decoded["type"].(string)
		writeTestJSON(fixture.t, w, map[string]any{"success": true, "result": map[string]any{"id": "txt-new"}})
	case providerAliyun:
		query := r.URL.Query()
		fixture.sent, fixture.typeSent = query.Get("Value"), query.Get("Type")
		writeTestJSON(fixture.t, w, map[string]any{"RequestId": "request-create", "RecordId": "txt-new"})
	case providerHuawei:
		if records, ok := decoded["records"].([]any); ok && len(records) == 1 {
			fixture.sent, _ = records[0].(string)
		}
		fixture.typeSent, _ = decoded["type"].(string)
		writeTestJSON(fixture.t, w, map[string]any{"id": "txt-new", "zone_id": "zone-hw", "name": "www.example.test.",
			"type": "TXT", "records": []string{fixture.sent}, "ttl": 600})
	case providerDNSPodCN:
		fixture.sent, fixture.typeSent = form.Get("value"), form.Get("record_type")
		writeTestJSON(fixture.t, w, map[string]any{"status": map[string]any{"code": "1"}, "record": map[string]any{"id": "txt-new"}})
	case providerDNSLA:
		fixture.sent, _ = decoded["data"].(string)
		if number, ok := decoded["type"].(float64); ok && number == 16 {
			fixture.typeSent = "TXT"
		}
		writeTestJSON(fixture.t, w, map[string]any{"code": 200, "data": map[string]any{"id": "txt-new"}})
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

// Every provider writes the TXT text verbatim (Huawei quotes it:
// TestHuaweiWireValueQuotesTXT; its create path lists record sets first).
func TestHubMutateWritesTXT(t *testing.T) {
	for provider, want := range map[string]string{
		providerCloudflare: hubTXTValue, providerAliyun: hubTXTValue, providerDNSPodCN: hubTXTValue,
		providerDNSLA: hubTXTValue,
	} {
		t.Run(provider, func(t *testing.T) {
			fixture := &hubWriteFixture{t: t, provider: provider}
			config := reconcileHTTPProviderConfig(provider)
			adapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
			hub := hubRemote{remote: &providerReconcileRemote{adapter: adapter}}
			config = completeTestConfig(config)
			operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www." + testZone + ".",
				Type: dnscheck.RecordTXT, Value: hubTXTValue, TTL: 600}
			id, err := hub.Mutate(t.Context(), config, operation)
			if err != nil || id != "txt-new" {
				t.Fatalf("Mutate() = %q, %v", id, err)
			}
			if fixture.sent != want || fixture.typeSent != "TXT" {
				t.Fatalf("sent type=%q value=%q, want TXT %q", fixture.typeSent, fixture.sent, want)
			}
			// The reconcile boundary still refuses TXT.
			if _, err := (&providerReconcileRemote{adapter: adapter}).Mutate(t.Context(), config, operation); ErrorCodeOf(err) != CodeUnsupported {
				t.Fatalf("reconcile Mutate(TXT) error = %v, want unsupported", err)
			}
		})
	}
}

func TestHuaweiWireValueQuotesTXT(t *testing.T) {
	if got := huaweiWireValue(dnscheck.RecordTXT, hubTXTValue); got != `"`+hubTXTValue+`"` {
		t.Fatalf("huaweiWireValue(TXT) = %q", got)
	}
	if got := huaweiWireValue(dnscheck.RecordCNAME, "a.example.test."); got != "a.example.test" {
		t.Fatalf("huaweiWireValue(CNAME) = %q", got)
	}
	// A multi-value TXT set keeps short, unique per-value record IDs.
	first := huaweiValueRecordID("set", `"`+hubTXTValue+`"`, 2)
	second := huaweiValueRecordID("set", `"other"`, 2)
	if first == second || len(first) > 64 || !strings.HasPrefix(first, "set/h") {
		t.Fatalf("TXT value IDs %q %q", first, second)
	}
	if got := huaweiValueRecordID("set", "192.0.2.1", 2); got != "set/192.0.2.1" {
		t.Fatalf("A value ID changed: %q", got)
	}
}

func TestHubRefusesUnwritableTXT(t *testing.T) {
	config := completeTestConfig(reconcileHTTPProviderConfig(providerCloudflare))
	hub := hubRemote{remote: &providerReconcileRemote{adapter: &Adapter{}}}
	_, err := hub.Mutate(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www." + testZone + ".", Type: dnscheck.RecordTXT, Value: `with "quote"`, TTL: 600})
	if ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("error = %v, want invalid input", err)
	}
}

func TestHubRecordTypeSupported(t *testing.T) {
	for _, capability := range ProviderCapabilityMatrix() {
		for _, recordType := range []dnscheck.RecordType{dnscheck.RecordA, dnscheck.RecordAAAA, dnscheck.RecordCNAME, dnscheck.RecordTXT} {
			if !HubRecordTypeSupported(capability.ProviderType, recordType) {
				t.Errorf("%s does not support %v", capability.ProviderType, recordType)
			}
		}
	}
	if HubRecordTypeSupported(providerCloudflare, dnscheck.RecordSOA) || HubRecordTypeSupported("dnsdun", dnscheck.RecordA) {
		t.Fatal("unsupported type or provider accepted")
	}
}
