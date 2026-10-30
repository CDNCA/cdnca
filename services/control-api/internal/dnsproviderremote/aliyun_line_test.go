package dnsproviderremote

import (
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// aliyunLineFixture serves DescribeDomainRecords over two pages (the owner has
// records on the default line, the telecom line and an Anhui-telecom line the
// unified enum does not map), DescribeDomainRecordInfo, and the three
// mutations. Every request must be signed and carry exactly the documented
// action parameters.
type aliyunLineFixture struct {
	t         *testing.T
	mu        sync.Mutex
	mutations []url.Values
	infoLine  string
	pages     []int
}

var aliyunCommonParameters = map[string]bool{
	"AccessKeyId": true, "Format": true, "SignatureMethod": true, "SignatureNonce": true,
	"SignatureVersion": true, "Timestamp": true, "Version": true, "Signature": true,
}

func aliyunActionParameters(query url.Values) map[string]string {
	result := map[string]string{}
	for name := range query {
		if !aliyunCommonParameters[name] {
			result[name] = query.Get(name)
		}
	}
	return result
}

func (fixture *aliyunLineFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	query := r.URL.Query()
	if r.Method != http.MethodGet || r.URL.Path != "/" || query.Get("AccessKeyId") != "provider-key" ||
		query.Get("SignatureNonce") != "nonce-123" || !verifyRound3AliyunSignature(query, "provider-secret") {
		fixture.t.Errorf("unsigned or malformed request %s %s", r.Method, r.URL.RequestURI())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch query.Get("Action") {
	case "DescribeDomainRecords":
		page, _ := strconv.Atoi(query.Get("PageNumber"))
		fixture.pages = append(fixture.pages, page)
		want := map[string]string{
			"Action": "DescribeDomainRecords", "DomainName": "example.test", "RRKeyWord": "www",
			"TypeKeyWord": "A", "PageNumber": strconv.Itoa(page), "PageSize": "100",
		}
		if query.Get("TypeKeyWord") == "" { // ListZoneRecords lists every type of the owner
			delete(want, "TypeKeyWord")
		}
		assertExactParameters(fixture.t, "DescribeDomainRecords", aliyunActionParameters(query), want)
		records := []any{}
		if page == 1 {
			for index := range 100 {
				line := "default"
				if index == 0 {
					line = "cn_telecom_anhui"
				}
				records = append(records, map[string]any{"RecordId": "default-" + strconv.Itoa(index), "RR": "www",
					"Type": "A", "Value": "198.51.100." + strconv.Itoa(index+1), "TTL": 300, "Line": line})
			}
		} else {
			records = append(records, map[string]any{"RecordId": "telecom-1", "RR": "www", "Type": "A",
				"Value": "192.0.2.10", "TTL": 300, "Line": "telecom"})
		}
		writeTestJSON(fixture.t, w, map[string]any{"RequestId": "request-list", "TotalCount": 101, "PageNumber": page, "PageSize": 100,
			"DomainRecords": map[string]any{"Record": records}})
	case "DescribeDomainRecordInfo":
		assertExactParameters(fixture.t, "DescribeDomainRecordInfo", aliyunActionParameters(query),
			map[string]string{"Action": "DescribeDomainRecordInfo", "RecordId": "telecom-1"})
		writeTestJSON(fixture.t, w, map[string]any{"RequestId": "request-info", "RecordId": "telecom-1", "RR": "www", "Type": "A",
			"Value": "192.0.2.10", "TTL": 300, "DomainName": "example.test", "Line": fixture.infoLine})
	case "AddDomainRecord", "UpdateDomainRecord", "DeleteDomainRecord":
		fixture.mutations = append(fixture.mutations, query)
		writeTestJSON(fixture.t, w, map[string]any{"RecordId": "telecom-1", "RequestId": "request-1"})
	default:
		fixture.t.Errorf("unexpected action %q", query.Get("Action"))
		w.WriteHeader(http.StatusBadRequest)
	}
}

func assertExactParameters(t *testing.T, name string, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s parameters = %v, want %v", name, got, want)
		return
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s %s = %q, want %q (all %v)", name, key, got[key], value, got)
		}
	}
}

func newAliyunLineRemote(t *testing.T) (*aliyunLineFixture, *providerReconcileRemote, ProviderConfig) {
	fixture := &aliyunLineFixture{t: t, infoLine: "telecom"}
	config := reconcileHTTPProviderConfig(providerAliyun)
	providerAdapter, _ := newProviderTestAdapter(t, config, fixture, time.Second)
	return fixture, &providerReconcileRemote{adapter: providerAdapter}, completeTestConfig(config)
}

func TestAliyunLineCreateLookupSeesOnlyItsLineAcrossPages(t *testing.T) {
	fixture, remote, config := newAliyunLineRemote(t)
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineTelecom}
	lookup, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "telecom-1" || lookup.Conflict || lookup.Ambiguous {
		t.Fatalf("telecom Lookup() = (%+v, %v), want the page-2 telecom record", lookup, err)
	}
	if len(fixture.pages) != 2 || fixture.pages[0] != 1 || fixture.pages[1] != 2 {
		t.Fatalf("pages = %v, want [1 2]", fixture.pages)
	}

	// The same value on the default line is a different record set: absent.
	operation.Line = LineDefault
	lookup, err = remote.Lookup(t.Context(), config, operation)
	if err != nil || lookup.TargetComplete || lookup.Conflict || lookup.Ambiguous {
		t.Fatalf("default Lookup() = (%+v, %v), want absent", lookup, err)
	}
	// 198.51.100.1 sits on the unmapped Anhui line; the default line does not see it.
	operation.Value = "198.51.100.1"
	lookup, err = remote.Lookup(t.Context(), config, operation)
	if err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("foreign-line Lookup() = (%+v, %v), want absent on 默认", lookup, err)
	}
	operation.Value = "198.51.100.2"
	lookup, err = remote.Lookup(t.Context(), config, operation)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "default-1" {
		t.Fatalf("default record Lookup() = (%+v, %v)", lookup, err)
	}
}

func TestAliyunLineMutationsSendMappedLine(t *testing.T) {
	fixture, remote, config := newAliyunLineRemote(t)
	base := dnscheck.ProviderOperation{Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}

	create := base
	create.Action, create.Line = dnscheck.ProviderCreate, LineOverseas
	if id, err := remote.Mutate(t.Context(), config, create); err != nil || id != "telecom-1" {
		t.Fatalf("create = (%q, %v)", id, err)
	}
	update := base
	update.Action, update.RecordID, update.Line = dnscheck.ProviderUpdate, "telecom-1", LineMobile
	update.PreviousValue, update.PreviousTTL, update.PreviousLine = "192.0.2.10", 300, LineTelecom
	if _, err := remote.Mutate(t.Context(), config, update); err != nil {
		t.Fatalf("update error = %v", err)
	}
	defaultCreate := base
	defaultCreate.Action = dnscheck.ProviderCreate
	if _, err := remote.Mutate(t.Context(), config, defaultCreate); err != nil {
		t.Fatalf("default create error = %v", err)
	}
	remove := base
	remove.Action, remove.RecordID, remove.Line = dnscheck.ProviderDelete, "telecom-1", "aliyun:cn_telecom_anhui"
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("delete of a foreign-line record error = %v", err)
	}

	want := []map[string]string{
		{"Action": "AddDomainRecord", "DomainName": "example.test", "RR": "www", "Type": "A", "Value": "192.0.2.10", "TTL": "300", "Line": "oversea"},
		{"Action": "UpdateDomainRecord", "RecordId": "telecom-1", "RR": "www", "Type": "A", "Value": "192.0.2.10", "TTL": "300", "Line": "mobile"},
		{"Action": "AddDomainRecord", "DomainName": "example.test", "RR": "www", "Type": "A", "Value": "192.0.2.10", "TTL": "300", "Line": "default"},
		{"Action": "DeleteDomainRecord", "RecordId": "telecom-1"},
	}
	if len(fixture.mutations) != len(want) {
		t.Fatalf("mutations = %d, want %d", len(fixture.mutations), len(want))
	}
	for index, query := range fixture.mutations {
		assertExactParameters(t, want[index]["Action"], aliyunActionParameters(query), want[index])
	}
}

func TestAliyunLineRecordLookupReadsInfoLine(t *testing.T) {
	fixture, remote, config := newAliyunLineRemote(t)
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: "telecom-1", Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineMobile,
		PreviousValue: "192.0.2.10", PreviousTTL: 300, PreviousLine: LineTelecom}
	lookup, err := remote.Lookup(t.Context(), config, update)
	if err != nil || lookup.TargetComplete || lookup.Conflict || lookup.RecordID != "" {
		t.Fatalf("pre-update Lookup() = (%+v, %v), want previous state", lookup, err)
	}
	fixture.infoLine = "mobile"
	lookup, err = remote.Lookup(t.Context(), config, update)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "telecom-1" {
		t.Fatalf("post-update Lookup() = (%+v, %v), want complete", lookup, err)
	}
	fixture.infoLine = "cn_mobile_anhui"
	lookup, err = remote.Lookup(t.Context(), config, update)
	if err != nil || !lookup.Conflict {
		t.Fatalf("foreign-line Lookup() = (%+v, %v), want conflict", lookup, err)
	}
}

func TestAliyunLineUnmappedLineFailsBeforeNetwork(t *testing.T) {
	fixture, remote, config := newAliyunLineRemote(t)
	for _, line := range []string{"教育网", "广东电信", "aliyun:cn_telecom_anhui"} {
		operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
			Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: line}
		if _, err := remote.Mutate(t.Context(), config, operation); ErrorCodeOf(err) != CodeUnsupported {
			t.Fatalf("Mutate(line %q) error = %v, want unsupported", line, err)
		}
	}
	if len(fixture.mutations) != 0 || len(fixture.pages) != 0 {
		t.Fatalf("network calls: mutations=%d pages=%v", len(fixture.mutations), fixture.pages)
	}
}

func TestAliyunListZoneRecordsReportsUnifiedLines(t *testing.T) {
	_, remote, config := newAliyunLineRemote(t)
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil {
		t.Fatalf("ListZoneRecords() error = %v", err)
	}
	lines := map[string]string{}
	for _, record := range records {
		lines[record.ID] = record.Line
	}
	if lines["telecom-1"] != LineTelecom || lines["default-1"] != LineDefault || lines["default-0"] != "aliyun:cn_telecom_anhui" {
		t.Fatalf("lines = telecom-1:%q default-1:%q default-0:%q", lines["telecom-1"], lines["default-1"], lines["default-0"])
	}
}
