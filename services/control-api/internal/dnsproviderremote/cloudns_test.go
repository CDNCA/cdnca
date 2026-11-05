package dnsproviderremote

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// Test-only credentials; requests reach only the httptest server.
const (
	clouDNSTestSubAuthID = "4321"
	clouDNSTestPassword  = "fixture-password"
)

// clouDNSFake follows the ClouDNS HTTP API wiki (articles 45/50/57-60):
// POST forms, HTTP 200 {"status":"Failed",...} refusals, records.json as a
// map keyed by id ([] when empty), the apex host "", the fixed TTL list.
type clouDNSFake struct {
	t        *testing.T
	mu       sync.Mutex
	nextID   int
	records  map[int]map[string]any
	noAddID  bool   // add-record answers without data.id
	failWith string // statusDescription forced on every call
	status   int    // HTTP status forced on every call
	pages    []string
	forms    []map[string]string
	zones    []string
}

func newClouDNSFake(t *testing.T) *clouDNSFake {
	return &clouDNSFake{t: t, nextID: 5000, records: map[int]map[string]any{}, zones: []string{testZone}}
}

func (fake *clouDNSFake) add(host, recordType, value string, ttl int, extra map[string]any) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.nextID++
	record := map[string]any{"id": strconv.Itoa(fake.nextID), "type": recordType, "host": host, "record": value,
		"ttl": strconv.Itoa(ttl), "status": 1, "failover": "0"}
	for key, item := range extra {
		record[key] = item
	}
	fake.records[fake.nextID] = record
	return fake.nextID
}

func (fake *clouDNSFake) reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fake.t.Errorf("encode: %v", err)
	}
}

func (fake *clouDNSFake) failed(w http.ResponseWriter, description string) {
	fake.reply(w, map[string]string{"status": "Failed", "statusDescription": description})
}

func (fake *clouDNSFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if r.Host != "api.cloudns.net" || r.Method != http.MethodPost ||
		r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		fake.t.Errorf("request %s %s host=%s query=%q", r.Method, r.URL.Path, r.Host, r.URL.RawQuery)
	}
	if err := r.ParseForm(); err != nil {
		fake.t.Fatalf("form: %v", err)
	}
	form := map[string]string{}
	for key := range r.PostForm {
		form[key] = r.PostForm.Get(key)
	}
	fake.forms = append(fake.forms, form)
	if fake.status != 0 {
		w.WriteHeader(fake.status)
		return
	}
	if form["sub-auth-id"] != clouDNSTestSubAuthID || form["auth-password"] != clouDNSTestPassword {
		fake.failed(w, "Invalid authentication, incorrect sub-auth-id, sub-auth-user or auth-password.")
		return
	}
	if fake.failWith != "" {
		fake.failed(w, fake.failWith)
		return
	}
	if r.URL.Path == "/login/login.json" {
		fake.reply(w, map[string]string{"status": "Success", "statusDescription": "Success login."})
		return
	}
	if r.URL.Path == "/dns/list-zones.json" {
		zones := []map[string]string{}
		for _, zone := range fake.zones {
			zones = append(zones, map[string]string{"name": zone, "type": "master", "zone": "domain", "status": "1"})
		}
		fake.reply(w, zones)
		return
	}
	if form["domain-name"] != testZone {
		fake.failed(w, "Missing domain-name")
		return
	}
	switch r.URL.Path {
	case "/dns/records.json":
		fake.list(w, form)
	case "/dns/add-record.json":
		ttl, _ := strconv.Atoi(form["ttl"])
		if !slices.Contains(clouDNSTTLs, uint32(ttl)) {
			fake.failed(w, "Invalid TTL. Choose from the list of the values we support.")
			return
		}
		fake.nextID++
		fake.records[fake.nextID] = map[string]any{"id": strconv.Itoa(fake.nextID), "type": form["record-type"],
			"host": form["host"], "record": form["record"], "ttl": form["ttl"], "status": 1}
		if fake.noAddID {
			fake.reply(w, map[string]string{"status": "Success", "statusDescription": "The record was added successfully."})
			return
		}
		fake.reply(w, map[string]any{"status": "Success", "statusDescription": "The record was added successfully.",
			"data": map[string]int{"id": fake.nextID}})
	case "/dns/mod-record.json":
		id, _ := strconv.Atoi(form["record-id"])
		record, exists := fake.records[id]
		ttl, _ := strconv.Atoi(form["ttl"])
		if !exists {
			fake.failed(w, "Invalid record-id param.")
			return
		}
		if !slices.Contains(clouDNSTTLs, uint32(ttl)) {
			fake.failed(w, "Invalid TTL. Choose from the list of the values we support.")
			return
		}
		record["host"], record["record"], record["ttl"] = form["host"], form["record"], form["ttl"]
		fake.reply(w, map[string]string{"status": "Success", "statusDescription": "The record was modified successfully."})
	case "/dns/delete-record.json":
		id, _ := strconv.Atoi(form["record-id"])
		if _, exists := fake.records[id]; !exists {
			fake.failed(w, "Invalid record-id param.")
			return
		}
		delete(fake.records, id)
		fake.reply(w, map[string]string{"status": "Success", "statusDescription": "The record was deleted successfully."})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (fake *clouDNSFake) list(w http.ResponseWriter, form map[string]string) {
	fake.pages = append(fake.pages, form["page"])
	ids := make([]int, 0, len(fake.records))
	for id, record := range fake.records {
		if _, filtered := form["host"]; filtered && record["host"] != form["host"] {
			continue
		}
		if form["type"] != "" && record["type"] != form["type"] {
			continue
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	size, _ := strconv.Atoi(form["rows-per-page"])
	page, _ := strconv.Atoi(form["page"])
	start := min((page-1)*size, len(ids))
	end := min(start+size, len(ids))
	if start == end {
		_, _ = w.Write([]byte("[]"))
		return
	}
	result := map[string]any{}
	for _, id := range ids[start:end] {
		result[strconv.Itoa(id)] = fake.records[id]
	}
	fake.reply(w, result)
}

func clouDNSTestConfig() ProviderConfig {
	return ProviderConfig{ProviderType: providerClouDNS, ZoneName: testZone,
		Credentials: map[string]string{"sub_auth_id": clouDNSTestSubAuthID, "auth_password": clouDNSTestPassword}}
}

func newClouDNSRemote(t *testing.T, fake *clouDNSFake) (*Adapter, *providerReconcileRemote, ProviderConfig) {
	config := clouDNSTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	return adapter, &providerReconcileRemote{adapter: adapter}, completeTestConfig(config)
}
func TestClouDNSDispatchAndCapability(t *testing.T) {
	adapter := newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)
	if provider, err := adapter.provider(providerClouDNS); err != nil {
		t.Fatalf("provider(cloudns) = %v", err)
	} else if _, ok := provider.(*clouDNSProvider); !ok {
		t.Fatalf("provider(cloudns) = %T", provider)
	}
	if production := productionEndpoints().cloudns; production.baseURL != "https://api.cloudns.net" || production.host != "api.cloudns.net" {
		t.Fatalf("production endpoint = %+v", production)
	}
	if got := SupportedLines(providerClouDNS); !slices.Equal(got, []string{LineDefault}) {
		t.Fatalf("SupportedLines = %v", got)
	}
	config := completeTestConfig(clouDNSTestConfig())
	err := validateProviderReconcileOperation(config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineTelecom})
	assertRemoteError(t, err, CodeUnsupported)
}

func TestClouDNSCredentials(t *testing.T) {
	for name, credentials := range map[string]map[string]string{
		"missing password": {"sub_auth_id": "1"},
		"non numeric id":   {"sub_auth_id": "user", "auth_password": "p"},
		"leading zero":     {"sub_auth_id": "01", "auth_password": "p"},
		"extra field":      {"sub_auth_id": "1", "auth_password": "p", "auth_id": "2"},
		"blank password":   {"sub_auth_id": "1", "auth_password": " "},
	} {
		if err := validateCredentials(providerClouDNS, credentials); ErrorCodeOf(err) != CodeInvalidInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := validateCredentials(providerClouDNS, map[string]string{"sub_auth_id": "4321", "auth_password": "p@ss"}); err != nil {
		t.Fatalf("valid credentials: %v", err)
	}
}

// The TTL list (article 58): below 60 is raised (ttl_clamped), others round
// down to a listed value.
func TestClouDNSEffectiveTTL(t *testing.T) {
	for _, test := range []struct {
		requested, want uint32
		clamped         bool
	}{{30, 60, true}, {60, 60, false}, {120, 60, false}, {300, 300, false}, {600, 300, false}, {3600, 3600, false},
		{86400, 86400, false}, {604800, 604800, false}} {
		if got, clamped := EffectiveTTL(providerClouDNS, test.requested); got != test.want || clamped != test.clamped {
			t.Errorf("EffectiveTTL(%d) = %d, %v", test.requested, got, clamped)
		}
	}
}

func TestClouDNSTXTLifecycle(t *testing.T) {
	for _, noAddID := range []bool{false, true} {
		t.Run("noAddID="+strconv.FormatBool(noAddID), func(t *testing.T) {
			fake := newClouDNSFake(t)
			fake.noAddID = noAddID
			fake.add("_acme-challenge", "TXT", "other-value", 60, nil)
			adapter, _, _ := newClouDNSRemote(t, fake)
			handle, err := adapter.PresentTXT(t.Context(), testChallenge())
			if err != nil {
				t.Fatalf("PresentTXT: %v", err)
			}
			add := fake.forms[0]
			if add["host"] != "_acme-challenge" || add["record-type"] != "TXT" || add["record"] != testValue || add["ttl"] != "60" {
				t.Fatalf("add-record form = %v", add)
			}
			requireHandle(t, handle, providerClouDNS, testZone, "5002")
			challenge := testChallengeWithHandle(handle)
			if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
				t.Fatalf("ObserveTXT: %v", err)
			}
			if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
				t.Fatalf("DeleteTXT: %v", err)
			}
			if _, exists := fake.records[5002]; exists || len(fake.records) != 1 {
				t.Fatalf("records = %v", fake.records)
			}
			assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound)
			if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
				t.Fatalf("second DeleteTXT: %v", err)
			}
		})
	}
}

func TestClouDNSRecoverTXTPages(t *testing.T) {
	fake := newClouDNSFake(t)
	for index := 0; index < 2*clouDNSPageSize; index++ {
		fake.add("_acme-challenge", "TXT", "filler-"+strconv.Itoa(index), 60, nil)
	}
	target := fake.add("_acme-challenge", "TXT", testValue, 60, nil)
	adapter, _, _ := newClouDNSRemote(t, fake)
	handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
	if err != nil || !found {
		t.Fatalf("RecoverTXT = %v, %v", found, err)
	}
	requireHandle(t, handle, providerClouDNS, testZone, strconv.Itoa(target))
	if !slices.Equal(fake.pages, []string{"1", "2", "3"}) {
		t.Fatalf("pages = %v", fake.pages)
	}
}

func TestClouDNSReconcileCRUD(t *testing.T) {
	fake := newClouDNSFake(t)
	fake.add("", "A", "192.0.2.99", 300, nil) // apex host is ""
	_, remote, config := newClouDNSRemote(t, fake)
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before create = %+v, %v", lookup, err)
	}
	recordID, err := remote.Mutate(t.Context(), config, create)
	if err != nil || recordID == "" {
		t.Fatalf("create = %q, %v", recordID, err)
	}
	if last := fake.forms[len(fake.forms)-1]; last["ttl"] != "300" || last["host"] != "www" {
		t.Fatalf("TTL 600 not written as listed 300: %v", last)
	}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup after create = %+v, %v", lookup, err)
	}
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600, PreviousValue: "192.0.2.10", PreviousTTL: 600}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before update = %+v, %v", lookup, err)
	}
	if got, err := remote.Mutate(t.Context(), config, update); err != nil || got != recordID {
		t.Fatalf("update = %q, %v", got, err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after update = %+v, %v", lookup, err)
	}
	cname := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "cdn.example.test.",
		Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 60}
	if _, err := remote.Mutate(t.Context(), config, cname); err != nil {
		t.Fatalf("create CNAME: %v", err)
	}
	if last := fake.forms[len(fake.forms)-1]; last["record"] != "edge.example.net" || last["record-type"] != "CNAME" {
		t.Fatalf("CNAME form = %v", last)
	}
	if lookup, err := remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup CNAME = %+v, %v", lookup, err)
	}
	remove := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600}
	if got, err := remote.Mutate(t.Context(), config, remove); err != nil || got != recordID {
		t.Fatalf("delete = %q, %v", got, err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, remove); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after delete = %+v, %v", lookup, err)
	}
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("second delete (Invalid record-id): %v", err)
	}
	apex, err := remote.ListZoneRecords(t.Context(), config, "example.test.")
	if err != nil || len(apex) != 1 || apex[0].Name != "example.test." || apex[0].Value != "192.0.2.99" {
		t.Fatalf("apex records = %+v, %v", apex, err)
	}
	zone, err := remote.ListZoneRecords(t.Context(), config, "")
	if err != nil || len(zone) != 2 {
		t.Fatalf("zone records = %+v, %v", zone, err)
	}
}

// A GeoDNS or disabled record of the owner is not the default-line answer:
// creating the same value conflicts instead of adopting it.
func TestClouDNSGeoDNSAndDisabledRecordsAreNotDefaultLine(t *testing.T) {
	for name, extra := range map[string]map[string]any{
		"geodns":   {"geodns-location-code": "EU"},
		"disabled": {"status": 0},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newClouDNSFake(t)
			fake.add("www", "A", "192.0.2.10", 300, extra)
			_, remote, config := newClouDNSRemote(t, fake)
			lookup, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
				Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300})
			if err != nil || lookup.TargetComplete || !lookup.Conflict {
				t.Fatalf("lookup = %+v, %v", lookup, err)
			}
		})
	}
}

func TestClouDNSErrorMapping(t *testing.T) {
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}
	for _, test := range []struct {
		name     string
		badAuth  bool
		failWith string
		status   int
		want     ErrorCode
	}{
		{name: "bad auth", badAuth: true, want: CodeCredentialsRejected},
		{name: "rate limited", failWith: "Request blocked. 198.51.100.7 is sending more than 20 requests per second.", want: CodeRateLimited},
		{name: "unknown zone", failWith: "Missing domain-name", want: CodeZoneNotHosted},
		{name: "refused value", failWith: "This is not a valid IP address.", want: CodeInvalidInput},
		{name: "http 503", status: http.StatusServiceUnavailable, want: CodeUnavailable},
		{name: "http 429", status: http.StatusTooManyRequests, want: CodeRateLimited},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newClouDNSFake(t)
			fake.failWith, fake.status = test.failWith, test.status
			_, remote, config := newClouDNSRemote(t, fake)
			if test.badAuth {
				config.Credentials["auth_password"] = "wrong-password"
			}
			_, err := remote.Lookup(t.Context(), config, create)
			assertRemoteError(t, err, test.want)
			var remoteErr *Error
			if test.want == CodeRateLimited && (!errorAs(err, &remoteErr) || !remoteErr.Temporary) {
				t.Fatalf("rate limit error = %+v", remoteErr)
			}
		})
	}
	fake := newClouDNSFake(t)
	_, remote, config := newClouDNSRemote(t, fake)
	fake.failWith = "Invalid TTL. Choose from the list of the values we support."
	if _, err := remote.Mutate(t.Context(), config, create); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("refused create = %v", err)
	}
}

func TestClouDNSResolveZoneApex(t *testing.T) {
	fake := newClouDNSFake(t)
	fake.zones = []string{"other.test", testZone}
	_, remote, config := newClouDNSRemote(t, fake)
	apex, err := remote.ResolveZoneApex(t.Context(), providerClouDNS, config.Credentials, "cdn."+testZone)
	if err != nil || apex != testZone {
		t.Fatalf("ResolveZoneApex = %q, %v", apex, err)
	}
	if fake.forms[0]["rows-per-page"] != strconv.Itoa(zoneApexPageSize) || fake.forms[0]["page"] != "1" {
		t.Fatalf("list-zones form = %v", fake.forms[0])
	}
}
