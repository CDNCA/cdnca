package dnsproviderremote

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// Test-only credentials; requests reach only the httptest server.
const (
	jdCloudTestAK = "FIXTUREAK0000000000000000"
	jdCloudTestSK = "FIXTURESK0000000000000000"
	jdCloudTestID = "199"
)

// jdCloudFake follows the domainservice v2 docs: describeDomains /
// describeResourceRecord pages (dataList, totalCount, totalPage), create
// (result.dataList = the RR), modify (requestId only), delete, the error
// envelope {"error":{"code","status","message"}} with the HTTP status. It
// recomputes every request's JDCLOUD2 signature.
type jdCloudFake struct {
	t        *testing.T
	mu       sync.Mutex
	nextID   int
	records  map[int]map[string]any
	freePlan bool
	status   int
	errCode  int
	domains  []string
	creates  []map[string]any
	modifies []map[string]any
	deleted  []string
	pages    []string
	searches []string
}

func newJDCloudFake(t *testing.T) *jdCloudFake {
	return &jdCloudFake{t: t, nextID: 9000, records: map[int]map[string]any{}, freePlan: true, domains: []string{testZone}}
}

func (fake *jdCloudFake) add(host, recordType, value string, ttl, view int, status string) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.nextID++
	fake.records[fake.nextID] = map[string]any{"id": fake.nextID, "hostRecord": host, "hostValue": value, "ttl": ttl,
		"type": recordType, "viewValue": []int{view}, "resolvingStatus": status, "weight": 1, "viewName": "x"}
	return fake.nextID
}

func (fake *jdCloudFake) fail(w http.ResponseWriter, code int, status string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"requestId": "req-1",
		"error": map[string]any{"code": code, "status": status, "message": "fixture"}})
}

func (fake *jdCloudFake) ok(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"requestId": "req-1"}
	if result != nil {
		body["result"] = result
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (fake *jdCloudFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.Host != "domainservice.jdcloud-api.com" || r.Header.Get("x-jdcloud-algorithm") != "JDCLOUD2-HMAC-SHA256" {
		fake.t.Errorf("request host=%s headers=%v", r.Host, r.Header)
	}
	at, _ := time.Parse(jdCloudTimeLayout, r.Header.Get("x-jdcloud-date"))
	want := JDCloudSignature(jdCloudTestAK, jdCloudTestSK, "cn-north-1", "domainservice", r.Method, r.URL.Path, r.URL.Query(),
		map[string]string{"content-type": r.Header.Get("Content-Type"), "host": r.Host,
			"x-jdcloud-date": r.Header.Get("x-jdcloud-date"), "x-jdcloud-nonce": r.Header.Get("x-jdcloud-nonce")}, body, at)
	if r.Header.Get("Authorization") != want || r.URL.RawQuery != jdCloudCanonicalQuery(r.URL.Query()) {
		fake.fail(w, http.StatusUnauthorized, "UNAUTHENTICATED")
		return
	}
	if fake.status != 0 {
		fake.fail(w, fake.status, "FORCED")
		return
	}
	if fake.errCode != 0 {
		// An error envelope on HTTP 200 (as the SDK checks resp.Error.Code).
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"requestId": "req-1",
			"error": map[string]any{"code": fake.errCode, "status": "FORCED", "message": "fixture"}})
		return
	}
	query := r.URL.Query()
	pageSize, _ := strconv.Atoi(query.Get("pageSize"))
	pageNumber, _ := strconv.Atoi(query.Get("pageNumber"))
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v2/regions/cn-north-1/domain":
		var list []map[string]any
		for index, domain := range fake.domains {
			if keyword := query.Get("domainName"); keyword != "" && !strings.Contains(domain, keyword) {
				continue
			}
			id := jdCloudTestID
			if domain != testZone {
				id = strconv.Itoa(300 + index)
			}
			list = append(list, map[string]any{"id": json.Number(id), "domainName": domain, "packId": 0})
		}
		fake.page(w, list, pageNumber, pageSize)
		return
	case !strings.HasPrefix(r.URL.Path, "/v2/regions/cn-north-1/domain/"+jdCloudTestID+"/ResourceRecord"):
		fake.fail(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v2/regions/cn-north-1/domain/"+jdCloudTestID+"/ResourceRecord")
	switch {
	case r.Method == http.MethodGet && rest == "":
		fake.pages = append(fake.pages, query.Get("pageNumber"))
		fake.searches = append(fake.searches, query.Get("search"))
		ids := make([]int, 0, len(fake.records))
		for id, record := range fake.records {
			if search := query.Get("search"); search == "" || strings.Contains(record["hostRecord"].(string), search) {
				ids = append(ids, id)
			}
		}
		sort.Ints(ids)
		list := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			list = append(list, fake.records[id])
		}
		fake.page(w, list, pageNumber, pageSize)
	case r.Method == http.MethodPost && rest == "":
		var request struct {
			Req map[string]any `json:"req"`
		}
		_ = json.Unmarshal(body, &request)
		fake.creates = append(fake.creates, request.Req)
		if !fake.writable(w, request.Req) {
			return
		}
		fake.nextID++
		record := map[string]any{"id": fake.nextID, "hostRecord": request.Req["hostRecord"], "hostValue": request.Req["hostValue"],
			"ttl": request.Req["ttl"], "type": request.Req["type"], "viewValue": []any{request.Req["viewValue"]}, "resolvingStatus": "2"}
		fake.records[fake.nextID] = record
		fake.ok(w, map[string]any{"dataList": record})
	case r.Method == http.MethodPut || r.Method == http.MethodDelete:
		id, _ := strconv.Atoi(strings.TrimPrefix(rest, "/"))
		record, exists := fake.records[id]
		if !exists {
			fake.fail(w, http.StatusNotFound, "NOT_FOUND")
			return
		}
		if r.Method == http.MethodDelete {
			fake.deleted = append(fake.deleted, strconv.Itoa(id))
			delete(fake.records, id)
			fake.ok(w, nil)
			return
		}
		var request struct {
			Req map[string]any `json:"req"`
		}
		_ = json.Unmarshal(body, &request)
		fake.modifies = append(fake.modifies, request.Req)
		if request.Req["domainName"] != testZone || !fake.writable(w, request.Req) {
			if request.Req["domainName"] != testZone {
				fake.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT")
			}
			return
		}
		record["hostRecord"], record["hostValue"], record["ttl"] = request.Req["hostRecord"], request.Req["hostValue"], request.Req["ttl"]
		record["viewValue"] = []any{request.Req["viewValue"]}
		fake.ok(w, nil)
	default:
		fake.fail(w, http.StatusNotFound, "NOT_FOUND")
	}
}

// writable enforces the free plan: TTL >= 120, no 境外 (view 4).
func (fake *jdCloudFake) writable(w http.ResponseWriter, request map[string]any) bool {
	ttl, _ := request["ttl"].(float64)
	view, _ := request["viewValue"].(float64)
	if fake.freePlan && (ttl < 120 || view == 4) {
		fake.fail(w, http.StatusBadRequest, "INVALID_ARGUMENT")
		return false
	}
	return true
}

func (fake *jdCloudFake) page(w http.ResponseWriter, list []map[string]any, pageNumber, pageSize int) {
	if pageNumber < 1 {
		pageNumber = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	start := min((pageNumber-1)*pageSize, len(list))
	end := min(start+pageSize, len(list))
	totalPage := (len(list) + pageSize - 1) / pageSize
	page := list[start:end]
	if page == nil {
		page = []map[string]any{}
	}
	fake.ok(w, map[string]any{"dataList": page, "totalCount": len(list), "totalPage": totalPage, "currentCount": len(page)})
}

func jdCloudTestConfig() ProviderConfig {
	return ProviderConfig{ProviderType: providerJDCloud, ZoneName: testZone,
		Credentials: map[string]string{"access_key_id": jdCloudTestAK, "access_key_secret": jdCloudTestSK}}
}

func newJDCloudRemote(t *testing.T, fake *jdCloudFake) (*Adapter, *providerReconcileRemote, ProviderConfig) {
	config := jdCloudTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	return adapter, &providerReconcileRemote{adapter: adapter}, completeTestConfig(config)
}
func TestJDCloudDispatchLinesCredentialsTTL(t *testing.T) {
	adapter := newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)
	if provider, err := adapter.provider(providerJDCloud); err != nil {
		t.Fatalf("provider(jdcloud) = %v", err)
	} else if _, ok := provider.(*jdCloudProvider); !ok {
		t.Fatalf("provider(jdcloud) = %T", provider)
	}
	if production := productionEndpoints().jdcloud; production.baseURL != "https://domainservice.jdcloud-api.com" {
		t.Fatalf("production endpoint = %+v", production)
	}
	if got := SupportedLines(providerJDCloud); !slices.Equal(got, []string{LineDefault, LineTelecom, LineUnicom, LineMobile, LineOverseas}) {
		t.Fatalf("SupportedLines = %v", got)
	}
	for name, credentials := range map[string]map[string]string{
		"missing secret": {"access_key_id": "a"},
		"extra field":    {"access_key_id": "a", "access_key_secret": "b", "region": "cn-north-1"},
		"blank secret":   {"access_key_id": "a", "access_key_secret": " "},
	} {
		if err := validateCredentials(providerJDCloud, credentials); ErrorCodeOf(err) != CodeInvalidInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, test := range []struct {
		requested, want uint32
		clamped         bool
	}{{60, 120, true}, {119, 120, true}, {120, 120, false}, {600, 600, false}} {
		if got, clamped := EffectiveTTL(providerJDCloud, test.requested); got != test.want || clamped != test.clamped {
			t.Errorf("EffectiveTTL(%d) = %d, %v", test.requested, got, clamped)
		}
	}
}

func TestJDCloudTXTLifecycle(t *testing.T) {
	fake := newJDCloudFake(t)
	fake.add("_acme-challenge", "TXT", "other-value", 120, -1, "2")
	adapter, _, _ := newJDCloudRemote(t, fake)
	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	create := fake.creates[0]
	if create["hostRecord"] != "_acme-challenge" || create["type"] != "TXT" || create["hostValue"] != testValue ||
		create["ttl"] != float64(120) || create["viewValue"] != float64(-1) {
		t.Fatalf("create = %v", create)
	}
	requireHandle(t, handle, providerJDCloud, jdCloudTestID, "9002")
	challenge := testChallengeWithHandle(handle)
	if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if !slices.Equal(fake.deleted, []string{"9002"}) || len(fake.records) != 1 {
		t.Fatalf("deleted = %v records = %v", fake.deleted, fake.records)
	}
	assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound)
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("second DeleteTXT: %v", err)
	}
	if err := (&jdCloudProvider{adapter: adapter}).deleteRecord(t.Context(), completeTestConfig(jdCloudTestConfig()),
		jdCloudTestID, "424242"); err != nil {
		t.Fatalf("delete missing record (404): %v", err)
	}
}

func TestJDCloudRecoverTXTPages(t *testing.T) {
	fake := newJDCloudFake(t)
	for index := 0; index < 2*jdCloudPageSize; index++ {
		fake.add("_acme-challenge", "TXT", "filler-"+strconv.Itoa(index), 120, -1, "2")
	}
	target := fake.add("_acme-challenge", "TXT", testValue, 120, -1, "2")
	adapter, _, _ := newJDCloudRemote(t, fake)
	handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
	if err != nil || !found {
		t.Fatalf("RecoverTXT = %v, %v", found, err)
	}
	requireHandle(t, handle, providerJDCloud, jdCloudTestID, strconv.Itoa(target))
	if !slices.Equal(fake.pages, []string{"1", "2", "3"}) || fake.searches[0] != "_acme-challenge" {
		t.Fatalf("pages = %v searches = %v", fake.pages, fake.searches)
	}
}

func TestJDCloudReconcileCRUDOnLines(t *testing.T) {
	fake := newJDCloudFake(t)
	fake.add("www", "A", "192.0.2.10", 600, 2, "2") // 联通: another line, independent
	_, remote, config := newJDCloudRemote(t, fake)
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 60, Line: LineTelecom}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before create = %+v, %v", lookup, err)
	}
	recordID, err := remote.Mutate(t.Context(), config, create)
	if err != nil || recordID == "" {
		t.Fatalf("create = %q, %v", recordID, err)
	}
	if last := fake.creates[len(fake.creates)-1]; last["viewValue"] != float64(1) || last["ttl"] != float64(120) {
		t.Fatalf("create on 电信 at TTL 120 = %v", last)
	}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup after create = %+v, %v", lookup, err)
	}
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600, Line: LineTelecom, PreviousValue: "192.0.2.10",
		PreviousTTL: 60, PreviousLine: LineTelecom}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before update = %+v, %v", lookup, err)
	}
	if got, err := remote.Mutate(t.Context(), config, update); err != nil || got != recordID {
		t.Fatalf("update = %q, %v", got, err)
	}
	if last := fake.modifies[len(fake.modifies)-1]; last["domainName"] != testZone || last["hostValue"] != "192.0.2.11" ||
		last["viewValue"] != float64(1) {
		t.Fatalf("modify = %v", last)
	}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after update = %+v, %v", lookup, err)
	}
	cname := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "example.test.",
		Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 600}
	if _, err := remote.Mutate(t.Context(), config, cname); err != nil {
		t.Fatalf("create apex CNAME: %v", err)
	}
	if last := fake.creates[len(fake.creates)-1]; last["hostRecord"] != "@" || last["hostValue"] != "edge.example.net" ||
		last["viewValue"] != float64(-1) {
		t.Fatalf("apex CNAME create = %v", last)
	}
	if lookup, err := remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup apex CNAME = %+v, %v", lookup, err)
	}
	remove := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600, Line: LineTelecom}
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, remove); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after delete = %+v, %v", lookup, err)
	}
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil || len(records) != 1 || records[0].Line != LineUnicom {
		t.Fatalf("www records = %+v, %v", records, err)
	}
}

// The free plan has no 境外 line: the refused write is line_not_in_plan.
func TestJDCloudOverseasOnFreePlanIsLineNotInPlan(t *testing.T) {
	fake := newJDCloudFake(t)
	_, remote, config := newJDCloudRemote(t, fake)
	_, err := remote.Mutate(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600, Line: LineOverseas})
	assertRemoteError(t, err, CodeLineNotInPlan)
	fake.freePlan = false
	if _, err := remote.Mutate(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600, Line: LineOverseas}); err != nil {
		t.Fatalf("overseas on enterprise plan: %v", err)
	}
	if last := fake.creates[len(fake.creates)-1]; last["viewValue"] != float64(4) {
		t.Fatalf("overseas view = %v", last)
	}
}

// A paused record of the owner is not the answer: the create conflicts.
func TestJDCloudPausedRecordConflicts(t *testing.T) {
	fake := newJDCloudFake(t)
	fake.add("www", "A", "192.0.2.10", 600, -1, "4")
	_, remote, config := newJDCloudRemote(t, fake)
	lookup, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600})
	if err != nil || lookup.TargetComplete || !lookup.Conflict {
		t.Fatalf("lookup = %+v, %v", lookup, err)
	}
}

func TestJDCloudErrorMapping(t *testing.T) {
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600}
	for _, test := range []struct {
		name    string
		badKey  bool
		status  int
		errCode int
		domains []string
		want    ErrorCode
	}{
		{name: "bad signature", badKey: true, want: CodeCredentialsRejected},
		{name: "forbidden", status: http.StatusForbidden, want: CodeCredentialsRejected},
		{name: "rate limited", status: http.StatusTooManyRequests, want: CodeRateLimited},
		{name: "unavailable", status: http.StatusServiceUnavailable, want: CodeUnavailable},
		{name: "error on http 200", errCode: http.StatusForbidden, want: CodeCredentialsRejected},
		{name: "zone not in account", domains: []string{"other.test"}, want: CodeZoneNotHosted},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newJDCloudFake(t)
			fake.status, fake.errCode = test.status, test.errCode
			if test.domains != nil {
				fake.domains = test.domains
			}
			_, remote, config := newJDCloudRemote(t, fake)
			if test.badKey {
				config.Credentials["access_key_secret"] = "WRONG-SECRET"
			}
			_, err := remote.Lookup(t.Context(), config, create)
			assertRemoteError(t, err, test.want)
		})
	}
}

func TestJDCloudResolveZoneApex(t *testing.T) {
	fake := newJDCloudFake(t)
	fake.domains = []string{"other.test", testZone}
	_, remote, config := newJDCloudRemote(t, fake)
	apex, err := remote.ResolveZoneApex(t.Context(), providerJDCloud, config.Credentials, "cdn."+testZone)
	if err != nil || apex != testZone {
		t.Fatalf("ResolveZoneApex = %q, %v", apex, err)
	}
}
