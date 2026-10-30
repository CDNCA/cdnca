package dnsproviderremote

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// Test-only credentials; the fake server below accepts nothing else. No
// request leaves the httptest server (endpoints point at it).
const (
	nameComTestUser  = "fixture-user"
	nameComTestToken = "fixture-token"
)

// nameComFake is a name.com Core API (/core/v1) double: Basic auth, zone
// records with numeric ids, perPage/page paging with totalCount/from/to/
// nextPage, PUT full replacement, DELETE 204, and the TTL floor 300.
type nameComFake struct {
	t        *testing.T
	mu       sync.Mutex
	nextID   int
	records  map[int]map[string]any
	order    []int
	status   int // forced status for every call (0: none)
	reset    string
	pages    []int // page numbers requested by GET list
	perPages []string
	deleted  []string
	puts     []map[string]any
	posts    []map[string]any
}

func newNameComFake(t *testing.T) *nameComFake {
	return &nameComFake{t: t, nextID: 1000, records: map[int]map[string]any{}}
}

func (fake *nameComFake) add(host, recordType, answer string, ttl int) int {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.nextID++
	id := fake.nextID
	fqdn := testZone + "."
	if host != "" && host != "@" {
		fqdn = host + "." + fqdn
	}
	fake.records[id] = map[string]any{
		"id": id, "domainName": testZone, "host": host, "fqdn": fqdn, "type": recordType, "answer": answer, "ttl": ttl,
	}
	fake.order = append(fake.order, id)
	return id
}

func (fake *nameComFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if r.Host != "api.name.com" {
		fake.t.Errorf("Host = %q", r.Host)
	}
	if user, token, ok := r.BasicAuth(); !ok || user != nameComTestUser || token != nameComTestToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Unauthorized"}`))
		return
	}
	if fake.status != 0 {
		if fake.reset != "" {
			w.Header().Set("X-RateLimit-Reset", fake.reset)
		}
		w.WriteHeader(fake.status)
		_, _ = w.Write([]byte(`{"message":"forced","details":"fixture"}`))
		return
	}
	prefix := "/core/v1/domains/" + testZone + "/records"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		fake.notFound(w)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	if rest == "" {
		switch r.Method {
		case http.MethodGet:
			fake.list(w, r)
		case http.MethodPost:
			if r.Header.Get("Content-Type") != "application/json" {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
			body := fake.decode(r)
			fake.posts = append(fake.posts, body)
			fake.nextID++
			id := fake.nextID
			fake.store(id, body)
			fake.order = append(fake.order, id)
			fake.writeJSON(w, fake.records[id])
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	id, err := strconv.Atoi(strings.TrimPrefix(rest, "/"))
	if err != nil {
		fake.notFound(w)
		return
	}
	record, exists := fake.records[id]
	switch r.Method {
	case http.MethodGet:
		if !exists {
			fake.notFound(w)
			return
		}
		fake.writeJSON(w, record)
	case http.MethodPut:
		if !exists {
			fake.notFound(w)
			return
		}
		body := fake.decode(r)
		fake.puts = append(fake.puts, body)
		fake.store(id, body)
		fake.writeJSON(w, fake.records[id])
	case http.MethodDelete:
		fake.deleted = append(fake.deleted, strconv.Itoa(id))
		if !exists {
			fake.notFound(w)
			return
		}
		delete(fake.records, id)
		fake.order = slices.DeleteFunc(fake.order, func(value int) bool { return value == id })
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (fake *nameComFake) decode(r *http.Request) map[string]any {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fake.t.Errorf("decode body: %v", err)
	}
	return body
}

// store keeps a full replacement, refusing what name.com refuses.
func (fake *nameComFake) store(id int, body map[string]any) {
	ttl, _ := body["ttl"].(float64)
	if ttl < NameComMinTTL {
		fake.t.Errorf("record %d written with TTL %v below the name.com floor", id, ttl)
	}
	host, _ := body["host"].(string)
	fqdn := testZone + "."
	if host != "" && host != "@" {
		fqdn = host + "." + fqdn
	}
	fake.records[id] = map[string]any{
		"id": id, "domainName": testZone, "host": host, "fqdn": fqdn, "type": body["type"], "answer": body["answer"],
		"ttl": int(ttl),
	}
}

func (fake *nameComFake) list(w http.ResponseWriter, r *http.Request) {
	perPage, _ := strconv.Atoi(r.URL.Query().Get("perPage"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	fake.perPages = append(fake.perPages, r.URL.Query().Get("perPage"))
	fake.pages = append(fake.pages, page)
	if perPage < 1 || page < 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	start := (page - 1) * perPage
	end := min(start+perPage, len(fake.order))
	records := make([]map[string]any, 0, perPage)
	for _, id := range fake.order[min(start, len(fake.order)):end] {
		records = append(records, fake.records[id])
	}
	body := map[string]any{"records": records, "totalCount": len(fake.order), "from": start + 1, "to": start + len(records)}
	if len(records) == 0 {
		body["from"], body["to"] = 0, 0
	}
	if end < len(fake.order) {
		body["nextPage"] = page + 1
		body["lastPage"] = (len(fake.order) + perPage - 1) / perPage
	}
	fake.writeJSON(w, body)
}

func (fake *nameComFake) notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"message":"Not Found","details":"record not found"}`))
}

func (fake *nameComFake) writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fake.t.Errorf("encode: %v", err)
	}
}

func nameComTestConfig() ProviderConfig {
	return ProviderConfig{ProviderType: providerNameCom, ZoneName: testZone,
		Credentials: map[string]string{"username": nameComTestUser, "api_token": nameComTestToken}}
}

func newNameComRemote(t *testing.T, fake *nameComFake) (*Adapter, *providerReconcileRemote, ProviderConfig) {
	config := nameComTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	return adapter, &providerReconcileRemote{adapter: adapter}, completeTestConfig(config)
}

func TestNameComDispatch(t *testing.T) {
	adapter := newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)
	provider, err := adapter.provider(providerNameCom)
	if err != nil {
		t.Fatalf("provider(namecom) = %v", err)
	}
	if _, ok := provider.(*nameComProvider); !ok {
		t.Fatalf("provider(namecom) = %T", provider)
	}
	if !supportedProvider(providerNameCom) {
		t.Fatal("namecom not supported")
	}
	if production := productionEndpoints().namecom; production.baseURL != "https://api.name.com" || production.host != "api.name.com" {
		t.Fatalf("production endpoint = %+v", production)
	}
}

func TestNameComSupportsOnlyDefaultLine(t *testing.T) {
	if got := SupportedLines(providerNameCom); !slices.Equal(got, []string{LineDefault}) {
		t.Fatalf("SupportedLines = %v", got)
	}
	config := completeTestConfig(nameComTestConfig())
	for _, line := range []string{LineTelecom, LineUnicom, LineMobile, LineOverseas} {
		err := validateProviderReconcileOperation(config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
			Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: line})
		assertRemoteError(t, err, CodeUnsupported)
	}
	if err := validateProviderReconcileOperation(config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineDefault}); err != nil {
		t.Fatalf("default line: %v", err)
	}
}

func TestNameComCredentials(t *testing.T) {
	for name, credentials := range map[string]map[string]string{
		"missing token":     {"username": "u"},
		"extra field":       {"username": "u", "api_token": "t", "plan": "free"},
		"colon in username": {"username": "a:b", "api_token": "t"},
		"blank token":       {"username": "u", "api_token": " "},
	} {
		if err := validateCredentials(providerNameCom, credentials); ErrorCodeOf(err) != CodeInvalidInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := validateCredentials(providerNameCom, map[string]string{"username": "u-test", "api_token": "t0k"}); err != nil {
		t.Fatalf("valid credentials: %v", err)
	}
}

func TestNameComEffectiveTTL(t *testing.T) {
	for _, test := range []struct {
		provider  string
		requested uint32
		want      uint32
		clamped   bool
	}{
		{providerNameCom, 60, 300, true},
		{providerNameCom, 299, 300, true},
		{providerNameCom, 300, 300, false},
		{providerNameCom, 600, 600, false},
		{providerCloudflare, 60, 60, false},
	} {
		got, clamped := EffectiveTTL(test.provider, test.requested)
		if got != test.want || clamped != test.clamped {
			t.Errorf("EffectiveTTL(%s, %d) = %d, %v", test.provider, test.requested, got, clamped)
		}
	}
}

// TXT present writes at the floor and reads back; observe/delete use the
// record id; deleting an already deleted record is idempotent.
func TestNameComTXTLifecycle(t *testing.T) {
	fake := newNameComFake(t)
	adapter, _, config := newNameComRemote(t, fake)
	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	if len(fake.posts) != 1 || fake.posts[0]["host"] != "_acme-challenge" || fake.posts[0]["type"] != "TXT" ||
		fake.posts[0]["answer"] != testValue || fake.posts[0]["ttl"] != float64(NameComMinTTL) {
		t.Fatalf("POST bodies = %v", fake.posts)
	}
	requireHandle(t, handle, providerNameCom, testZone, "1001")
	challenge := testChallengeWithHandle(handle)
	if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if len(fake.records) != 0 || !slices.Equal(fake.deleted, []string{"1001"}) {
		t.Fatalf("records = %v deleted = %v", fake.records, fake.deleted)
	}
	// The record is gone: observe reports absence, delete is a no-op.
	assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound)
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("second DeleteTXT: %v", err)
	}
	// Direct delete of a missing id (404) is success too.
	if err := (&nameComProvider{adapter: adapter}).deleteRecord(t.Context(), config, "424242"); err != nil {
		t.Fatalf("delete missing record: %v", err)
	}
}

func TestNameComRecoverTXTPagesWholeZone(t *testing.T) {
	fake := newNameComFake(t)
	for index := 0; index < 2*nameComPageSize+5; index++ {
		fake.add("filler-"+strconv.Itoa(index), "A", "192.0.2.1", 300)
	}
	target := fake.add("_acme-challenge", "TXT", testValue, 300)
	fake.add("_acme-challenge", "TXT", "other-value", 300)
	adapter, _, _ := newNameComRemote(t, fake)
	handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
	if err != nil || !found {
		t.Fatalf("RecoverTXT = %v, %v", found, err)
	}
	requireHandle(t, handle, providerNameCom, testZone, strconv.Itoa(target))
	if !slices.Equal(fake.pages, []int{1, 2, 3}) {
		t.Fatalf("pages = %v", fake.pages)
	}
	for _, perPage := range fake.perPages {
		if perPage != strconv.Itoa(nameComPageSize) {
			t.Fatalf("perPage = %v", fake.perPages)
		}
	}
}

func TestNameComReconcileCRUD(t *testing.T) {
	fake := newNameComFake(t)
	fake.add("", "A", "192.0.2.99", 300) // apex, not the owner
	_, remote, config := newNameComRemote(t, fake)
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600}
	lookup, err := remote.Lookup(t.Context(), config, create)
	if err != nil || lookup.TargetComplete || lookup.Conflict || lookup.Ambiguous {
		t.Fatalf("lookup before create = %+v, %v", lookup, err)
	}
	recordID, err := remote.Mutate(t.Context(), config, create)
	if err != nil || recordID == "" {
		t.Fatalf("create = %q, %v", recordID, err)
	}
	if lookup, err = remote.Lookup(t.Context(), config, create); err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup after create = %+v, %v", lookup, err)
	}

	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600, PreviousValue: "192.0.2.10", PreviousTTL: 600}
	if lookup, err = remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before update = %+v, %v", lookup, err)
	}
	if got, err := remote.Mutate(t.Context(), config, update); err != nil || got != recordID {
		t.Fatalf("update = %q, %v", got, err)
	}
	if last := fake.puts[len(fake.puts)-1]; last["host"] != "www" || last["type"] != "A" || last["answer"] != "192.0.2.11" ||
		last["ttl"] != float64(600) {
		t.Fatalf("PUT body (full replacement) = %v", last)
	}
	if lookup, err = remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after update = %+v, %v", lookup, err)
	}

	cname := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "cdn.example.test.",
		Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 300}
	if _, err := remote.Mutate(t.Context(), config, cname); err != nil {
		t.Fatalf("create CNAME: %v", err)
	}
	if last := fake.posts[len(fake.posts)-1]; last["answer"] != "edge.example.net" || last["host"] != "cdn" {
		t.Fatalf("CNAME POST = %v", last)
	}
	if lookup, err = remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup CNAME = %+v, %v", lookup, err)
	}

	remove := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600}
	if got, err := remote.Mutate(t.Context(), config, remove); err != nil || got != recordID {
		t.Fatalf("delete = %q, %v", got, err)
	}
	if lookup, err = remote.Lookup(t.Context(), config, remove); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after delete = %+v, %v", lookup, err)
	}
	// Deleting it again: 404 from name.com, still success.
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("second delete: %v", err)
	}

	records, err := remote.ListZoneRecords(t.Context(), config, "cdn.example.test.")
	if err != nil || len(records) != 1 || records[0].Type != dnscheck.RecordCNAME || records[0].Value != "edge.example.net." ||
		records[0].Line != LineDefault {
		t.Fatalf("ListZoneRecords = %+v, %v", records, err)
	}
	zone, err := remote.ListZoneRecords(t.Context(), config, "")
	if err != nil || len(zone) != 2 {
		t.Fatalf("zone records = %+v, %v", zone, err)
	}
}

// Attack escalation level D asks for TTL 60: name.com takes no less than
// 300, so the record is written at 300 and the lookup reads it back as the
// target (EffectiveTTL reports ttl_clamped) instead of failing every pass.
func TestNameComReconcileClampsTTLToProviderFloor(t *testing.T) {
	fake := newNameComFake(t)
	_, remote, config := newNameComRemote(t, fake)
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "site.example.test.",
		Type: dnscheck.RecordA, Value: "0.0.0.0", TTL: 60}
	if err := validateProviderReconcileOperation(config, operation); err != nil {
		t.Fatalf("validation: %v", err)
	}
	recordID, err := remote.Mutate(t.Context(), config, operation)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if fake.posts[0]["ttl"] != float64(NameComMinTTL) {
		t.Fatalf("written TTL = %v", fake.posts[0]["ttl"])
	}
	lookup, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup = %+v, %v", lookup, err)
	}
	// An update from TTL 60 (stored 300) to another TTL-60 value also
	// compares at the floor.
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "site.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.5", TTL: 60, PreviousValue: "0.0.0.0", PreviousTTL: 60}
	if lookup, err = remote.Lookup(t.Context(), config, update); err != nil || lookup.Conflict || lookup.TargetComplete {
		t.Fatalf("lookup before update = %+v, %v", lookup, err)
	}
	if _, err := remote.Mutate(t.Context(), config, update); err != nil {
		t.Fatalf("update: %v", err)
	}
	if fake.puts[0]["ttl"] != float64(NameComMinTTL) {
		t.Fatalf("updated TTL = %v", fake.puts[0]["ttl"])
	}
	if lookup, err = remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after update = %+v, %v", lookup, err)
	}
}

func TestNameComErrorMapping(t *testing.T) {
	for _, test := range []struct {
		status     int
		reset      string
		badAuth    bool
		want       ErrorCode
		retryAfter time.Duration
	}{
		{badAuth: true, want: CodeCredentialsRejected},
		{status: http.StatusUnauthorized, want: CodeCredentialsRejected},
		{status: http.StatusForbidden, want: CodeCredentialsRejected},
		{status: http.StatusTooManyRequests, reset: strconv.FormatInt(remoteProviderTestTime.Add(30*time.Second).Unix(), 10),
			want: CodeRateLimited, retryAfter: 30 * time.Second},
		{status: http.StatusTooManyRequests, want: CodeRateLimited},
		{status: http.StatusServiceUnavailable, want: CodeUnavailable},
		{status: http.StatusBadRequest, want: CodeInvalidResponse},
	} {
		t.Run(strconv.Itoa(test.status)+test.reset, func(t *testing.T) {
			fake := newNameComFake(t)
			fake.status, fake.reset = test.status, test.reset
			_, remote, config := newNameComRemote(t, fake)
			if test.badAuth {
				config.Credentials["api_token"] = "wrong-token"
			}
			_, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
				Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300})
			assertRemoteError(t, err, test.want)
			var remoteErr *Error
			if test.want == CodeRateLimited && (!errorAs(err, &remoteErr) || remoteErr.RetryAfter != test.retryAfter || !remoteErr.Temporary) {
				t.Fatalf("rate limit error = %+v", remoteErr)
			}
		})
	}
	// 404 on a record read is absence, not an error.
	fake := newNameComFake(t)
	adapter, _, config := newNameComRemote(t, fake)
	if _, exists, err := (&nameComProvider{adapter: adapter}).get(t.Context(), config,
		recordHandle{ZoneID: testZone, RecordID: "777"}, testValue); err != nil || exists {
		t.Fatalf("get missing = %v, %v", exists, err)
	}
	// 404 on the zone list (domain not in the account) is not absence.
	fake.status = http.StatusNotFound
	if _, err := (&nameComProvider{adapter: adapter}).listRecords(t.Context(), config); ErrorCodeOf(err) != CodeInvalidResponse {
		t.Fatalf("list on unknown domain = %v", err)
	}
}

func errorAs(err error, target **Error) bool {
	value, ok := err.(*Error)
	if ok {
		*target = value
	}
	return ok
}

// A page that skips or repeats records is refused rather than trusted.
func TestNameComRejectsInconsistentPages(t *testing.T) {
	for name, page := range map[string]map[string]any{
		"missing totalCount": {"records": []any{}, "from": 0, "to": 0},
		"next page on last":  {"records": []any{}, "totalCount": 0, "from": 0, "to": 0, "nextPage": 2},
		"short page":         {"records": []any{}, "totalCount": 3, "from": 1, "to": 0, "nextPage": 2},
		"other domain": {"records": []any{map[string]any{"id": 1, "domainName": "other.test", "host": "www",
			"fqdn": "www.other.test.", "type": "A", "answer": "192.0.2.1", "ttl": 300}}, "totalCount": 1, "from": 1, "to": 1},
	} {
		t.Run(name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(page)
			})
			config := nameComTestConfig()
			adapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
			_, err := (&nameComProvider{adapter: adapter}).listRecords(t.Context(), completeTestConfig(config))
			assertRemoteError(t, err, CodeInvalidResponse)
		})
	}
}
