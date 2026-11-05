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

// namesiloFake is a Namesilo API double built from the api-reference samples
// (read 2026-11-05): GET /api/<op>?version=1&type=json&key=, reply.code 300,
// FQDN hosts, string-valued fields, a one-record list as a bare object, and
// dnsUpdateRecord answering a new record_id.
type namesiloFake struct {
	t       *testing.T
	mu      sync.Mutex
	nextID  int
	records []map[string]string
	code    string // forced reply code ("": none)
	status  int
	calls   []map[string]string
	domains []string
}

const namesiloTestKey = "fixture-namesilo-key"

func newNamesiloFake(t *testing.T) *namesiloFake { return &namesiloFake{t: t, nextID: 100} }

func (fake *namesiloFake) add(host, recordType, value, ttl string) string {
	fake.nextID++
	id := "rr" + strconv.Itoa(fake.nextID)
	fqdn := testZone
	if host != "" {
		fqdn = host + "." + testZone
	}
	fake.records = append(fake.records, map[string]string{"record_id": id, "type": recordType, "host": fqdn,
		"value": value, "ttl": ttl, "distance": "0"})
	return id
}

func (fake *namesiloFake) index(id string) int {
	return slices.IndexFunc(fake.records, func(record map[string]string) bool { return record["record_id"] == id })
}

func (fake *namesiloFake) reply(w http.ResponseWriter, operation, code string, extra map[string]any) {
	reply := map[string]any{"code": code, "detail": "fixture"}
	if code == "300" {
		reply["code"] = 300 // the samples show a number for success
	}
	for key, value := range extra {
		reply[key] = value
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"request": map[string]string{"operation": operation, "ip": "192.0.2.200"},
		"reply": reply})
}

func (fake *namesiloFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	query := r.URL.Query()
	call := map[string]string{"path": r.URL.Path}
	for key := range query {
		call[key] = query.Get(key)
	}
	fake.calls = append(fake.calls, call)
	if r.Host != "www.namesilo.com" || r.Method != http.MethodGet || query.Get("version") != "1" || query.Get("type") != "json" {
		fake.t.Errorf("request %s %s host=%q query=%v", r.Method, r.URL.Path, r.Host, query)
	}
	operation := r.URL.Path[len("/api/"):]
	if fake.status != 0 {
		w.WriteHeader(fake.status)
		return
	}
	if query.Get("key") != namesiloTestKey {
		fake.reply(w, operation, "110", nil)
		return
	}
	if fake.code != "" {
		fake.reply(w, operation, fake.code, nil)
		return
	}
	if operation != "listDomains" && query.Get("domain") != testZone {
		fake.reply(w, operation, "200", nil)
		return
	}
	switch operation {
	case "dnsListRecords":
		switch len(fake.records) {
		case 0:
			fake.reply(w, operation, "300", nil)
		case 1:
			fake.reply(w, operation, "300", map[string]any{"resource_record": fake.records[0]})
		default:
			fake.reply(w, operation, "300", map[string]any{"resource_record": fake.records})
		}
	case "dnsAddRecord":
		for _, record := range fake.records {
			if record["type"] == query.Get("rrtype") && record["value"] == query.Get("rrvalue") &&
				record["host"] == fqdnOf(query.Get("rrhost")) {
				fake.reply(w, operation, "280", nil)
				return
			}
		}
		id := fake.add(query.Get("rrhost"), query.Get("rrtype"), query.Get("rrvalue"), query.Get("rrttl"))
		fake.reply(w, operation, "300", map[string]any{"record_id": id})
	case "dnsUpdateRecord":
		index := fake.index(query.Get("rrid"))
		if index < 0 {
			fake.reply(w, operation, "280", nil)
			return
		}
		recordType := fake.records[index]["type"]
		fake.records = slices.Delete(fake.records, index, index+1)
		id := fake.add(query.Get("rrhost"), recordType, query.Get("rrvalue"), query.Get("rrttl"))
		fake.reply(w, operation, "300", map[string]any{"record_id": id})
	case "dnsDeleteRecord":
		index := fake.index(query.Get("rrid"))
		if index < 0 {
			fake.reply(w, operation, "280", nil)
			return
		}
		fake.records = slices.Delete(fake.records, index, index+1)
		fake.reply(w, operation, "300", nil)
	case "listDomains":
		page, _ := strconv.Atoi(query.Get("page"))
		size, _ := strconv.Atoi(query.Get("pageSize"))
		entries := []map[string]string{}
		for index := (page - 1) * size; index < len(fake.domains) && index < page*size; index++ {
			entries = append(entries, map[string]string{"domain": fake.domains[index], "created": "2026-01-01"})
		}
		fake.reply(w, operation, "300", map[string]any{"domains": entries,
			"pager": map[string]string{"total": strconv.Itoa(len(fake.domains)), "pageSize": query.Get("pageSize"), "page": query.Get("page")}})
	default:
		fake.reply(w, operation, "107", nil)
	}
}

func fqdnOf(host string) string {
	if host == "" {
		return testZone
	}
	return host + "." + testZone
}

func (fake *namesiloFake) lastCall(path string) map[string]string {
	for index := len(fake.calls) - 1; index >= 0; index-- {
		if fake.calls[index]["path"] == path {
			return fake.calls[index]
		}
	}
	return nil
}

func namesiloTestConfig() ProviderConfig {
	return ProviderConfig{ProviderType: providerNamesilo, ZoneName: testZone,
		Credentials: map[string]string{"key": namesiloTestKey}}
}

func newNamesiloRemote(t *testing.T, fake *namesiloFake) (*Adapter, *providerReconcileRemote, ProviderConfig) {
	config := namesiloTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	return adapter, &providerReconcileRemote{adapter: adapter}, completeTestConfig(config)
}

func TestNamesiloTXTLifecycle(t *testing.T) {
	fake := newNamesiloFake(t)
	adapter, _, config := newNamesiloRemote(t, fake)
	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	add := fake.lastCall("/api/dnsAddRecord")
	if add["rrtype"] != "TXT" || add["rrhost"] != testRelative || add["rrvalue"] != testValue || add["rrttl"] != "3600" ||
		add["key"] != namesiloTestKey {
		t.Fatalf("dnsAddRecord = %v", add)
	}
	requireHandle(t, handle, providerNamesilo, testZone, "rr101")
	challenge := testChallengeWithHandle(handle)
	if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound)
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("second DeleteTXT: %v", err)
	}
	// dnsDeleteRecord of an unknown rrid (280) is success once it is not listed.
	if err := (&namesiloProvider{adapter: adapter}).deleteRecord(t.Context(), config, "rr999"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	// A 280 for a record still listed stays an error.
	fake.add("other", "A", "192.0.2.1", "3600")
	fake.code = "280"
	if err := (&namesiloProvider{adapter: adapter}).deleteRecord(t.Context(), config, "rr102"); ErrorCodeOf(err) != CodeRecordMismatch {
		t.Fatalf("delete refused: %v", err)
	}
}

// Hosts with or without the root dot, and a bare-object one-record list.
func TestNamesiloListShapes(t *testing.T) {
	fake := newNamesiloFake(t)
	fake.add("www", "A", "192.0.2.1", "7207")
	_, remote, config := newNamesiloRemote(t, fake)
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil || len(records) != 1 || records[0].Name != "www.example.test." || records[0].TTL != 7207 {
		t.Fatalf("one record = %+v, %v", records, err)
	}
	fake.records[0]["host"] = "WWW.example.test."
	fake.add("", "CNAME", "edge.example.net", "3600")
	fake.add("*", "A", "192.0.2.9", "3600")
	records, err = remote.ListZoneRecords(t.Context(), config, "")
	if err == nil {
		t.Fatalf("wildcard owner accepted by the strict listing: %+v", records)
	}
	hub := hubRemote{remote: remote}
	listed, skipped, err := hub.ListHubRecords(t.Context(), config, "")
	if err != nil || skipped != 1 || len(listed) != 2 || listed[0].Name != "www.example.test." || listed[1].Value != "edge.example.net." {
		t.Fatalf("hub listing = %+v skipped=%d, %v", listed, skipped, err)
	}
	// A host outside the zone is refused.
	fake.records = append(fake.records, map[string]string{"record_id": "x1", "type": "A", "host": "www.other.test",
		"value": "192.0.2.1", "ttl": "3600"})
	if _, _, err := hub.ListHubRecords(t.Context(), config, ""); ErrorCodeOf(err) != CodeInvalidResponse {
		t.Fatalf("foreign host: %v", err)
	}
}

// dnsUpdateRecord gives the record a new record_id: the post-mutation
// lookup finds the one record holding the target and reports its ID.
func TestNamesiloReconcileCRUD(t *testing.T) {
	fake := newNamesiloFake(t)
	fake.add("", "A", "192.0.2.99", "3600")
	_, remote, config := newNamesiloRemote(t, fake)
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "example.test.",
		Type: dnscheck.RecordAAAA, Value: "2001:db8::1", TTL: 3600}
	recordID, err := remote.Mutate(t.Context(), config, create)
	if err != nil || recordID == "" {
		t.Fatalf("create = %q, %v", recordID, err)
	}
	if call := fake.lastCall("/api/dnsAddRecord"); call["rrhost"] != "" || call["rrtype"] != "AAAA" {
		t.Fatalf("apex add = %v", call)
	}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup after create = %+v, %v", lookup, err)
	}
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "example.test.",
		Type: dnscheck.RecordAAAA, Value: "2001:db8::2", TTL: 3600, PreviousValue: "2001:db8::1", PreviousTTL: 3600}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before update = %+v, %v", lookup, err)
	}
	newID, err := remote.Mutate(t.Context(), config, update)
	if err != nil || newID == recordID || newID == "" {
		t.Fatalf("update = %q (old %q), %v", newID, recordID, err)
	}
	if call := fake.lastCall("/api/dnsUpdateRecord"); call["rrid"] != recordID || call["rrvalue"] != "2001:db8::2" {
		t.Fatalf("dnsUpdateRecord = %v", call)
	}
	lookup, err := remote.Lookup(t.Context(), config, update)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != newID {
		t.Fatalf("lookup after update = %+v, %v (new %q)", lookup, err, newID)
	}
	// Another record with the same target makes the recovery ambiguous: conflict.
	fake.add("", "AAAA", "2001:db8::2", "3600")
	if lookup, err = remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || !lookup.Conflict {
		t.Fatalf("ambiguous recovery = %+v, %v", lookup, err)
	}
	remove := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: newID, Name: "example.test.",
		Type: dnscheck.RecordAAAA, Value: "2001:db8::2", TTL: 3600}
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	cname := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "cdn.example.test.",
		Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 600}
	if _, err := remote.Mutate(t.Context(), config, cname); err != nil {
		t.Fatalf("create CNAME: %v", err)
	}
	call := fake.lastCall("/api/dnsAddRecord")
	if call["rrvalue"] != "edge.example.net" || call["rrhost"] != "cdn" || call["rrttl"] != "3600" {
		t.Fatalf("CNAME add = %v", call)
	}
	if lookup, err := remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup CNAME at floor = %+v, %v", lookup, err)
	}
}

func TestNamesiloErrorMapping(t *testing.T) {
	for name, test := range map[string]struct {
		code, key string
		status    int
		want      ErrorCode
	}{
		"invalid key":    {key: "wrong", want: CodeCredentialsRejected},
		"ip not allowed": {code: "113", want: CodeCredentialsRejected},
		"processing":     {code: "400", want: CodeRateLimited},
		"registry down":  {code: "115", want: CodeUnavailable},
		"not your zone":  {code: "200", want: CodeZoneNotHosted},
		"general error":  {code: "210", want: CodeInvalidResponse},
		"http 429":       {status: http.StatusTooManyRequests, want: CodeRateLimited},
		"http 502":       {status: http.StatusBadGateway, want: CodeUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newNamesiloFake(t)
			fake.code, fake.status = test.code, test.status
			_, remote, config := newNamesiloRemote(t, fake)
			if test.key != "" {
				config.Credentials["key"] = test.key
			}
			_, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
				Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 3600})
			assertRemoteError(t, err, test.want)
			if err != nil && strings.Contains(err.Error(), namesiloTestKey) {
				t.Fatalf("error leaks the key: %v", err)
			}
		})
	}
}

func TestNamesiloHostedDomains(t *testing.T) {
	fake := newNamesiloFake(t)
	for index := 0; index < zoneApexPageSize+1; index++ {
		fake.domains = append(fake.domains, "zone"+strconv.Itoa(index)+".test")
	}
	fake.domains = append(fake.domains, testZone)
	_, remote, config := newNamesiloRemote(t, fake)
	apex, err := remote.ResolveZoneApex(t.Context(), providerNamesilo, config.Credentials, "cdn."+testZone)
	if err != nil || apex != testZone {
		t.Fatalf("apex = %q, %v", apex, err)
	}
}
