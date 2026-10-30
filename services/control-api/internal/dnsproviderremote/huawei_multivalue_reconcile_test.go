package dnsproviderremote

import (
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// huaweiZoneFake is a Huawei DNS zone holding one record set per
// name+type (the provider's model). Without search_mode=equal its name
// filters are fuzzy, as the Huawei Cloud API documents (default "like").
type huaweiZoneFake struct {
	t       *testing.T
	mu      sync.Mutex
	sets    map[string]map[string]any
	nextID  int
	posts   int
	puts    int
	deletes int
}

func (fake *huaweiZoneFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	query := r.URL.Query()
	matches := func(name, wanted string) bool {
		if query.Get("search_mode") == "equal" {
			return name == wanted
		}
		return strings.Contains(name, strings.TrimSuffix(wanted, "."))
	}
	const base = "/v2.1/zones/zone-hw/recordsets"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v2/zones":
		zones := []any{}
		for _, name := range []string{"example.test.", "sub.example.test.", "myexample.test."} {
			if matches(name, query.Get("name")) {
				zones = append(zones, map[string]any{"id": "zone-" + strings.ReplaceAll(strings.TrimSuffix(name, "."), ".", "-"), "name": name})
			}
		}
		if len(zones) > 0 && zones[0].(map[string]any)["name"] == "example.test." {
			zones[0].(map[string]any)["id"] = "zone-hw"
		}
		writeTestJSON(fake.t, w, map[string]any{"zones": zones, "metadata": map[string]any{"total_count": len(zones)},
			"links": map[string]any{"next": ""}})
	case r.Method == http.MethodGet && r.URL.Path == base:
		sets := []any{}
		ids := make([]string, 0, len(fake.sets))
		for id := range fake.sets {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			set := fake.sets[id]
			if matches(set["name"].(string), query.Get("name")) && (query.Get("type") == "" || set["type"] == query.Get("type")) {
				sets = append(sets, set)
			}
		}
		writeTestJSON(fake.t, w, map[string]any{"recordsets": sets, "metadata": map[string]any{"total_count": len(sets)},
			"links": map[string]any{"next": ""}})
	case r.Method == http.MethodPost && r.URL.Path == base:
		var body map[string]any
		if err := decodeJSONBody(r, &body); err != nil {
			fake.t.Fatal(err)
		}
		for _, set := range fake.sets {
			if set["name"] == body["name"] && set["type"] == body["type"] {
				// Huawei allows one record set per name, type and line.
				w.WriteHeader(http.StatusBadRequest)
				writeTestJSON(fake.t, w, map[string]any{"code": "DNS.0312", "message": "record set exists"})
				return
			}
		}
		fake.posts++
		fake.nextID++
		id := "rs-" + string(rune('0'+fake.nextID))
		set := map[string]any{"id": id, "zone_id": "zone-hw", "name": body["name"], "type": body["type"],
			"ttl": body["ttl"], "records": body["records"]}
		fake.sets[id] = set
		w.WriteHeader(http.StatusAccepted)
		writeTestJSON(fake.t, w, set)
	case strings.HasPrefix(r.URL.Path, base+"/"):
		id := strings.TrimPrefix(r.URL.Path, base+"/")
		set, ok := fake.sets[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeTestJSON(fake.t, w, set)
		case http.MethodPut:
			var body map[string]any
			if err := decodeJSONBody(r, &body); err != nil {
				fake.t.Fatal(err)
			}
			if body["name"] != set["name"] || body["type"] != set["type"] {
				fake.t.Errorf("PUT changed identity: %+v", body)
			}
			fake.puts++
			set["records"], set["ttl"] = body["records"], body["ttl"]
			w.WriteHeader(http.StatusAccepted)
			writeTestJSON(fake.t, w, set)
		case http.MethodDelete:
			fake.deletes++
			delete(fake.sets, id)
			w.WriteHeader(http.StatusAccepted)
		}
	default:
		fake.t.Errorf("unexpected Huawei request %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

func (fake *huaweiZoneFake) values(name string) []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, set := range fake.sets {
		if set["name"] == name {
			var values []string
			for _, value := range set["records"].([]any) {
				values = append(values, value.(string))
			}
			slices.Sort(values)
			return values
		}
	}
	return nil
}

// FX03: several A values of one owner are one Huawei record set. Reconcile
// merges creates into it, rewrites it on update and delete, and does not
// confuse it with fuzzy-matched names or zones.
func TestHuaweiReconcileMergesMultiValueRecordSet(t *testing.T) {
	fake := &huaweiZoneFake{t: t, sets: map[string]map[string]any{
		// A fuzzy name match ("www.example.test" is contained in it).
		"rs-other": {"id": "rs-other", "zone_id": "zone-hw", "name": "a.www.example.test.", "type": "A", "ttl": 300,
			"records": []any{"198.51.100.1", "198.51.100.2"}},
	}}
	config := completeTestConfig(reconcileHTTPProviderConfig(providerHuawei))
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	remote := &providerReconcileRemote{adapter: adapter}
	const owner = "www.example.test."
	apply := func(operation dnscheck.ProviderOperation) string {
		t.Helper()
		before, err := remote.Lookup(t.Context(), config, operation)
		if err != nil || before.TargetComplete || before.Conflict || before.Ambiguous {
			t.Fatalf("%s %s lookup before = (%+v, %v)", operation.Action, operation.Value, before, err)
		}
		recordID, err := remote.Mutate(t.Context(), config, operation)
		if err != nil {
			t.Fatalf("%s %s mutate: %v", operation.Action, operation.Value, err)
		}
		after, err := remote.Lookup(t.Context(), config, operation)
		if err != nil || !after.TargetComplete || after.Conflict || after.Ambiguous {
			t.Fatalf("%s %s lookup after = (%+v, %v)", operation.Action, operation.Value, after, err)
		}
		if operation.Action != dnscheck.ProviderDelete && after.RecordID != recordID {
			t.Fatalf("record id %q after, mutate returned %q", after.RecordID, recordID)
		}
		return recordID
	}
	create := func(value string) dnscheck.ProviderOperation {
		return dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: owner, Type: dnscheck.RecordA, Value: value, TTL: 300}
	}
	setID := apply(create("192.0.2.10"))
	if second := apply(create("192.0.2.11")); second != setID {
		t.Fatalf("second value created record set %q, want merge into %q", second, setID)
	}
	if got := fake.values(owner); !slices.Equal(got, []string{"192.0.2.10", "192.0.2.11"}) || fake.posts != 1 {
		t.Fatalf("record set = %v after %d POSTs", got, fake.posts)
	}
	apply(dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: setID, Name: owner, Type: dnscheck.RecordA,
		Value: "192.0.2.12", TTL: 300, PreviousValue: "192.0.2.11", PreviousTTL: 300})
	if got := fake.values(owner); !slices.Equal(got, []string{"192.0.2.10", "192.0.2.12"}) {
		t.Fatalf("after update record set = %v", got)
	}
	apply(dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: setID, Name: owner, Type: dnscheck.RecordA,
		Value: "192.0.2.10", TTL: 300})
	if got := fake.values(owner); !slices.Equal(got, []string{"192.0.2.12"}) || fake.deletes != 0 {
		t.Fatalf("after deleting one value record set = %v (deletes %d)", got, fake.deletes)
	}
	apply(dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: setID, Name: owner, Type: dnscheck.RecordA,
		Value: "192.0.2.12", TTL: 300})
	if fake.values(owner) != nil || fake.deletes != 1 {
		t.Fatalf("last value must delete the record set (deletes %d)", fake.deletes)
	}
	if got := fake.values("a.www.example.test."); len(got) != 2 {
		t.Fatalf("fuzzy-matched record set was touched: %v", got)
	}
}

// Every provider: another A/AAAA value of the same owner is a sibling of the
// RRset, not a competing record; a different CNAME target still is.
func TestLookupRecordCreateTreatsAddressSiblingsAsCompatible(t *testing.T) {
	sibling := reconcileRecord{ID: "r1", Name: "www.example.test.", Type: "A", Value: "192.0.2.1", TTL: 300}
	got := lookupRecord([]reconcileRecord{sibling}, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.2", TTL: 300})
	if got.Conflict || got.Ambiguous || got.TargetComplete {
		t.Fatalf("create next to an A sibling = %+v", got)
	}
	cname := reconcileRecord{ID: "r2", Name: "www.example.test.", Type: "CNAME", Value: "a.example.net.", TTL: 300}
	got = lookupRecord([]reconcileRecord{cname}, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordCNAME, Value: "b.example.net.", TTL: 300})
	if !got.Conflict {
		t.Fatalf("create next to another CNAME target = %+v, want conflict", got)
	}
}

// Zone and record listings ask Huawei for exact names (search_mode=equal).
func TestHuaweiZoneLookupUsesExactNameMatch(t *testing.T) {
	fake := &huaweiZoneFake{t: t, sets: map[string]map[string]any{}}
	config := completeTestConfig(reconcileHTTPProviderConfig(providerHuawei))
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	zoneID, err := (&huaweiProvider{adapter: adapter}).zoneID(t.Context(), config)
	if err != nil || zoneID != "zone-hw" {
		t.Fatalf("zoneID() = (%q, %v); sub.example.test / myexample.test must not make it ambiguous", zoneID, err)
	}
	records, err := (&providerReconcileRemote{adapter: adapter}).ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil || len(records) != 0 {
		t.Fatalf("ListZoneRecords() = (%+v, %v)", records, err)
	}
}

// A multi-value record set lists one entry per value with its own ID
// ("<set>/<value>"), so a reconcile snapshot can delete or replace exactly
// one stale value (dnscheck rejects duplicate record IDs).
func TestHuaweiListsMultiValueRecordSetAsDistinctRecords(t *testing.T) {
	fake := &huaweiZoneFake{t: t, sets: map[string]map[string]any{
		"rs-www": {"id": "rs-www", "zone_id": "zone-hw", "name": "www.example.test.", "type": "A", "ttl": 300,
			"records": []any{"192.0.2.10", "192.0.2.11", "192.0.2.12"}},
	}}
	config := completeTestConfig(reconcileHTTPProviderConfig(providerHuawei))
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	remote := &providerReconcileRemote{adapter: adapter}
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil || len(records) != 3 {
		t.Fatalf("ListZoneRecords() = (%+v, %v)", records, err)
	}
	ids := map[string]string{}
	for _, record := range records {
		ids[record.Value] = record.ID
	}
	if len(ids) != 3 || ids["192.0.2.11"] != "rs-www/192.0.2.11" {
		t.Fatalf("record IDs = %v", ids)
	}
	apply := func(operation dnscheck.ProviderOperation) {
		t.Helper()
		before, err := remote.Lookup(t.Context(), config, operation)
		if err != nil || before.TargetComplete || before.Conflict || before.Ambiguous {
			t.Fatalf("%s lookup before = (%+v, %v)", operation.Action, before, err)
		}
		recordID, err := remote.Mutate(t.Context(), config, operation)
		if err != nil || recordID != operation.RecordID {
			t.Fatalf("%s mutate = (%q, %v)", operation.Action, recordID, err)
		}
		after, err := remote.Lookup(t.Context(), config, operation)
		if err != nil || !after.TargetComplete || after.RecordID != operation.RecordID {
			t.Fatalf("%s lookup after = (%+v, %v)", operation.Action, after, err)
		}
	}
	apply(dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: ids["192.0.2.11"], Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 300})
	apply(dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: ids["192.0.2.12"], Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.13", TTL: 300, PreviousValue: "192.0.2.12", PreviousTTL: 300})
	if got := fake.values("www.example.test."); !slices.Equal(got, []string{"192.0.2.10", "192.0.2.13"}) {
		t.Fatalf("record set = %v", got)
	}
}
