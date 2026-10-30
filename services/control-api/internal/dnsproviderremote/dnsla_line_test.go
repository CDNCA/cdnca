package dnsproviderremote

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

const (
	dnsLATelecomLineID  = "84613316902921216"
	dnsLAMobileLineID   = "84613316953252864"
	dnsLAOverseasLineID = "84613317016167424"
)

// dnsLALineZone serves recordList over two pages: page 1 holds 100 records on
// the default line and on an unmapped province line, page 2 the telecom one.
type dnsLALineZone struct {
	t      *testing.T
	mu     sync.Mutex
	pages  []int
	bodies []string
	calls  []string
	lineID string
}

func (zone *dnsLALineZone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zone.mu.Lock()
	defer zone.mu.Unlock()
	if r.Header.Get("Authorization") != "Basic "+basicAuth("provider-id", "provider-secret") {
		zone.t.Errorf("unauthenticated %s %s", r.Method, r.URL.RequestURI())
	}
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/domain":
		writeTestJSON(zone.t, w, map[string]any{"code": 200, "data": map[string]any{"id": "zone-dnsla", "domain": testZone}})
	case r.Method == http.MethodGet && r.URL.Path == "/api/recordList":
		page, _ := strconv.Atoi(query.Get("pageIndex"))
		zone.pages = append(zone.pages, page)
		if query.Get("domainId") != "zone-dnsla" || query.Get("host") != "www" || query.Get("pageSize") != "100" ||
			query.Get("lineId") != "" || (query.Get("type") != "" && query.Get("type") != "1") {
			zone.t.Errorf("recordList query = %s", r.URL.RawQuery)
		}
		record := func(id, value, lineID, lineCode string) map[string]any {
			return map[string]any{"id": id, "domainId": "zone-dnsla", "host": "www", "type": 1, "data": value,
				"ttl": 300, "lineId": lineID, "lineCode": lineCode, "lineName": "", "weight": 1}
		}
		results := []any{}
		if page == 1 {
			for index := range 100 {
				lineID, lineCode := "", ""
				if index == 0 {
					lineID, lineCode = "84613320933647360", "cnshhdgtele"
				}
				results = append(results, record("default-"+strconv.Itoa(index), "198.51.100."+strconv.Itoa(index+1), lineID, lineCode))
			}
		} else {
			results = append(results, record("telecom-1", "192.0.2.10", zone.lineID, "tele"))
		}
		writeTestJSON(zone.t, w, map[string]any{"code": 200, "msg": "", "data": map[string]any{"total": 101, "results": results}})
	case r.Method == http.MethodPost && r.URL.Path == "/api/record", r.Method == http.MethodPut && r.URL.Path == "/api/record":
		body, _ := io.ReadAll(r.Body)
		zone.calls = append(zone.calls, r.Method+" "+r.URL.RequestURI())
		zone.bodies = append(zone.bodies, string(bytes.TrimSpace(body)))
		writeTestJSON(zone.t, w, map[string]any{"code": 200, "msg": "", "data": map[string]any{"id": "telecom-1"}})
	case r.Method == http.MethodDelete && r.URL.Path == "/api/record":
		zone.calls = append(zone.calls, r.Method+" "+r.URL.RequestURI())
		writeTestJSON(zone.t, w, map[string]any{"code": 200, "msg": "", "data": true})
	default:
		zone.t.Errorf("unexpected DNS.LA request %s %s", r.Method, r.URL.RequestURI())
		w.WriteHeader(http.StatusNotFound)
	}
}

func newDNSLALineRemote(t *testing.T) (*dnsLALineZone, *providerReconcileRemote, ProviderConfig) {
	zone := &dnsLALineZone{t: t, lineID: dnsLATelecomLineID}
	config := reconcileHTTPProviderConfig(providerDNSLA)
	providerAdapter, _ := newProviderTestAdapter(t, config, zone, time.Second)
	return zone, &providerReconcileRemote{adapter: providerAdapter}, completeTestConfig(config)
}

func TestDNSLALineLookupSeesOnlyItsLineAcrossPages(t *testing.T) {
	zone, remote, config := newDNSLALineRemote(t)
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineTelecom}
	lookup, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "telecom-1" {
		t.Fatalf("telecom Lookup() = (%+v, %v)", lookup, err)
	}
	if len(zone.pages) != 2 || zone.pages[0] != 1 || zone.pages[1] != 2 {
		t.Fatalf("pages = %v, want [1 2]", zone.pages)
	}
	operation.Line = LineDefault
	if lookup, err = remote.Lookup(t.Context(), config, operation); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("default Lookup() of a telecom value = (%+v, %v), want absent", lookup, err)
	}
	operation.Value = "198.51.100.1" // on the unmapped Shanghai-telecom line
	if lookup, err = remote.Lookup(t.Context(), config, operation); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("default Lookup() of a province-line value = (%+v, %v), want absent", lookup, err)
	}
	operation.Value = "198.51.100.2"
	if lookup, err = remote.Lookup(t.Context(), config, operation); err != nil || !lookup.TargetComplete || lookup.RecordID != "default-1" {
		t.Fatalf("default Lookup() = (%+v, %v)", lookup, err)
	}

	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: "telecom-1", Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineMobile,
		PreviousValue: "192.0.2.10", PreviousTTL: 300, PreviousLine: LineTelecom}
	if lookup, err = remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("pre-update Lookup() = (%+v, %v)", lookup, err)
	}
	zone.lineID = dnsLAMobileLineID
	if lookup, err = remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete {
		t.Fatalf("post-update Lookup() = (%+v, %v)", lookup, err)
	}
}

func TestDNSLALineMutationsSendLineID(t *testing.T) {
	zone, remote, config := newDNSLALineRemote(t)
	base := dnscheck.ProviderOperation{Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}
	create := base
	create.Action, create.Line = dnscheck.ProviderCreate, LineOverseas
	defaultCreate := base
	defaultCreate.Action = dnscheck.ProviderCreate
	update := base
	update.Action, update.RecordID, update.Line = dnscheck.ProviderUpdate, "telecom-1", LineMobile
	update.PreviousValue, update.PreviousTTL, update.PreviousLine = "192.0.2.10", 300, LineTelecom
	remove := base
	remove.Action, remove.RecordID, remove.Line = dnscheck.ProviderDelete, "default-0", "dns_la:cnshhdgtele"
	for _, operation := range []dnscheck.ProviderOperation{create, defaultCreate, update, remove} {
		if _, err := remote.Mutate(t.Context(), config, operation); err != nil {
			t.Fatalf("Mutate(%s %q) error = %v", operation.Action, operation.Line, err)
		}
	}
	wantCalls := []string{"POST /api/record", "POST /api/record", "PUT /api/record?id=telecom-1", "DELETE /api/record?id=default-0"}
	if len(zone.calls) != len(wantCalls) {
		t.Fatalf("calls = %v, want %v", zone.calls, wantCalls)
	}
	for index, call := range wantCalls {
		if zone.calls[index] != call {
			t.Fatalf("call %d = %q, want %q", index, zone.calls[index], call)
		}
	}
	marshal := func(value map[string]any) string {
		encoded, _ := json.Marshal(value)
		return string(encoded)
	}
	wantBodies := []string{
		marshal(map[string]any{"domainId": "zone-dnsla", "type": 1, "host": "www", "data": "192.0.2.10", "ttl": 300, "lineId": dnsLAOverseasLineID}),
		marshal(map[string]any{"domainId": "zone-dnsla", "type": 1, "host": "www", "data": "192.0.2.10", "ttl": 300, "lineId": ""}),
		marshal(map[string]any{"domainId": "zone-dnsla", "type": 1, "host": "www", "data": "192.0.2.10", "ttl": 300, "lineId": dnsLAMobileLineID}),
	}
	for index, want := range wantBodies {
		if zone.bodies[index] != want {
			t.Fatalf("body %d = %s, want %s", index, zone.bodies[index], want)
		}
	}
}

func TestDNSLALineUnmappedLineFailsBeforeNetwork(t *testing.T) {
	zone, remote, config := newDNSLALineRemote(t)
	for _, line := range []string{"教育网", "dns_la:cnshhdgtele"} {
		operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
			Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: line}
		if _, err := remote.Mutate(t.Context(), config, operation); ErrorCodeOf(err) != CodeUnsupported {
			t.Fatalf("Mutate(%q) error = %v, want unsupported", line, err)
		}
	}
	if len(zone.calls) != 0 || len(zone.pages) != 0 {
		t.Fatalf("network calls = %v pages %v", zone.calls, zone.pages)
	}
}

func TestDNSLAListZoneRecordsReportsUnifiedLines(t *testing.T) {
	_, remote, config := newDNSLALineRemote(t)
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil {
		t.Fatalf("ListZoneRecords() error = %v", err)
	}
	lines := map[string]string{}
	for _, record := range records {
		lines[record.ID] = record.Line
	}
	if lines["telecom-1"] != LineTelecom || lines["default-1"] != LineDefault || lines["default-0"] != "dns_la:cnshhdgtele" {
		t.Fatalf("lines = telecom-1:%q default-1:%q default-0:%q", lines["telecom-1"], lines["default-1"], lines["default-0"])
	}
}
