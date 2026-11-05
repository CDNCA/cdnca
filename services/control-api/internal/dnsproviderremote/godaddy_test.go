package dnsproviderremote

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// goDaddyFake is a GoDaddy Domains v1 double built from domains-v1.json
// (read 2026-11-05): "sso-key KEY:SECRET", relative names ("@" apex), no
// record IDs, GET zone with offset/limit, GET/PUT/DELETE by type+name, PATCH
// append (duplicate refused with 422), 429 ErrorLimit {retryAfterSec}.
type goDaddyFake struct {
	t        *testing.T
	mu       sync.Mutex
	records  []goDaddyRecord
	status   int
	body     string
	ignorePg bool // answer the whole zone whatever offset/limit say
	offsets  []string
	patches  [][]goDaddyRecord
	puts     [][]goDaddyRecord
	deletes  []string
	domains  []string
	markers  []string
}

const (
	goDaddyTestKey    = "fixture-key"
	goDaddyTestSecret = "fixture-secret"
)

func newGoDaddyFake(t *testing.T) *goDaddyFake { return &goDaddyFake{t: t} }

func (fake *goDaddyFake) add(name, recordType, data string, ttl uint32) {
	fake.records = append(fake.records, goDaddyRecord{Data: data, Name: name, TTL: ttl, Type: recordType})
}

func (fake *goDaddyFake) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fake.t.Errorf("encode: %v", err)
	}
}

func (fake *goDaddyFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if r.Host != "api.godaddy.com" {
		fake.t.Errorf("Host = %q", r.Host)
	}
	if r.Header.Get("Authorization") != "sso-key "+goDaddyTestKey+":"+goDaddyTestSecret {
		fake.writeJSON(w, http.StatusUnauthorized, map[string]string{"code": "UNABLE_TO_AUTHENTICATE", "message": "fixture"})
		return
	}
	if fake.status != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fake.status)
		_, _ = io.WriteString(w, fake.body)
		return
	}
	if r.URL.Path == "/v1/domains" {
		fake.markers = append(fake.markers, r.URL.Query().Get("marker"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		start := 0
		if marker := r.URL.Query().Get("marker"); marker != "" {
			start = slices.Index(fake.domains, marker) + 1
		}
		page := []map[string]string{}
		for index := start; index < len(fake.domains) && len(page) < limit; index++ {
			page = append(page, map[string]string{"domain": fake.domains[index], "status": "ACTIVE"})
		}
		fake.writeJSON(w, http.StatusOK, page)
		return
	}
	prefix := "/v1/domains/" + testZone + "/records"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		fake.writeJSON(w, http.StatusNotFound, map[string]string{"code": "NOT_FOUND", "message": "Domain not found"})
		return
	}
	rest := strings.Split(strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/"), "/")
	switch {
	case rest[0] == "" && r.Method == http.MethodGet:
		fake.offsets = append(fake.offsets, r.URL.Query().Get("offset"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		page := []goDaddyRecord{}
		for index, record := range fake.records {
			if fake.ignorePg || index >= offset && index < offset+limit {
				page = append(page, record)
			}
		}
		fake.writeJSON(w, http.StatusOK, page)
	case rest[0] == "" && r.Method == http.MethodPatch:
		var body []goDaddyRecord
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil {
			fake.writeJSON(w, http.StatusBadRequest, map[string]string{"code": "INVALID_BODY"})
			return
		}
		fake.patches = append(fake.patches, body)
		for _, record := range body {
			for _, existing := range fake.records {
				if existing.Type == record.Type && strings.EqualFold(existing.Name, record.Name) && existing.Data == record.Data {
					fake.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"code": "DUPLICATE_RECORD"})
					return
				}
			}
			if record.TTL < 600 {
				fake.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"code": "INVALID_BODY", "message": "ttl"})
				return
			}
			fake.records = append(fake.records, record)
		}
		w.WriteHeader(http.StatusOK)
	case len(rest) == 2:
		recordType, name := rest[0], rest[1]
		same := func(record goDaddyRecord) bool {
			return record.Type == recordType && strings.EqualFold(record.Name, name)
		}
		switch r.Method {
		case http.MethodGet:
			set := []goDaddyRecord{}
			for _, record := range fake.records {
				if same(record) {
					set = append(set, record)
				}
			}
			fake.writeJSON(w, http.StatusOK, set)
		case http.MethodPut:
			var body []goDaddyRecord
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				fake.writeJSON(w, http.StatusBadRequest, map[string]string{"code": "INVALID_BODY"})
				return
			}
			fake.puts = append(fake.puts, body)
			fake.records = slices.DeleteFunc(fake.records, same)
			for _, record := range body {
				if record.Name != "" || record.Type != "" {
					fake.t.Errorf("PUT by type+name carries name/type: %+v", record)
				}
				fake.records = append(fake.records, goDaddyRecord{Data: record.Data, Name: name, TTL: record.TTL, Type: recordType})
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			fake.deletes = append(fake.deletes, recordType+"/"+name)
			fake.records = slices.DeleteFunc(fake.records, same)
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func goDaddyTestConfig() ProviderConfig {
	return ProviderConfig{ProviderType: providerGoDaddy, ZoneName: testZone,
		Credentials: map[string]string{"api_key": goDaddyTestKey, "api_secret": goDaddyTestSecret}}
}

func newGoDaddyRemote(t *testing.T, fake *goDaddyFake) (*Adapter, *providerReconcileRemote, ProviderConfig) {
	config := goDaddyTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	return adapter, &providerReconcileRemote{adapter: adapter}, completeTestConfig(config)
}

func TestGoDaddyRecordIDs(t *testing.T) {
	if got := goDaddyRecordID("A", "www", "192.0.2.1", 1); got != "A/www" {
		t.Fatalf("single = %q", got)
	}
	multi := goDaddyRecordID("A", "www", "192.0.2.1", 2)
	recordType, name, key, ok := splitGoDaddyRecordID(multi)
	if !ok || recordType != "A" || name != "www" || key != goDaddyValueKey("192.0.2.1") {
		t.Fatalf("split(%q) = %q %q %q %v", multi, recordType, name, key, ok)
	}
	for _, bad := range []string{"", "A", "A/", "/www", "A/www/", "A/b/c/d"} {
		if _, _, _, ok := splitGoDaddyRecordID(bad); ok {
			t.Errorf("split(%q) accepted", bad)
		}
	}
}

// Two challenges of one owner share the TXT set; each handle names its value.
func TestGoDaddyTXTLifecycle(t *testing.T) {
	fake := newGoDaddyFake(t)
	fake.add(testRelative, "TXT", testOtherValue, 600)
	adapter, _, _ := newGoDaddyRemote(t, fake)
	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	if len(fake.patches) != 1 || fake.patches[0][0] != (goDaddyRecord{Data: testValue, Name: testRelative, TTL: 600, Type: "TXT"}) {
		t.Fatalf("PATCH = %+v", fake.patches)
	}
	requireHandle(t, handle, providerGoDaddy, testZone, "TXT/"+testRelative+"/"+goDaddyValueKey(testValue))
	challenge := testChallengeWithHandle(handle)
	if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	// The other challenge's value stays (PUT of the reduced set, no DELETE).
	if len(fake.records) != 1 || fake.records[0].Data != testOtherValue || len(fake.deletes) != 0 {
		t.Fatalf("records = %+v deletes = %v", fake.records, fake.deletes)
	}
	assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound)
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("second DeleteTXT: %v", err)
	}
	handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
	if err != nil || found {
		t.Fatalf("RecoverTXT after delete = %v, %v", found, err)
	}
	_ = handle
}

func TestGoDaddyReconcileCRUD(t *testing.T) {
	fake := newGoDaddyFake(t)
	fake.add("@", "A", "192.0.2.99", 600)
	fake.add("@", "NS", "ns01.domaincontrol.com", 3600)
	_, remote, config := newGoDaddyRemote(t, fake)
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before create = %+v, %v", lookup, err)
	}
	recordID, err := remote.Mutate(t.Context(), config, create)
	if err != nil || recordID != "A/www" {
		t.Fatalf("create = %q, %v", recordID, err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || !lookup.TargetComplete || lookup.RecordID != "A/www" {
		t.Fatalf("lookup after create = %+v, %v", lookup, err)
	}
	// A second A value of the owner is a sibling: both get value-named IDs.
	sibling := create
	sibling.Value = "192.0.2.20"
	siblingID, err := remote.Mutate(t.Context(), config, sibling)
	if err != nil || siblingID != "A/www/"+goDaddyValueKey("192.0.2.20") {
		t.Fatalf("sibling = %q, %v", siblingID, err)
	}
	// Update the first value: the set is rewritten with the sibling kept.
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600, PreviousValue: "192.0.2.10", PreviousTTL: 600}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before update = %+v, %v", lookup, err)
	}
	if got, err := remote.Mutate(t.Context(), config, update); err != nil || got != recordID {
		t.Fatalf("update = %q, %v", got, err)
	}
	last := fake.puts[len(fake.puts)-1]
	if len(last) != 2 || last[0].Data != "192.0.2.20" || last[1].Data != "192.0.2.11" || last[1].TTL != 600 {
		t.Fatalf("PUT set = %+v", last)
	}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after update = %+v, %v", lookup, err)
	}
	// Updating a value that is gone is a mismatch, not a blind write.
	stale := update
	stale.PreviousValue = "198.51.100.1"
	if _, err := remote.Mutate(t.Context(), config, stale); ErrorCodeOf(err) != CodeRecordMismatch {
		t.Fatalf("stale update: %v", err)
	}
	cname := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "cdn.example.test.",
		Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 600}
	if _, err := remote.Mutate(t.Context(), config, cname); err != nil {
		t.Fatalf("create CNAME: %v", err)
	}
	if patch := fake.patches[len(fake.patches)-1][0]; patch.Data != "edge.example.net" || patch.Name != "cdn" {
		t.Fatalf("CNAME PATCH = %+v", patch)
	}
	if lookup, err := remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup CNAME = %+v, %v", lookup, err)
	}
	// Delete both A values: the last one deletes the set.
	for _, value := range []string{"192.0.2.20", "192.0.2.11"} {
		remove := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: "A/www", Name: "www.example.test.",
			Type: dnscheck.RecordA, Value: value, TTL: 600}
		if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
			t.Fatalf("delete %s: %v", value, err)
		}
		if lookup, err := remote.Lookup(t.Context(), config, remove); err != nil || !lookup.TargetComplete {
			t.Fatalf("lookup after delete = %+v, %v", lookup, err)
		}
	}
	if !slices.Equal(fake.deletes, []string{"A/www"}) {
		t.Fatalf("deletes = %v", fake.deletes)
	}
	zone, err := remote.ListZoneRecords(t.Context(), config, "")
	if err != nil || len(zone) != 2 || zone[0].Name != "example.test." || zone[1].Value != "edge.example.net." {
		t.Fatalf("zone = %+v, %v", zone, err)
	}
}

func TestGoDaddyClampsTTLToFloor(t *testing.T) {
	fake := newGoDaddyFake(t)
	_, remote, config := newGoDaddyRemote(t, fake)
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "site.example.test.",
		Type: dnscheck.RecordA, Value: "0.0.0.0", TTL: 60}
	if _, err := remote.Mutate(t.Context(), config, operation); err != nil {
		t.Fatalf("create: %v", err)
	}
	if fake.patches[0][0].TTL != 600 {
		t.Fatalf("written TTL = %d", fake.patches[0][0].TTL)
	}
	if lookup, err := remote.Lookup(t.Context(), config, operation); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup = %+v, %v", lookup, err)
	}
}

// The zone listing pages with offset/limit; a server ignoring paging (a
// repeated record) is refused.
func TestGoDaddyListPaging(t *testing.T) {
	fake := newGoDaddyFake(t)
	for index := 0; index < goDaddyPageSize+10; index++ {
		fake.add("h"+strconv.Itoa(index), "A", "192.0.2.1", 600)
	}
	_, remote, config := newGoDaddyRemote(t, fake)
	records, err := remote.ListZoneRecords(t.Context(), config, "")
	if err != nil || len(records) != goDaddyPageSize+10 || !slices.Equal(fake.offsets, []string{"0", "500"}) {
		t.Fatalf("records = %d offsets = %v, %v", len(records), fake.offsets, err)
	}
	fake.ignorePg = true
	if _, err := remote.ListZoneRecords(t.Context(), config, ""); ErrorCodeOf(err) != CodeRecordMismatch {
		t.Fatalf("ignored paging: %v", err)
	}
}

func TestGoDaddyErrorMapping(t *testing.T) {
	for name, test := range map[string]struct {
		status     int
		body       string
		badAuth    bool
		want       ErrorCode
		retryAfter time.Duration
	}{
		"bad key":   {badAuth: true, want: CodeCredentialsRejected},
		"403":       {status: http.StatusForbidden, body: `{"code":"ACCESS_DENIED"}`, want: CodeCredentialsRejected},
		"429 body":  {status: http.StatusTooManyRequests, body: `{"code":"TOO_MANY_REQUESTS","retryAfterSec":42}`, want: CodeRateLimited, retryAfter: 42 * time.Second},
		"429 bare":  {status: http.StatusTooManyRequests, want: CodeRateLimited},
		"409":       {status: http.StatusConflict, body: `{"code":"INELIGIBLE"}`, want: CodeUnsupported},
		"422":       {status: http.StatusUnprocessableEntity, body: `{"code":"INVALID_BODY"}`, want: CodeInvalidInput},
		"504":       {status: http.StatusGatewayTimeout, want: CodeUnavailable},
		"404 write": {status: http.StatusNotFound, body: `{"code":"NOT_FOUND"}`, want: CodeZoneNotHosted},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newGoDaddyFake(t)
			fake.status, fake.body = test.status, test.body
			_, remote, config := newGoDaddyRemote(t, fake)
			if test.badAuth {
				config.Credentials["api_secret"] = "wrong"
			}
			err := (&goDaddyProvider{adapter: remote.adapter}).appendRecord(t.Context(), config,
				goDaddyRecord{Data: "192.0.2.1", Name: "www", TTL: 600, Type: "A"})
			assertRemoteError(t, err, test.want)
			var remoteErr *Error
			if test.want == CodeRateLimited && (!errorAs(err, &remoteErr) || remoteErr.RetryAfter != test.retryAfter) {
				t.Fatalf("rate limit = %+v", remoteErr)
			}
		})
	}
	// RateLimit-Reset is the fallback wait.
	response := httpResponse{status: http.StatusTooManyRequests, header: http.Header{"Ratelimit-Reset": {"1399"}}}
	if got := goDaddyRetryAfter(response); got != 1399*time.Second {
		t.Fatalf("RateLimit-Reset wait = %v", got)
	}
}

func TestGoDaddyHostedDomainsMarker(t *testing.T) {
	fake := newGoDaddyFake(t)
	for index := 0; index < zoneApexPageSize+2; index++ {
		fake.domains = append(fake.domains, "zone"+strconv.Itoa(index)+".test")
	}
	fake.domains = append(fake.domains, testZone)
	_, remote, config := newGoDaddyRemote(t, fake)
	apex, err := remote.ResolveZoneApex(t.Context(), providerGoDaddy, config.Credentials, "a.cdn."+testZone)
	if err != nil || apex != testZone {
		t.Fatalf("apex = %q, %v", apex, err)
	}
	if len(fake.markers) != 2 || fake.markers[0] != "" || fake.markers[1] != "zone49.test" {
		t.Fatalf("markers = %v", fake.markers)
	}
}
