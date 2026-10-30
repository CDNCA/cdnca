package dnsproviderremote

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

// verifyHuaweiBodySignature checks the SDK-HMAC-SHA256 signature over the
// exact request body (verifyRound3HuaweiSignature covers bodiless requests).
func verifyHuaweiBodySignature(request *http.Request, body []byte) bool {
	timestamp := request.Header.Get("X-Sdk-Date")
	payloadDigest := sha256.Sum256(body)
	canonicalURI := request.URL.EscapedPath()
	if !strings.HasSuffix(canonicalURI, "/") {
		canonicalURI += "/"
	}
	headers := "host:" + request.Host + "\nx-project-id:" + request.Header.Get("X-Project-Id") + "\nx-sdk-date:" + timestamp + "\n"
	const signed = "host;x-project-id;x-sdk-date"
	canonical := request.Method + "\n" + canonicalURI + "\n" + request.URL.Query().Encode() + "\n" + headers + "\n" +
		signed + "\n" + hex.EncodeToString(payloadDigest[:])
	canonicalDigest := sha256.Sum256([]byte(canonical))
	mac := hmac.New(sha256.New, []byte("provider-secret"))
	_, _ = mac.Write([]byte("SDK-HMAC-SHA256\n" + timestamp + "\n" + hex.EncodeToString(canonicalDigest[:])))
	return request.Header.Get("Authorization") == "SDK-HMAC-SHA256 Access=provider-key, SignedHeaders="+signed+
		", Signature="+hex.EncodeToString(mac.Sum(nil))
}

// huaweiLineZone holds one record set per name+type+line, as Huawei public
// zones do. The list is served over pages of recoveryPageSize so the
// adapter must walk offsets; a filler owner occupies page 1.
type huaweiLineZone struct {
	t      *testing.T
	mu     sync.Mutex
	sets   []map[string]any
	nextID int
	bodies []map[string]any
	paths  []string
}

func (zone *huaweiLineZone) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	zone.mu.Lock()
	defer zone.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	if r.Header.Get("X-Project-Id") != "0123456789abcdef0123456789abcdef" || !verifyHuaweiBodySignature(r, body) {
		zone.t.Errorf("invalid Huawei signature for %s %s", r.Method, r.URL.RequestURI())
	}
	const base = "/v2.1/zones/zone-hw/recordsets"
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v2/zones":
		writeTestJSON(zone.t, w, map[string]any{"zones": []any{map[string]any{"id": "zone-hw", "name": "example.test."}}})
	case r.Method == http.MethodGet && r.URL.Path == base:
		if query.Get("search_mode") != "equal" || query.Get("limit") != "100" || query.Get("line_id") != "" {
			zone.t.Errorf("list query = %s", r.URL.RawQuery)
		}
		var matching []any
		for _, set := range zone.sets {
			if set["name"] == query.Get("name") && (query.Get("type") == "" || set["type"] == query.Get("type")) {
				matching = append(matching, set)
			}
		}
		offset, _ := strconv.Atoi(query.Get("offset"))
		end := min(offset+recoveryPageSize, len(matching))
		// Huawei (Designate) lists "self" always and "next" only while more
		// pages follow (SDK PageLink.Next is omitempty): the last page has none.
		links := map[string]any{"self": "https://dns.cn-north-4.myhuaweicloud.com" + base + "?" + r.URL.RawQuery}
		if end < len(matching) {
			links["next"] = "https://dns.cn-north-4.myhuaweicloud.com" + base + "?offset=" + strconv.Itoa(end)
		}
		writeTestJSON(zone.t, w, map[string]any{"recordsets": matching[offset:end],
			"metadata": map[string]any{"total_count": len(matching)}, "links": links})
	case r.Method == http.MethodPost && r.URL.Path == base:
		var request map[string]any
		if err := json.Unmarshal(body, &request); err != nil {
			zone.t.Fatal(err)
		}
		zone.bodies, zone.paths = append(zone.bodies, request), append(zone.paths, "POST "+r.URL.Path)
		for _, set := range zone.sets {
			if set["name"] == request["name"] && set["type"] == request["type"] && set["line"] == request["line"] {
				w.WriteHeader(http.StatusBadRequest)
				writeTestJSON(zone.t, w, map[string]any{"code": "DNS.0312", "message": "record set exists"})
				return
			}
		}
		zone.nextID++
		set := map[string]any{"id": "rs-" + strconv.Itoa(zone.nextID), "zone_id": "zone-hw", "name": request["name"],
			"type": request["type"], "ttl": request["ttl"], "records": request["records"], "line": request["line"]}
		zone.sets = append(zone.sets, set)
		w.WriteHeader(http.StatusAccepted)
		writeTestJSON(zone.t, w, set)
	case strings.HasPrefix(r.URL.Path, base+"/"):
		id := strings.TrimPrefix(r.URL.Path, base+"/")
		index := slices.IndexFunc(zone.sets, func(set map[string]any) bool { return set["id"] == id })
		if index < 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		set := zone.sets[index]
		switch r.Method {
		case http.MethodGet:
			writeTestJSON(zone.t, w, set)
		case http.MethodPut:
			var request map[string]any
			if err := json.Unmarshal(body, &request); err != nil {
				zone.t.Fatal(err)
			}
			zone.bodies, zone.paths = append(zone.bodies, request), append(zone.paths, "PUT "+r.URL.Path)
			if _, ok := request["line"]; ok {
				zone.t.Errorf("PUT carries line (UpdateRecordSets has no line): %v", request)
			}
			set["records"], set["ttl"] = request["records"], request["ttl"]
			w.WriteHeader(http.StatusAccepted)
			writeTestJSON(zone.t, w, set)
		case http.MethodDelete:
			zone.paths = append(zone.paths, "DELETE "+r.URL.Path)
			zone.sets = slices.Delete(zone.sets, index, index+1)
			w.WriteHeader(http.StatusAccepted)
		}
	default:
		zone.t.Errorf("unexpected Huawei request %s %s", r.Method, r.URL.RequestURI())
		w.WriteHeader(http.StatusNotFound)
	}
}

// set returns the www record set of a line; a nil line is the line-less
// default set.
func (zone *huaweiLineZone) set(line any) map[string]any {
	zone.mu.Lock()
	defer zone.mu.Unlock()
	for _, set := range zone.sets {
		if set["name"] == "www.example.test." && set["line"] == line {
			return set
		}
	}
	return nil
}

func newHuaweiLineRemote(t *testing.T) (*huaweiLineZone, *providerReconcileRemote, ProviderConfig) {
	zone := &huaweiLineZone{t: t}
	// One record set on an unmapped line plus the default-line set. The
	// default-line set has no "line" field, as older v2 responses omit it.
	zone.sets = append(zone.sets,
		map[string]any{"id": "rs-shanxi", "zone_id": "zone-hw", "name": "www.example.test.", "type": "A", "ttl": 300,
			"records": []any{"192.0.2.10"}, "line": "Dianxin_Shanxi"},
		map[string]any{"id": "rs-default", "zone_id": "zone-hw", "name": "www.example.test.", "type": "A", "ttl": 300,
			"records": []any{"192.0.2.10"}})
	config := reconcileHTTPProviderConfig(providerHuawei)
	providerAdapter, _ := newProviderTestAdapter(t, config, zone, time.Second)
	return zone, &providerReconcileRemote{adapter: providerAdapter}, completeTestConfig(config)
}

func applyHuaweiLine(t *testing.T, remote *providerReconcileRemote, config ProviderConfig,
	operation dnscheck.ProviderOperation) string {
	t.Helper()
	before, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || before.TargetComplete || before.Conflict || before.Ambiguous {
		t.Fatalf("%s %s lookup before = (%+v, %v)", operation.Action, operation.Line, before, err)
	}
	recordID, err := remote.Mutate(t.Context(), config, operation)
	if err != nil {
		t.Fatalf("%s %s mutate: %v", operation.Action, operation.Line, err)
	}
	after, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || !after.TargetComplete || after.Conflict || after.Ambiguous {
		t.Fatalf("%s %s lookup after = (%+v, %v)", operation.Action, operation.Line, after, err)
	}
	return recordID
}

func TestHuaweiLineCreatesOneRecordSetPerLine(t *testing.T) {
	zone, remote, config := newHuaweiLineRemote(t)
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineTelecom}
	telecomID := applyHuaweiLine(t, remote, config, create)
	// A second telecom value merges into the telecom set, not the default one.
	create.Value = "192.0.2.11"
	if id := applyHuaweiLine(t, remote, config, create); id != telecomID {
		t.Fatalf("second telecom value created %q, want merge into %q", id, telecomID)
	}
	create.Line, create.Value = LineMobile, "192.0.2.20"
	applyHuaweiLine(t, remote, config, create)
	// 境外 is Huawei's basic line Abroad (官方线路表: "Abroad 境外", beside "CN 中国大陆").
	create.Line, create.Value = LineOverseas, "192.0.2.30"
	applyHuaweiLine(t, remote, config, create)

	wantPaths := []string{"POST /v2.1/zones/zone-hw/recordsets", "PUT /v2.1/zones/zone-hw/recordsets/" + telecomID,
		"POST /v2.1/zones/zone-hw/recordsets", "POST /v2.1/zones/zone-hw/recordsets"}
	if !slices.Equal(zone.paths, wantPaths) {
		t.Fatalf("paths = %v, want %v", zone.paths, wantPaths)
	}
	wantBodies := []map[string]any{
		{"name": "www.example.test.", "type": "A", "ttl": float64(300), "records": []any{"192.0.2.10"}, "line": "Dianxin"},
		{"name": "www.example.test.", "type": "A", "ttl": float64(300), "records": []any{"192.0.2.10", "192.0.2.11"}},
		{"name": "www.example.test.", "type": "A", "ttl": float64(300), "records": []any{"192.0.2.20"}, "line": "Yidong"},
		{"name": "www.example.test.", "type": "A", "ttl": float64(300), "records": []any{"192.0.2.30"}, "line": "Abroad"},
	}
	for index, want := range wantBodies {
		got, _ := json.Marshal(zone.bodies[index])
		expected, _ := json.Marshal(want)
		if !bytes.Equal(got, expected) {
			t.Fatalf("body %d = %s, want %s", index, got, expected)
		}
	}
	if values := zone.set("default_view"); values != nil {
		t.Fatalf("no set may be created with an explicit default_view line here: %v", values)
	}
	defaultSet := zone.set(nil)
	if records := defaultSet["records"].([]any); len(records) != 1 {
		t.Fatalf("default set was touched: %v", records)
	}
}

func TestHuaweiLineLookupSeparatesLinesAcrossPages(t *testing.T) {
	zone, remote, config := newHuaweiLineRemote(t)
	// Fill page 1 with unrelated-line sets so the telecom set is on page 2.
	for index := range recoveryPageSize {
		zone.sets = append([]map[string]any{{"id": "rs-fill-" + strconv.Itoa(index), "zone_id": "zone-hw",
			"name": "www.example.test.", "type": "A", "ttl": 300, "records": []any{"203.0.113.1"},
			"line": "Dianxin_Fill" + strconv.Itoa(index)}}, zone.sets...)
	}
	zone.sets = append(zone.sets, map[string]any{"id": "rs-telecom", "zone_id": "zone-hw", "name": "www.example.test.",
		"type": "A", "ttl": 300, "records": []any{"192.0.2.10"}, "line": "Dianxin"})
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Line: LineTelecom}
	lookup, err := remote.Lookup(t.Context(), config, operation)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "rs-telecom" {
		t.Fatalf("telecom Lookup() = (%+v, %v)", lookup, err)
	}
	operation.Line = LineDefault
	lookup, err = remote.Lookup(t.Context(), config, operation)
	if err != nil || !lookup.TargetComplete || lookup.RecordID != "rs-default" {
		t.Fatalf("default Lookup() = (%+v, %v), want the line-less set as 默认", lookup, err)
	}
	operation.Line = LineUnicom
	lookup, err = remote.Lookup(t.Context(), config, operation)
	if err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("unicom Lookup() = (%+v, %v), want absent", lookup, err)
	}
}

// 修复华为云 DNS 分页问题：华为云列表末页只给 links.self、不给
// links.next（SDK PageLink.Next omitempty）；满页的末页按 Designate 仍可能带
// next。两种都必须读成功；还有后续页却缺 next 才算响应异常。
func TestHuaweiListLinksNextOnlyRequiredWhilePagesFollow(t *testing.T) {
	for _, test := range []struct {
		name  string
		links map[string]any
		total int
		ok    bool
	}{
		{"last page without next", map[string]any{"self": "s"}, 1, true},
		{"full last page with next", map[string]any{"self": "s", "next": "n"}, 1, true},
		{"more pages without next", map[string]any{"self": "s"}, recoveryPageSize + 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := reconcileHTTPProviderConfig(providerHuawei)
			adapter, _ := newProviderTestAdapter(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/zones" {
					writeTestJSON(t, w, map[string]any{"zones": []any{map[string]any{"id": "zone-hw", "name": "example.test."}}})
					return
				}
				writeTestJSON(t, w, map[string]any{"recordsets": []any{map[string]any{"id": "rs-1", "zone_id": "zone-hw",
					"name": "www.example.test.", "type": "A", "ttl": 300, "records": []any{"192.0.2.10"}}},
					"metadata": map[string]any{"total_count": test.total}, "links": test.links})
			}), time.Second)
			remote := &providerReconcileRemote{adapter: adapter}
			lookup, err := remote.Lookup(t.Context(), completeTestConfig(config), dnscheck.ProviderOperation{
				Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA,
				Value: "192.0.2.10", TTL: 300, Line: LineDefault})
			if test.ok && (err != nil || !lookup.TargetComplete) {
				t.Fatalf("Lookup() = (%+v, %v), want the listed record", lookup, err)
			}
			if !test.ok && ErrorCodeOf(err) != CodeInvalidResponse {
				t.Fatalf("Lookup() error = %v, want invalid response", err)
			}
		})
	}
}

func TestHuaweiLineUpdateAndDeleteKeepTheSetLine(t *testing.T) {
	zone, remote, config := newHuaweiLineRemote(t)
	zone.sets = append(zone.sets, map[string]any{"id": "rs-telecom", "zone_id": "zone-hw", "name": "www.example.test.",
		"type": "A", "ttl": 300, "records": []any{"192.0.2.10", "192.0.2.11"}, "line": "Dianxin"})
	applyHuaweiLine(t, remote, config, dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate,
		RecordID: "rs-telecom/192.0.2.11", Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.12", TTL: 300,
		Line: LineTelecom, PreviousValue: "192.0.2.11", PreviousTTL: 300, PreviousLine: LineTelecom})
	applyHuaweiLine(t, remote, config, dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete,
		RecordID: "rs-telecom/192.0.2.10", Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
		Line: LineTelecom})
	if records := zone.set("Dianxin")["records"].([]any); len(records) != 1 || records[0] != "192.0.2.12" {
		t.Fatalf("telecom set = %v", records)
	}
	// Deleting the last value of an unmapped-line set removes it.
	applyHuaweiLine(t, remote, config, dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete,
		RecordID: "rs-shanxi", Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300,
		Line: "huawei:Dianxin_Shanxi"})
	if zone.set("Dianxin_Shanxi") != nil {
		t.Fatal("Shanxi set was not deleted")
	}
	if records := zone.set(nil)["records"].([]any); len(records) != 1 {
		t.Fatalf("default set was touched: %v", records)
	}
}

func TestHuaweiLineRejectsLineChangeAndUnmappedLinesBeforeNetwork(t *testing.T) {
	zone, remote, config := newHuaweiLineRemote(t)
	for _, operation := range []dnscheck.ProviderOperation{
		{Action: dnscheck.ProviderUpdate, RecordID: "rs-default", Name: "www.example.test.", Type: dnscheck.RecordA,
			Value: "192.0.2.10", TTL: 300, Line: LineTelecom, PreviousValue: "192.0.2.10", PreviousTTL: 300},
		{Action: dnscheck.ProviderCreate, Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10",
			TTL: 300, Line: "huawei:Dianxin_Shanxi"},
	} {
		if _, err := remote.Mutate(t.Context(), config, operation); ErrorCodeOf(err) != CodeUnsupported {
			t.Fatalf("Mutate(%s %q) error = %v, want unsupported", operation.Action, operation.Line, err)
		}
	}
	if len(zone.paths) != 0 {
		t.Fatalf("network mutations = %v", zone.paths)
	}
}

func TestHuaweiListZoneRecordsReportsUnifiedLines(t *testing.T) {
	_, remote, config := newHuaweiLineRemote(t)
	records, err := remote.ListZoneRecords(t.Context(), config, "www.example.test.")
	if err != nil {
		t.Fatalf("ListZoneRecords() error = %v", err)
	}
	lines := map[string]string{}
	for _, record := range records {
		lines[record.ID] = record.Line
	}
	if lines["rs-default"] != LineDefault || lines["rs-shanxi"] != "huawei:Dianxin_Shanxi" {
		t.Fatalf("lines = %v", lines)
	}
}
