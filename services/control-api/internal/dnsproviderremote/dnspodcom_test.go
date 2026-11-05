package dnsproviderremote

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// dnsPodComFake is a DNSPod.com legacy API double built from the samples of
// https://docs.dnspod.com/api-legacy/ (read 2026-11-05): form POST
// /<Method>, login_token "ID,Token", string-valued fields, domain_id
// addressing, Record.List offset/length with info.record_total, codes -1,
// -2, 6, 8, 10.
type dnsPodComFake struct {
	t       *testing.T
	mu      sync.Mutex
	nextID  int
	records map[string]map[string]string
	order   []string
	code    string // forced status code for every call ("": none)
	status  int    // forced HTTP status (0: none)
	forms   []map[string]string
	offsets []string
	domains []string
}

const (
	dnsPodComTestID     = "730060"
	dnsPodComTestToken  = "fixture-token"
	dnsPodComTestDomain = "9"
)

func newDNSPodComFake(t *testing.T) *dnsPodComFake {
	return &dnsPodComFake{t: t, nextID: 5000, records: map[string]map[string]string{}}
}

func (fake *dnsPodComFake) add(name, recordType, line, value, ttl string) string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.nextID++
	id := strconv.Itoa(fake.nextID)
	fake.records[id] = map[string]string{"id": id, "name": name, "type": recordType, "line": line, "value": value, "ttl": ttl}
	fake.order = append(fake.order, id)
	return id
}

func (fake *dnsPodComFake) reply(w http.ResponseWriter, code string, extra map[string]any) {
	body := map[string]any{"status": map[string]string{"code": code, "message": "fixture", "created_at": "2026-11-05 10:00:00"}}
	for key, value := range extra {
		body[key] = value
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		fake.t.Errorf("encode: %v", err)
	}
}

func (fake *dnsPodComFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if r.Host != "api.dnspod.com" || r.Method != http.MethodPost ||
		r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		fake.t.Errorf("request %s %s host=%q type=%q", r.Method, r.URL.Path, r.Host, r.Header.Get("Content-Type"))
	}
	if err := r.ParseForm(); err != nil {
		fake.t.Fatalf("form: %v", err)
	}
	form := map[string]string{"method": r.URL.Path}
	for key := range r.PostForm {
		form[key] = r.PostForm.Get(key)
	}
	fake.forms = append(fake.forms, form)
	if fake.status != 0 {
		w.WriteHeader(fake.status)
		return
	}
	if form["format"] != "json" || form["login_token"] != dnsPodComTestID+","+dnsPodComTestToken {
		fake.reply(w, "-1", nil)
		return
	}
	if fake.code != "" {
		fake.reply(w, fake.code, nil)
		return
	}
	if r.URL.Path != "/Domain.Info" && r.URL.Path != "/Domain.List" && form["domain_id"] != dnsPodComTestDomain {
		fake.reply(w, "6", nil)
		return
	}
	switch r.URL.Path {
	case "/Domain.Info":
		if form["domain"] != testZone {
			fake.reply(w, "6", nil)
			return
		}
		fake.reply(w, "1", map[string]any{"domain": map[string]any{"id": dnsPodComTestDomain, "name": testZone,
			"punycode": testZone, "grade": "DP_Free", "ttl": "600"}})
	case "/Domain.List":
		offset, _ := strconv.Atoi(form["offset"])
		length, _ := strconv.Atoi(form["length"])
		page := []map[string]any{}
		for index := offset; index < len(fake.domains) && index < offset+length; index++ {
			page = append(page, map[string]any{"id": index + 1, "name": fake.domains[index], "punycode": fake.domains[index]})
		}
		if len(fake.domains) == 0 {
			fake.reply(w, "9", nil)
			return
		}
		fake.reply(w, "1", map[string]any{"info": map[string]any{"domain_total": len(fake.domains)}, "domains": page})
	case "/Record.List":
		fake.offsets = append(fake.offsets, form["offset"])
		if len(fake.order) == 0 {
			fake.reply(w, "10", nil)
			return
		}
		offset, _ := strconv.Atoi(form["offset"])
		length, _ := strconv.Atoi(form["length"])
		page := []map[string]string{}
		for index := offset; index < len(fake.order) && index < offset+length; index++ {
			page = append(page, fake.records[fake.order[index]])
		}
		fake.reply(w, "1", map[string]any{
			"domain":  map[string]any{"id": dnsPodComTestDomain, "name": testZone, "grade": "DP_Free"},
			"info":    map[string]any{"sub_domains": "1", "record_total": strconv.Itoa(len(fake.order))},
			"records": page,
		})
	case "/Record.Info":
		record, ok := fake.records[form["record_id"]]
		if !ok {
			fake.reply(w, "8", nil)
			return
		}
		fake.reply(w, "1", map[string]any{
			"domain": map[string]any{"id": dnsPodComTestDomain, "domain": testZone, "domain_grade": "DP_Free"},
			"record": map[string]string{"id": record["id"], "sub_domain": record["name"], "record_type": record["type"],
				"record_line": "Default", "value": record["value"], "ttl": record["ttl"], "domain_id": dnsPodComTestDomain},
		})
	case "/Record.Create", "/Record.Modify":
		id := form["record_id"]
		if r.URL.Path == "/Record.Create" {
			fake.nextID++
			id = strconv.Itoa(fake.nextID)
			fake.order = append(fake.order, id)
		} else if _, ok := fake.records[id]; !ok {
			fake.reply(w, "8", nil)
			return
		}
		name := form["sub_domain"]
		if name == "" {
			name = "@"
		}
		fake.records[id] = map[string]string{"id": id, "name": name, "type": form["record_type"], "line": "Default",
			"value": form["value"], "ttl": form["ttl"]}
		fake.reply(w, "1", map[string]any{"record": map[string]any{"id": id, "name": name, "status": "enable"}})
	case "/Record.Remove":
		id := form["record_id"]
		if _, ok := fake.records[id]; !ok {
			fake.reply(w, "8", nil)
			return
		}
		delete(fake.records, id)
		fake.order = slices.DeleteFunc(fake.order, func(value string) bool { return value == id })
		fake.reply(w, "1", nil)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (fake *dnsPodComFake) lastForm(method string) map[string]string {
	for index := len(fake.forms) - 1; index >= 0; index-- {
		if fake.forms[index]["method"] == method {
			return fake.forms[index]
		}
	}
	return nil
}

func dnsPodComTestConfig() ProviderConfig {
	return ProviderConfig{ProviderType: providerDNSPodCom, ZoneName: testZone,
		Credentials: map[string]string{"dp_id": dnsPodComTestID, "dp_key": dnsPodComTestToken}}
}

func newDNSPodComRemote(t *testing.T, fake *dnsPodComFake) (*Adapter, *providerReconcileRemote, ProviderConfig) {
	config := dnsPodComTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	return adapter, &providerReconcileRemote{adapter: adapter}, completeTestConfig(config)
}

func TestNewProvidersDispatchAndEndpoints(t *testing.T) {
	adapter := newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)
	for providerType, want := range map[string]endpoint{
		providerDNSPodCom: {baseURL: "https://api.dnspod.com", host: "api.dnspod.com"},
		providerGoDaddy:   {baseURL: "https://api.godaddy.com", host: "api.godaddy.com"},
		providerNamesilo:  {baseURL: "https://www.namesilo.com", host: "www.namesilo.com"},
	} {
		provider, err := adapter.provider(providerType)
		if err != nil || !supportedProvider(providerType) {
			t.Fatalf("provider(%s) = %T, %v", providerType, provider, err)
		}
		got := map[string]endpoint{providerDNSPodCom: productionEndpoints().dnspodcom,
			providerGoDaddy: productionEndpoints().godaddy, providerNamesilo: productionEndpoints().namesilo}[providerType]
		if got != want {
			t.Fatalf("%s endpoint = %+v", providerType, got)
		}
		if lines := SupportedLines(providerType); !slices.Equal(lines, []string{LineDefault}) {
			t.Fatalf("SupportedLines(%s) = %v", providerType, lines)
		}
		if HubSupportsWeight(providerType) {
			t.Fatalf("%s weight", providerType)
		}
	}
	if _, ok := mustProvider(t, adapter, providerDNSPodCom).(*dnsPodComProvider); !ok {
		t.Fatal("dnspod_com provider type")
	}
	if _, ok := mustProvider(t, adapter, providerGoDaddy).(*goDaddyProvider); !ok {
		t.Fatal("godaddy provider type")
	}
	if _, ok := mustProvider(t, adapter, providerNamesilo).(*namesiloProvider); !ok {
		t.Fatal("namesilo provider type")
	}
}

func mustProvider(t *testing.T, adapter *Adapter, providerType string) remoteProvider {
	t.Helper()
	provider, err := adapter.provider(providerType)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

// Carrier lines are refused before any call; the default line passes.
func TestNewProvidersRefuseCarrierLines(t *testing.T) {
	for _, config := range []ProviderConfig{dnsPodComTestConfig(), goDaddyTestConfig(), namesiloTestConfig()} {
		config = completeTestConfig(config)
		for _, line := range []string{LineTelecom, LineUnicom, LineMobile, LineOverseas} {
			err := validateProviderReconcileOperation(config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
				Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600, Line: line})
			assertRemoteError(t, err, CodeUnsupported)
		}
		if err := validateProviderReconcileOperation(config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
			Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600, Line: LineDefault}); err != nil {
			t.Fatalf("%s default line: %v", config.ProviderType, err)
		}
	}
}

func TestNewProvidersCredentials(t *testing.T) {
	for providerType, cases := range map[string]map[string]map[string]string{
		providerDNSPodCom: {
			"missing token": {"dp_id": "1"}, "non-numeric id": {"dp_id": "abc", "dp_key": "t"},
			"comma in token": {"dp_id": "1", "dp_key": "a,b"}, "extra": {"dp_id": "1", "dp_key": "t", "x": "y"},
		},
		providerGoDaddy: {
			"missing secret": {"api_key": "k"}, "colon in key": {"api_key": "a:b", "api_secret": "s"},
			"blank secret": {"api_key": "k", "api_secret": " "},
		},
		providerNamesilo: {
			"missing key": {}, "space in key": {"key": "a b"}, "extra": {"key": "k", "api_secret": "s"},
			"old field name": {"api_key": "k"},
		},
	} {
		for name, credentials := range cases {
			if err := validateCredentials(providerType, credentials); ErrorCodeOf(err) != CodeInvalidInput {
				t.Errorf("%s %s: %v", providerType, name, err)
			}
		}
	}
	for providerType, credentials := range map[string]map[string]string{
		providerDNSPodCom: {"dp_id": "730060", "dp_key": "e1a8a$f14dc5dcbafd83680b3d2a553c4d553d"},
		providerGoDaddy:   {"api_key": "dLP4_key", "api_secret": "secret"},
		providerNamesilo:  {"key": "12345abcde"},
	} {
		if err := validateCredentials(providerType, credentials); err != nil {
			t.Errorf("%s valid credentials: %v", providerType, err)
		}
	}
}

func TestNewProvidersEffectiveTTL(t *testing.T) {
	for _, test := range []struct {
		provider  string
		requested uint32
		want      uint32
		clamped   bool
	}{
		{providerDNSPodCom, 60, 600, true}, {providerDNSPodCom, 600, 600, false}, {providerDNSPodCom, 3600, 3600, false},
		{providerGoDaddy, 60, 600, true}, {providerGoDaddy, 599, 600, true}, {providerGoDaddy, 600, 600, false},
		{providerNamesilo, 60, 3600, true}, {providerNamesilo, 600, 3600, true}, {providerNamesilo, 7200, 7200, false},
		{providerNameCom, 60, 300, true}, {providerDNSPodCN, 60, 60, false},
	} {
		got, clamped := EffectiveTTL(test.provider, test.requested)
		if got != test.want || clamped != test.clamped {
			t.Errorf("EffectiveTTL(%s, %d) = %d, %v", test.provider, test.requested, got, clamped)
		}
	}
}

func TestDNSPodComTXTLifecycle(t *testing.T) {
	fake := newDNSPodComFake(t)
	adapter, _, _ := newDNSPodComRemote(t, fake)
	handle, err := adapter.PresentTXT(t.Context(), testChallenge())
	if err != nil {
		t.Fatalf("PresentTXT: %v", err)
	}
	created := fake.lastForm("/Record.Create")
	if created["domain_id"] != dnsPodComTestDomain || created["sub_domain"] != testRelative || created["record_type"] != "TXT" ||
		created["record_line"] != "default" || created["value"] != testValue || created["ttl"] != "600" {
		t.Fatalf("Record.Create form = %v", created)
	}
	payload := requireHandle(t, handle, providerDNSPodCom, dnsPodComTestDomain, "5001")
	_ = payload
	challenge := testChallengeWithHandle(handle)
	if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
		t.Fatalf("ObserveTXT: %v", err)
	}
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("DeleteTXT: %v", err)
	}
	if len(fake.records) != 0 {
		t.Fatalf("records after delete = %v", fake.records)
	}
	assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound)
	if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
		t.Fatalf("second DeleteTXT: %v", err)
	}
	// Record.Remove of an unknown id (code 8) is success.
	if err := (&dnsPodComProvider{adapter: adapter}).delete(t.Context(), completeTestConfig(dnsPodComTestConfig()),
		recordHandle{ZoneID: dnsPodComTestDomain, RecordID: "424242"}); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

// RecoverTXT pages the whole zone with offset/length until record_total.
func TestDNSPodComRecoverTXTPages(t *testing.T) {
	fake := newDNSPodComFake(t)
	for index := 0; index < 2*recoveryPageSize+5; index++ {
		fake.add("filler-"+strconv.Itoa(index), "A", "Default", "192.0.2.1", "600")
	}
	target := fake.add(testRelative, "TXT", "Default", testValue, "600")
	fake.add(testRelative, "TXT", "Default", testOtherValue, "600")
	adapter, _, _ := newDNSPodComRemote(t, fake)
	handle, found, err := adapter.RecoverTXT(t.Context(), testChallenge())
	if err != nil || !found {
		t.Fatalf("RecoverTXT = %v, %v", found, err)
	}
	requireHandle(t, handle, providerDNSPodCom, dnsPodComTestDomain, target)
	if !slices.Equal(fake.offsets, []string{"0", "100", "200"}) {
		t.Fatalf("offsets = %v", fake.offsets)
	}
}

func TestDNSPodComReconcileCRUD(t *testing.T) {
	fake := newDNSPodComFake(t)
	fake.add("@", "A", "Default", "192.0.2.99", "600")
	fake.add("www", "A", "US", "192.0.2.50", "600") // a country line: independent
	_, remote, config := newDNSPodComRemote(t, fake)
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before create = %+v, %v", lookup, err)
	}
	recordID, err := remote.Mutate(t.Context(), config, create)
	if err != nil || recordID == "" {
		t.Fatalf("create = %q, %v", recordID, err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, create); err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup after create = %+v, %v", lookup, err)
	}
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600, PreviousValue: "192.0.2.10", PreviousTTL: 600}
	if got, err := remote.Mutate(t.Context(), config, update); err != nil || got != recordID {
		t.Fatalf("update = %q, %v", got, err)
	}
	if modify := fake.lastForm("/Record.Modify"); modify["record_id"] != recordID || modify["record_line"] != "default" ||
		modify["value"] != "192.0.2.11" {
		t.Fatalf("Record.Modify form = %v", modify)
	}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after update = %+v, %v", lookup, err)
	}
	// CNAME is written without the root dot and read back with it.
	cname := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "cdn.example.test.",
		Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 600}
	if _, err := remote.Mutate(t.Context(), config, cname); err != nil {
		t.Fatalf("create CNAME: %v", err)
	}
	if form := fake.lastForm("/Record.Create"); form["value"] != "edge.example.net" {
		t.Fatalf("CNAME value = %q", form["value"])
	}
	if lookup, err := remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup CNAME = %+v, %v", lookup, err)
	}
	remove := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600}
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, remove); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after delete = %+v, %v", lookup, err)
	}
	records, err := remote.ListZoneRecords(t.Context(), config, "cdn.example.test.")
	if err != nil || len(records) != 1 || records[0].Value != "edge.example.net." || records[0].Line != LineDefault {
		t.Fatalf("ListZoneRecords = %+v, %v", records, err)
	}
	zone, err := remote.ListZoneRecords(t.Context(), config, "")
	if err != nil || len(zone) != 3 {
		t.Fatalf("zone = %+v, %v", zone, err)
	}
}

// TTL 60 (attack escalation level D) is written at 600 and reads back as the target.
func TestDNSPodComClampsTTLToFloor(t *testing.T) {
	fake := newDNSPodComFake(t)
	_, remote, config := newDNSPodComRemote(t, fake)
	operation := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "site.example.test.",
		Type: dnscheck.RecordA, Value: "0.0.0.0", TTL: 60}
	recordID, err := remote.Mutate(t.Context(), config, operation)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ttl := fake.lastForm("/Record.Create")["ttl"]; ttl != "600" {
		t.Fatalf("written TTL = %s", ttl)
	}
	if lookup, err := remote.Lookup(t.Context(), config, operation); err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup = %+v, %v", lookup, err)
	}
}

func TestDNSPodComErrorMapping(t *testing.T) {
	for name, test := range map[string]struct {
		code, token string
		status      int
		want        ErrorCode
	}{
		"login failed":  {token: "wrong", want: CodeCredentialsRejected},
		"refused -8":    {code: "-8", want: CodeCredentialsRejected},
		"too frequent":  {code: "-2", want: CodeRateLimited},
		"not ready":     {code: "-99", want: CodeUnavailable},
		"http 503":      {status: http.StatusServiceUnavailable, want: CodeUnavailable},
		"http 429":      {status: http.StatusTooManyRequests, want: CodeRateLimited},
		"unknown code":  {code: "3", want: CodeInvalidResponse},
		"domain absent": {code: "6", want: CodeZoneNotHosted},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newDNSPodComFake(t)
			fake.code, fake.status = test.code, test.status
			_, remote, config := newDNSPodComRemote(t, fake)
			if test.token != "" {
				config.Credentials["dp_key"] = test.token
			}
			_, err := remote.Lookup(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
				Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600})
			assertRemoteError(t, err, test.want)
		})
	}
	// Domain.Info for a zone the account lacks: dns_zone_not_hosted.
	fake := newDNSPodComFake(t)
	_, remote, config := newDNSPodComRemote(t, fake)
	config.ZoneName = "other.test"
	_, err := (&dnsPodComProvider{adapter: remote.adapter}).listRecords(t.Context(), config)
	assertRemoteError(t, err, CodeZoneNotHosted)
}

// A page whose size disagrees with record_total is refused.
func TestDNSPodComRejectsInconsistentPage(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{"status": map[string]string{"code": "1"}}
		if r.URL.Path == "/Domain.Info" {
			body["domain"] = map[string]any{"id": "9", "name": testZone}
		} else {
			body["info"] = map[string]any{"record_total": "3"}
			body["records"] = []map[string]string{{"id": "1", "name": "www", "type": "A", "line": "Default",
				"value": "192.0.2.1", "ttl": "600"}}
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	config := dnsPodComTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, handler, time.Second)
	_, err := (&dnsPodComProvider{adapter: adapter}).listRecords(t.Context(), completeTestConfig(config))
	assertRemoteError(t, err, CodeInvalidResponse)
}

func TestNewProvidersHostedDomains(t *testing.T) {
	fake := newDNSPodComFake(t)
	for index := 0; index < zoneApexPageSize+3; index++ {
		fake.domains = append(fake.domains, "zone"+strconv.Itoa(index)+".test")
	}
	fake.domains = append(fake.domains, testZone)
	_, remote, config := newDNSPodComRemote(t, fake)
	apex, err := remote.ResolveZoneApex(t.Context(), providerDNSPodCom, config.Credentials, "cdn."+testZone)
	if err != nil || apex != testZone {
		t.Fatalf("dnspod_com apex = %q, %v", apex, err)
	}
	empty := newDNSPodComFake(t)
	_, remote, config = newDNSPodComRemote(t, empty)
	if _, err := remote.ResolveZoneApex(t.Context(), providerDNSPodCom, config.Credentials, testZone); ErrorCodeOf(err) != CodeZoneNotHosted {
		t.Fatalf("empty account apex: %v", err)
	}
}
