package dnsproviderremote

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
)

// Test-only credentials; requests reach only the httptest server.
const (
	namecheapTestUser = "fixture-user"
	namecheapTestKey  = "fixture0key0000000000000000000000"
	namecheapTestIP   = "192.0.2.44"
)

// namecheapFake follows the documented XML API: POST /xml.response with the
// global parameters, getHosts (<host> elements as the live API writes them;
// the docs print <Host>), setHosts replacing the whole set, getList paging,
// <Errors><Error Number=...> refusals.
type namecheapFake struct {
	t         *testing.T
	mu        sync.Mutex
	hosts     []namecheapHost
	emailType string
	notOurDNS bool
	errNumber string
	status    int
	upperTag  bool
	sets      []map[string]string
	commands  []string
	// afterSet runs after a setHosts write (simulates another writer).
	afterSet func(*namecheapFake)
	domains  []string
	nextID   int
}

func newNamecheapFake(t *testing.T) *namecheapFake {
	return &namecheapFake{t: t, emailType: "MX", domains: []string{testZone}, nextID: 100}
}

func (fake *namecheapFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if r.Host != "api.namecheap.com" || r.Method != http.MethodPost || r.URL.Path != "/xml.response" || r.URL.RawQuery != "" {
		fake.t.Errorf("request %s %s host=%s query=%q", r.Method, r.URL.Path, r.Host, r.URL.RawQuery)
	}
	if err := r.ParseForm(); err != nil {
		fake.t.Fatalf("form: %v", err)
	}
	form := map[string]string{}
	for key := range r.PostForm {
		form[key] = r.PostForm.Get(key)
	}
	fake.commands = append(fake.commands, form["Command"])
	if fake.status != 0 {
		w.WriteHeader(fake.status)
		return
	}
	switch {
	case form["ApiUser"] != namecheapTestUser || form["UserName"] != namecheapTestUser || form["ApiKey"] != namecheapTestKey:
		fake.fail(w, "1011102", "API Key is invalid or API access has not been enabled")
		return
	case form["ClientIp"] != namecheapTestIP:
		fake.fail(w, "1011150", "Invalid request IP")
		return
	case fake.errNumber != "":
		fake.fail(w, fake.errNumber, "forced")
		return
	}
	if form["Command"] == "namecheap.domains.getList" {
		var builder strings.Builder
		for _, domain := range fake.domains {
			fmt.Fprintf(&builder, `<Domain ID="1" Name="%s" User="%s" IsOurDNS="true"/>`, domain, namecheapTestUser)
		}
		fake.ok(w, form["Command"], `<DomainGetListResult>`+builder.String()+`</DomainGetListResult><Paging><TotalItems>`+
			strconv.Itoa(len(fake.domains))+`</TotalItems><CurrentPage>1</CurrentPage><PageSize>`+form["PageSize"]+`</PageSize></Paging>`)
		return
	}
	if form["SLD"]+"."+form["TLD"] != testZone {
		fake.fail(w, "2019166", "Domain not found")
		return
	}
	switch form["Command"] {
	case "namecheap.domains.dns.getHosts":
		tag := "host"
		if fake.upperTag {
			tag = "Host"
		}
		var builder strings.Builder
		for _, host := range fake.hosts {
			fake.nextID++
			fmt.Fprintf(&builder, `<%s HostId="%d" Name="%s" Type="%s" Address="%s" MXPref="%s" TTL="%s" IsActive="true" IsDDNSEnabled="false"/>`,
				tag, fake.nextID, xmlEscape(host.Name), host.Type, xmlEscape(host.Address), host.MXPref, host.TTL)
		}
		fake.ok(w, form["Command"], fmt.Sprintf(`<DomainDNSGetHostsResult Domain="%s" EmailType="%s" IsUsingOurDNS="%t">%s</DomainDNSGetHostsResult>`,
			testZone, fake.emailType, !fake.notOurDNS, builder.String()))
	case "namecheap.domains.dns.setHosts":
		fake.sets = append(fake.sets, form)
		var hosts []namecheapHost
		for index := 1; form["HostName"+strconv.Itoa(index)] != ""; index++ {
			suffix := strconv.Itoa(index)
			mxPref := form["MXPref"+suffix]
			if mxPref == "" {
				mxPref = "10"
			}
			hosts = append(hosts, namecheapHost{Name: form["HostName"+suffix], Type: form["RecordType"+suffix],
				Address: form["Address"+suffix], MXPref: mxPref, TTL: form["TTL"+suffix]})
		}
		fake.hosts = hosts
		if fake.afterSet != nil {
			fake.afterSet(fake)
		}
		fake.ok(w, form["Command"], `<DomainDNSSetHostsResult Domain="`+testZone+`" IsSuccess="true" />`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func xmlEscape(value string) string {
	var builder strings.Builder
	_ = xml.EscapeText(&builder, []byte(value))
	return strings.ReplaceAll(builder.String(), `"`, "&quot;")
}

func (fake *namecheapFake) ok(w http.ResponseWriter, command, result string) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><Warnings /><RequestedCommand>%s</RequestedCommand><CommandResponse Type="%s">%s</CommandResponse><Server>SERVER</Server><GMTTimeDifference>--5:00</GMTTimeDifference><ExecutionTime>0.01</ExecutionTime></ApiResponse>`,
		command, command, result)
}

func (fake *namecheapFake) fail(w http.ResponseWriter, number, text string) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?><ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response"><Errors><Error Number="%s">%s</Error></Errors><Warnings /><RequestedCommand /><Server>SERVER</Server><GMTTimeDifference>--5:00</GMTTimeDifference><ExecutionTime>0</ExecutionTime></ApiResponse>`,
		number, text)
}

func namecheapTestConfig() ProviderConfig {
	return ProviderConfig{ProviderType: providerNamecheap, ZoneName: testZone, Credentials: map[string]string{
		"username": namecheapTestUser, "api_key": namecheapTestKey, "source_ip": namecheapTestIP}}
}

func newNamecheapRemote(t *testing.T, fake *namecheapFake) (*Adapter, *providerReconcileRemote, ProviderConfig) {
	config := namecheapTestConfig()
	adapter, _ := newProviderTestAdapter(t, config, fake, time.Second)
	return adapter, &providerReconcileRemote{adapter: adapter}, completeTestConfig(config)
}

// existingHosts is a zone with records the platform does not own: they must
// survive every setHosts.
func existingHosts() []namecheapHost {
	return []namecheapHost{
		{Name: "@", Type: "A", Address: "192.0.2.99", MXPref: "10", TTL: "1800"},
		{Name: "@", Type: "MX", Address: "mail.example.net.", MXPref: "5", TTL: "1800"},
		{Name: "@", Type: "TXT", Address: "v=spf1 include:example.net ~all", MXPref: "10", TTL: "1799"},
		{Name: "old", Type: "URL301", Address: "https://example.net/", MXPref: "10", TTL: "1800"},
	}
}

func hostsWithout(hosts []namecheapHost, keep func(namecheapHost) bool) []namecheapHost {
	return slices.DeleteFunc(slices.Clone(hosts), func(host namecheapHost) bool { return !keep(host) })
}

func requireExistingHosts(t *testing.T, fake *namecheapFake) {
	t.Helper()
	for _, want := range existingHosts() {
		if !slices.ContainsFunc(fake.hosts, func(host namecheapHost) bool {
			return host.Name == want.Name && host.Type == want.Type && host.Address == want.Address && host.TTL == want.TTL &&
				(want.Type != "MX" || host.MXPref == want.MXPref)
		}) {
			t.Fatalf("record %+v lost: %+v", want, fake.hosts)
		}
	}
}
func TestNamecheapDispatchCredentialsAndTTL(t *testing.T) {
	adapter := newAdapter(nil, nil, nil, productionEndpoints(), requestTimeout, nil, nil)
	if provider, err := adapter.provider(providerNamecheap); err != nil {
		t.Fatalf("provider(namecheap) = %v", err)
	} else if _, ok := provider.(*namecheapProvider); !ok {
		t.Fatalf("provider(namecheap) = %T", provider)
	}
	if production := productionEndpoints().namecheap; production.baseURL != "https://api.namecheap.com" {
		t.Fatalf("production endpoint = %+v", production)
	}
	if got := SupportedLines(providerNamecheap); !slices.Equal(got, []string{LineDefault}) {
		t.Fatalf("SupportedLines = %v", got)
	}
	for name, credentials := range map[string]map[string]string{
		"missing ip":  {"username": "u", "api_key": "k"},
		"ipv6 source": {"username": "u", "api_key": "k", "source_ip": "2001:db8::1"},
		"not an ip":   {"username": "u", "api_key": "k", "source_ip": "example.net"},
		"padded ip":   {"username": "u", "api_key": "k", "source_ip": "192.0.2.010"},
		"extra field": {"username": "u", "api_key": "k", "source_ip": "192.0.2.1", "plan": "x"},
		"spaced key":  {"username": "u", "api_key": "k k", "source_ip": "192.0.2.1"},
	} {
		if err := validateCredentials(providerNamecheap, credentials); ErrorCodeOf(err) != CodeInvalidInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := validateCredentials(providerNamecheap, namecheapTestConfig().Credentials); err != nil {
		t.Fatalf("valid credentials: %v", err)
	}
	for _, test := range []struct {
		requested, want uint32
		clamped         bool
	}{{30, 60, true}, {60, 60, false}, {600, 600, false}, {60000, 60000, false}, {86400, 60000, false}} {
		if got, clamped := EffectiveTTL(providerNamecheap, test.requested); got != test.want || clamped != test.clamped {
			t.Errorf("EffectiveTTL(%d) = %d, %v", test.requested, got, clamped)
		}
	}
}

// setHosts replaces the whole set: present / delete keep every other record
// (MX preference, URL redirect, SPF TXT, EmailType) and write them back.
func TestNamecheapTXTLifecycleKeepsOtherRecords(t *testing.T) {
	for _, upper := range []bool{false, true} {
		t.Run("upperTag="+strconv.FormatBool(upper), func(t *testing.T) {
			fake := newNamecheapFake(t)
			fake.hosts, fake.upperTag = existingHosts(), upper
			adapter, _, _ := newNamecheapRemote(t, fake)
			handle, err := adapter.PresentTXT(t.Context(), testChallenge())
			if err != nil {
				t.Fatalf("PresentTXT: %v", err)
			}
			if len(fake.sets) != 1 || fake.sets[0]["EmailType"] != "MX" || fake.sets[0]["HostName5"] != "_acme-challenge" ||
				fake.sets[0]["Address5"] != testValue || fake.sets[0]["TTL5"] != "60" || fake.sets[0]["MXPref2"] != "5" {
				t.Fatalf("setHosts = %v", fake.sets)
			}
			requireExistingHosts(t, fake)
			requireHandle(t, handle, providerNamecheap, testZone, namecheapRecordID("_acme-challenge.example.test.", "TXT", testValue))
			challenge := testChallengeWithHandle(handle)
			if err := adapter.ObserveTXT(t.Context(), challenge); err != nil {
				t.Fatalf("ObserveTXT: %v", err)
			}
			if err := adapter.DeleteTXT(t.Context(), challenge); err != nil {
				t.Fatalf("DeleteTXT: %v", err)
			}
			if len(fake.hosts) != len(existingHosts()) {
				t.Fatalf("hosts after delete = %+v", fake.hosts)
			}
			requireExistingHosts(t, fake)
			assertRemoteError(t, adapter.ObserveTXT(t.Context(), challenge), CodeRecordNotFound)
			sets := len(fake.sets)
			if err := adapter.DeleteTXT(t.Context(), challenge); err != nil || len(fake.sets) != sets {
				t.Fatalf("second DeleteTXT = %v (sets %d -> %d)", err, sets, len(fake.sets))
			}
		})
	}
}

func TestNamecheapReconcileCRUD(t *testing.T) {
	fake := newNamecheapFake(t)
	fake.hosts = existingHosts()
	_, remote, config := newNamecheapRemote(t, fake)
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
		t.Fatalf("lookup after create = %+v, %v (id %s)", lookup, err, recordID)
	}
	update := dnscheck.ProviderOperation{Action: dnscheck.ProviderUpdate, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600, PreviousValue: "192.0.2.10", PreviousTTL: 600}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || lookup.TargetComplete || lookup.Conflict {
		t.Fatalf("lookup before update = %+v, %v", lookup, err)
	}
	if got, err := remote.Mutate(t.Context(), config, update); err != nil || got != recordID {
		t.Fatalf("update = %q, %v", got, err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, update); err != nil || !lookup.TargetComplete || lookup.RecordID != recordID {
		t.Fatalf("lookup after update = %+v, %v", lookup, err)
	}
	if slices.ContainsFunc(fake.hosts, func(host namecheapHost) bool { return host.Address == "192.0.2.10" }) {
		t.Fatalf("previous value kept: %+v", fake.hosts)
	}
	cname := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "cdn.example.test.",
		Type: dnscheck.RecordCNAME, Value: "edge.example.net.", TTL: 86400}
	if _, err := remote.Mutate(t.Context(), config, cname); err != nil {
		t.Fatalf("create CNAME: %v", err)
	}
	last := fake.sets[len(fake.sets)-1]
	if !slices.ContainsFunc(fake.hosts, func(host namecheapHost) bool {
		return host.Name == "cdn" && host.Address == "edge.example.net" && host.TTL == "60000"
	}) {
		t.Fatalf("CNAME not written without root dot at TTL 60000: %v", last)
	}
	if lookup, err := remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup CNAME = %+v, %v", lookup, err)
	}
	// Namecheap answering the target with a root dot still matches.
	for index := range fake.hosts {
		if fake.hosts[index].Name == "cdn" {
			fake.hosts[index].Address = "edge.example.net."
		}
	}
	if lookup, err := remote.Lookup(t.Context(), config, cname); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup CNAME with root dot = %+v, %v", lookup, err)
	}
	remove := dnscheck.ProviderOperation{Action: dnscheck.ProviderDelete, RecordID: recordID, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.11", TTL: 600}
	if got, err := remote.Mutate(t.Context(), config, remove); err != nil || got != recordID {
		t.Fatalf("delete = %q, %v", got, err)
	}
	if lookup, err := remote.Lookup(t.Context(), config, remove); err != nil || !lookup.TargetComplete {
		t.Fatalf("lookup after delete = %+v, %v", lookup, err)
	}
	sets := len(fake.sets)
	if _, err := remote.Mutate(t.Context(), config, remove); err != nil || len(fake.sets) != sets {
		t.Fatalf("second delete = %v (wrote again: %v)", err, len(fake.sets) != sets)
	}
	requireExistingHosts(t, fake)
	apex, err := remote.ListZoneRecords(t.Context(), config, "example.test.")
	if err != nil || len(apex) != 1 || apex[0].Value != "192.0.2.99" || apex[0].Line != LineDefault {
		t.Fatalf("apex records = %+v, %v", apex, err)
	}
}

// Another writer changing the set between our setHosts and the read-back:
// the result is uncertain (temporary), never reported as success.
func TestNamecheapReadBackMismatchIsUncertain(t *testing.T) {
	fake := newNamecheapFake(t)
	fake.hosts = existingHosts()
	fake.afterSet = func(fake *namecheapFake) {
		fake.hosts = hostsWithout(fake.hosts, func(host namecheapHost) bool { return host.Name != "www" })
	}
	_, remote, config := newNamecheapRemote(t, fake)
	_, err := remote.Mutate(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600})
	var remoteErr *Error
	if !errorAs(err, &remoteErr) || remoteErr.Code != CodeUnavailable || !remoteErr.Temporary || !mutationResultUnknown(err) {
		t.Fatalf("read-back mismatch = %v", err)
	}
}

// Writes to one zone are serialised: concurrent creates all survive.
func TestNamecheapConcurrentWritesKeepEachOther(t *testing.T) {
	fake := newNamecheapFake(t)
	_, remote, config := newNamecheapRemote(t, fake)
	var group sync.WaitGroup
	errs := make(chan error, 4)
	for index := 0; index < 4; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			_, err := remote.Mutate(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
				Name: fmt.Sprintf("n%d.example.test.", index), Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600})
			errs <- err
		}(index)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	if len(fake.hosts) != 4 {
		t.Fatalf("hosts = %+v", fake.hosts)
	}
}

// A record type setHosts cannot write back (CAA, SRV) stops the rewrite.
func TestNamecheapRefusesZoneWithUnwritableRecords(t *testing.T) {
	fake := newNamecheapFake(t)
	fake.hosts = append(existingHosts(), namecheapHost{Name: "@", Type: "CAA", Address: `0 issue "letsencrypt.org"`, TTL: "1800"})
	_, remote, config := newNamecheapRemote(t, fake)
	_, err := remote.Mutate(t.Context(), config, dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate,
		Name: "www.example.test.", Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 600})
	assertRemoteError(t, err, CodeUnsupported)
	if len(fake.sets) != 0 {
		t.Fatalf("setHosts called: %v", fake.sets)
	}
}

func TestNamecheapErrorMapping(t *testing.T) {
	create := dnscheck.ProviderOperation{Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300}
	for _, test := range []struct {
		name      string
		mutate    func(ProviderConfig)
		errNumber string
		status    int
		notOurDNS bool
		want      ErrorCode
	}{
		{name: "bad key", mutate: func(config ProviderConfig) { config.Credentials["api_key"] = "wrong" }, want: CodeCredentialsRejected},
		{name: "ip not whitelisted", mutate: func(config ProviderConfig) { config.Credentials["source_ip"] = "198.51.100.1" },
			want: CodeCredentialsRejected},
		{name: "domain not found", errNumber: "2019166", want: CodeZoneNotHosted},
		{name: "not namecheap dns", notOurDNS: true, want: CodeZoneNotHosted},
		{name: "enom error", errNumber: "3050900", want: CodeUnavailable},
		{name: "unknown error", errNumber: "9999999", want: CodeInvalidResponse},
		{name: "http 429", status: http.StatusTooManyRequests, want: CodeRateLimited},
		{name: "http 502", status: http.StatusBadGateway, want: CodeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := newNamecheapFake(t)
			fake.errNumber, fake.status, fake.notOurDNS = test.errNumber, test.status, test.notOurDNS
			_, remote, config := newNamecheapRemote(t, fake)
			if test.mutate != nil {
				test.mutate(config)
			}
			_, err := remote.Lookup(t.Context(), config, create)
			assertRemoteError(t, err, test.want)
		})
	}
	fake := newNamecheapFake(t)
	_, remote, config := newNamecheapRemote(t, fake)
	fake.errNumber = "3013288"
	if _, err := remote.Mutate(t.Context(), config, create); ErrorCodeOf(err) != CodeInvalidInput {
		t.Fatalf("too many records = %v", err)
	}
}

func TestNamecheapResolveZoneApexSplitsTLD(t *testing.T) {
	fake := newNamecheapFake(t)
	fake.domains = []string{"other.co.uk", testZone}
	_, remote, config := newNamecheapRemote(t, fake)
	apex, err := remote.ResolveZoneApex(t.Context(), providerNamecheap, config.Credentials, "cdn."+testZone)
	if err != nil || apex != testZone {
		t.Fatalf("ResolveZoneApex = %q, %v", apex, err)
	}
	if domain, err := namecheapDomain("example.co.uk"); err != nil || domain.Get("SLD") != "example" || domain.Get("TLD") != "co.uk" {
		t.Fatalf("namecheapDomain = %v, %v", domain, err)
	}
}
