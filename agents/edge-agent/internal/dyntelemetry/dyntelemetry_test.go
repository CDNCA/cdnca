package dyntelemetry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

const (
	scopeA  = "0d120000-0000-4000-8000-0000000000a1"
	scopeB  = "0d120000-0000-4000-8000-0000000000b1"
	tenantA = "0d120000-0000-4000-8000-0000000000a2"
	tenantB = "0d120000-0000-4000-8000-0000000000b2"
	nodeID  = "0d120000-0000-4000-8000-00000000ffff"
)

func testSite(scope, tenant, site, primary string, aliases []string, capture bool, ports ...int) edgesite.Site {
	listeners := []edgesite.Listener{}
	for _, port := range ports {
		listeners = append(listeners, edgesite.Listener{Port: port, AddressFamily: edgesite.FamilyIPv4})
	}
	if aliases == nil {
		aliases = []string{}
	}
	telemetry := &edgesite.Telemetry{Capture: siteobject.TelemetryCapture{Methods: []string{}, URIPrefixes: []string{},
		RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{},
		ResponseBodyFieldAllowlist: []string{}}}
	if capture {
		telemetry.Capture.Enabled = true
		telemetry.Capture.Revision = 3
		telemetry.Capture.EvidenceDigest = strings.Repeat("ab", 32)
		telemetry.Capture.RequestHeaderAllowlist = []string{"User-Agent"}
	}
	return edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scope, TenantID: tenant, SiteID: site, Revision: 1,
		Hosts: edgesite.Hosts{Primary: primary, Aliases: aliases}, Listeners: listeners,
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "o", Scheme: "http", Host: "192.0.2.1", Port: 80, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 10}}}},
		Security:  edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:    []edgesite.ErrorPage{},
		Telemetry: telemetry,
	}
}

type mapSites map[string]edgesite.Site

func (sites mapSites) Site(digest string) (edgesite.Site, error) {
	site, ok := sites[digest]
	if !ok {
		return edgesite.Site{}, os.ErrNotExist
	}
	return site, nil
}

func digestOf(t *testing.T, site edgesite.Site) string {
	t.Helper()
	raw, err := edgesite.Encode(site)
	if err != nil {
		t.Fatal(err)
	}
	return edgesite.Digest(raw)
}

// accessLine is what the node writes for a request of site on port.
func accessLine(site edgesite.Site, digest, host string, generation uint64, port int) string {
	v7 := map[string]any{"schema_version": 1, "type": "access.v1", "occurred_at": "2026-10-18T10:00:00+00:00",
		"tenant_id": site.TenantID, "site_id": site.SiteID, "node_id": "", "config_version_id": "", "installation_id": "",
		"task_id": nil, "request_id": "r1", "trace_id": "", "host": host, "path": "/a", "client_ip": "127.0.0.1",
		"method": "GET", "protocol": "HTTP/1.1", "connection": "7", "connection_requests": 1, "cache_status": "BYPASS",
		"status_code": 200, "request_bytes": 100, "response_bytes": 200, "request_headers": nil, "response_headers": nil,
		"request_body": nil, "response_body": nil, "ja4": "", "origin_connect_us": 0, "origin_first_byte_us": 0,
		"origin_total_us": 0, "blocked": false}
	raw, _ := json.Marshal(v7)
	attribution, _ := json.Marshal(Attribution{Generation: generation, Scope: site.ConfigurationScopeID, Digest: digest, Port: uint16(port)})
	return strings.TrimSuffix(string(raw), "}") + `,"cdnca":` + string(attribution) + "}"
}

func TestNormalizeIsTheV7Line(t *testing.T) {
	site := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000001", "a.example.test", []string{"*.a.example.test"}, true, 80, 443)
	digest := digestOf(t, site)
	registry := NewRegistry()
	if err := registry.Register(5, 6, map[string]string{scopeA: "cfg-a-1"}); err != nil {
		t.Fatal(err)
	}
	result, err := Normalize([]byte(accessLine(site, digest, "x.a.example.test", 6, 443)), registry, mapSites{digest: site}, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(result.Line, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["config_version_id"] != "cfg-a-1" || fields["cdnca"] != nil || fields["host"] != "x.a.example.test" {
		t.Fatalf("line %s", result.Line)
	}
	want := eventspool.TrustedIdentity{ListenPort: 443, EnrollmentNodeID: nodeID, TenantID: tenantA, SiteID: site.SiteID,
		ConfigVersionID: "cfg-a-1", CapturePolicyRevision: 3, CapturePolicyDigest: strings.Repeat("ab", 32)}
	if result.Identity != want || !result.CapturePolicy.Enabled || result.CapturePolicy.MaxEventBytes != 1<<20 {
		t.Fatalf("identity %+v policy %+v", result.Identity, result.CapturePolicy)
	}
	// The normalized line passes the event spool exactly like a v7 line.
	envelope, err := eventspool.ParseSourceLineBound(result.Line, result.CapturePolicy, result.Identity)
	if err != nil || envelope.SiteID != site.SiteID || envelope.ConfigVersionID != "cfg-a-1" || envelope.ListenPort != 443 {
		t.Fatalf("spool parse %+v %v", envelope, err)
	}
}

func TestNormalizeRefusesWhatTheSiteObjectDoesNotConfirm(t *testing.T) {
	a := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000001", "a.example.test", nil, false, 80)
	b := testSite(scopeB, tenantB, "0d120000-0000-4000-8000-000000000002", "b.example.test", nil, false, 80)
	none := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000003", "n.example.test", nil, false, 80)
	none.Telemetry = nil
	da, db, dn := digestOf(t, a), digestOf(t, b), digestOf(t, none)
	sites := mapSites{da: a, db: b, dn: none}
	registry := NewRegistry()
	_ = registry.Register(1, 1, map[string]string{scopeA: "cfg-a", scopeB: "cfg-b"})
	line := accessLine(a, da, "a.example.test", 1, 80)
	for name, mutate := range map[string]func(string) string{
		"other tenant":     func(s string) string { return strings.Replace(s, tenantA, tenantB, 1) },
		"other site":       func(s string) string { return strings.Replace(s, a.SiteID, b.SiteID, 1) },
		"other digest":     func(s string) string { return strings.Replace(s, da, db, 1) },
		"scope of another": func(s string) string { return strings.Replace(s, `"scope":"`+scopeA, `"scope":"`+scopeB, 1) },
		"port not served":  func(s string) string { return strings.Replace(s, `"port":80}`, `"port":81}`, 1) },
		"host not served": func(s string) string {
			return strings.Replace(s, `"host":"a.example.test"`, `"host":"b.example.test"`, 1)
		},
		"config version set": func(s string) string {
			return strings.Replace(s, `"config_version_id":""`, `"config_version_id":"x"`, 1)
		},
		"duplicate key":       func(s string) string { return strings.Replace(s, `"host":`, `"site_id":"`+a.SiteID+`","host":`, 1) },
		"extra attribution":   func(s string) string { return strings.Replace(s, `"port":80}`, `"port":80,"x":1}`, 1) },
		"no attribution":      func(s string) string { return s[:strings.Index(s, `,"cdnca"`)] + "}" },
		"generation zero":     func(s string) string { return strings.Replace(s, `"generation":1`, `"generation":0`, 1) },
		"bad digest":          func(s string) string { return strings.Replace(s, da, strings.ToUpper(da), 1) },
		"site sans telemetry": func(s string) string { return accessLine(none, dn, "n.example.test", 1, 80) },
	} {
		_, err := Normalize([]byte(mutate(line)), registry, sites, nodeID)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Not yet attributable (unknown generation or object) is distinct.
	if _, err := Normalize([]byte(accessLine(a, da, "a.example.test", 999999, 80)), registry, sites, nodeID); errors.Is(err, ErrInvalid) || err == nil {
		t.Errorf("future generation: %v", err)
	}
	if _, err := Normalize([]byte(accessLine(a, da, "a.example.test", 1, 80)), registry, mapSites{}, nodeID); !errors.Is(err, ErrUnattributed) {
		t.Errorf("missing object: %v", err)
	}
}

func TestRegistrySteps(t *testing.T) {
	registry := NewRegistry()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(registry.Register(1, 3, map[string]string{scopeA: "a1"}))
	must(registry.Register(4, 6, map[string]string{scopeA: "a2", scopeB: "b1"})) // split activation 4..6
	must(registry.Register(7, 9, map[string]string{scopeB: "b9"}))               // aborted
	must(registry.Register(7, 9, map[string]string{scopeB: "b1"}))               // retried: scope A left
	for _, c := range []struct {
		generation  uint64
		scope, want string
	}{
		{1, scopeA, "a1"}, {3, scopeA, "a1"}, {4, scopeA, "a2"}, {6, scopeA, "a2"}, {7, scopeA, ""},
		{3, scopeB, ""}, {5, scopeB, "b1"}, {9, scopeB, "b1"}, {10, scopeB, ""},
	} {
		got, ok := registry.ConfigVersion(c.generation, c.scope)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("gen %d %s = %q %v, want %q", c.generation, c.scope, got, ok, c.want)
		}
	}
	if err := registry.Register(5, 5, map[string]string{scopeB: "b1"}); err == nil {
		t.Fatal("registration below the newest accepted")
	}
	// Window: very old generations are no longer attributed.
	must(registry.Register(10+Window, 10+Window, map[string]string{scopeB: "b2"}))
	if _, ok := registry.ConfigVersion(5, scopeB); ok {
		t.Fatal("generation outside the window attributed")
	}
	if got, _ := registry.ConfigVersion(10, scopeB); got != "b1" {
		t.Fatalf("window edge %q", got)
	}
	if _, present := registry.scopes[scopeA]; present {
		t.Fatal("left scope not pruned")
	}
}

func TestRegistryPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = registry.Register(2, 2, map[string]string{scopeA: "a1"})
	_ = registry.Register(3, 4, map[string]string{scopeA: "a1"})
	_ = registry.Register(5, 5, map[string]string{scopeA: "a2"})
	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := reopened.ConfigVersion(4, scopeA); got != "a1" {
		t.Fatalf("after reopen %q", got)
	}
	if got, _ := reopened.ConfigVersion(5, scopeA); got != "a2" || reopened.Newest() != 5 {
		t.Fatalf("after reopen %q newest %d", got, reopened.Newest())
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	_ = os.WriteFile(path, []byte(`{"schema_version":1,"newest":1,"scopes":{"x":[]}}`), 0o600)
	if _, err := OpenRegistry(path); err == nil {
		t.Fatal("corrupt registry accepted")
	}
}

// sink collects appended envelopes.
type sink struct{ events []eventspool.Envelope }

func (s *sink) AppendBatch(_ context.Context, events []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	results := make([]eventspool.AppendResult, len(events))
	for index, event := range events {
		s.events = append(s.events, event)
		results[index] = eventspool.AppendResult{EventID: event.EventID, Sequence: uint64(len(s.events))}
	}
	return results, nil
}

// One shared source with interleaved sites of two tenants: every event gets
// its own site's identity; a line of a generation not registered yet stops
// the tail until it is, then continues in order.
func TestSharedSourceTail(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	source := filepath.Join(root, "access.jsonl")
	a := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000001", "a.example.test", nil, false, 80)
	b := testSite(scopeB, tenantB, "0d120000-0000-4000-8000-000000000002", "b.example.test", nil, true, 80)
	da, db := digestOf(t, a), digestOf(t, b)
	registry := NewRegistry()
	_ = registry.Register(1, 1, map[string]string{scopeA: "cfg-a", scopeB: "cfg-b"})
	now := time.Unix(1000, 0)
	resolver := &Resolver{Registry: registry, Sites: mapSites{da: a, db: b}, NodeID: nodeID, Grace: time.Minute, Now: func() time.Time { return now }}
	lines := []string{accessLine(a, da, "a.example.test", 1, 80), accessLine(b, db, "b.example.test", 1, 80),
		accessLine(a, da, "a.example.test", 2, 80), accessLine(b, db, "b.example.test", 2, 80)}
	if err := os.WriteFile(source, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := eventspool.NewTailer(eventspool.TailConfig{SourcePath: source, StateDir: filepath.Join(root, "state"),
		Identity: eventspool.TrustedIdentity{EnrollmentNodeID: nodeID}, MaxLineBytes: 16 << 10, MaxBatchEvents: 100,
		MaxQuarantineBytes: 1 << 20, Resolve: resolver.Resolve})
	if err != nil {
		t.Fatal(err)
	}
	collected := &sink{}
	result, err := tailer.TailOnce(context.Background(), collected)
	if err != nil || len(collected.events) != 2 || result.QuarantinedLines != 0 {
		t.Fatalf("first tail %+v %v events %d", result, err, len(collected.events))
	}
	_ = registry.Register(2, 2, map[string]string{scopeA: "cfg-a2", scopeB: "cfg-b"})
	if _, err := tailer.TailOnce(context.Background(), collected); err != nil || len(collected.events) != 4 {
		t.Fatalf("second tail %v events %d", err, len(collected.events))
	}
	versions := map[string][]string{}
	for _, event := range collected.events {
		versions[event.SiteID] = append(versions[event.SiteID], event.TenantID+"/"+event.ConfigVersionID)
	}
	if strings.Join(versions[a.SiteID], ",") != tenantA+"/cfg-a,"+tenantA+"/cfg-a2" ||
		strings.Join(versions[b.SiteID], ",") != tenantB+"/cfg-b,"+tenantB+"/cfg-b" {
		t.Fatalf("attribution %v", versions)
	}
	for _, event := range collected.events {
		if event.SiteID == b.SiteID && event.CapturePolicyRevision != 3 || event.SiteID == a.SiteID && event.CapturePolicyRevision != 0 {
			t.Fatalf("capture identity %+v", event)
		}
	}
	// A line that never becomes attributable waits for the grace, then is
	// quarantined and the tail goes on.
	stuck := accessLine(a, da, "a.example.test", 50, 80)
	after := accessLine(a, da, "a.example.test", 2, 80)
	file, _ := os.OpenFile(source, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = file.WriteString(stuck + "\n" + after + "\n")
	_ = file.Close()
	if _, err := tailer.TailOnce(context.Background(), collected); err != nil || len(collected.events) != 4 {
		t.Fatalf("waiting tail %v events %d", err, len(collected.events))
	}
	now = now.Add(2 * time.Minute)
	result, err = tailer.TailOnce(context.Background(), collected)
	if err != nil || len(collected.events) != 5 || result.QuarantinedLines != 1 {
		t.Fatalf("after grace %+v %v events %d", result, err, len(collected.events))
	}
	if counts := resolver.Counts(); counts.Attributed != 5 || counts.Unattributed != 1 {
		t.Fatalf("counts %+v", counts)
	}
}

// sec-log-fix: a security line exactly as nginx writes it from the dynamic
// routing log format (every $variable substituted with what the Lua modules
// set: $cdnca_security_* by cdnca_security / cdnca_waf / the CC engine,
// the attribution by site selection) is normalized and accepted by the
// event spool as a security event of its site.
func TestNormalizeSecurityLineOfTheDynamicRoutingFormat(t *testing.T) {
	site := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000003", "s.example.test", nil, false, 8080)
	digest := digestOf(t, site)
	registry := NewRegistry()
	if err := registry.Register(2, 2, map[string]string{scopeA: "cfg-s-1"}); err != nil {
		t.Fatal(err)
	}
	formats := regexp.MustCompile(`log_format (\S+) escape=json '([^']*)';`).FindAllStringSubmatch(edgeconfig.RenderDynamicRoutingTelemetryHTTP(), -1)
	format := ""
	for _, match := range formats {
		if match[1] == "cdnca_security_json" {
			format = match[2]
		}
	}
	if format == "" {
		t.Fatal("no cdnca_security_json format")
	}
	values := map[string]string{
		"time_iso8601": "2026-10-20T10:00:00+00:00", "cdnca_tenant_id": tenantA, "cdnca_site_id": site.SiteID,
		"cdnca_node_id": "", "cdnca_config_version_id": "", "request_id": "r9", "http_traceparent": "", "host": "s.example.test",
		"uri": "/probe", "cdnca_security_path": "/probe", "cdnca_telemetry_client_ip": "127.0.0.9", "request_method": "GET", "status": "403", "scheme": "http",
		"cdnca_security_type": "cc", "cdnca_security_action": "block", "cdnca_security_severity": "high",
		"cdnca_security_rule_id": "cc_rule:10001", "cdnca_security_request_class": "standard",
		"cdnca_site_generation": "2", "cdnca_site_scope": scopeA, "cdnca_site_digest": digest, "cdnca_site_port": "8080",
		// the map of $cdnca_l2_trusted (fix-l2trust): a visitor's request
		"cdnca_telemetry_l2": "false",
	}
	unknown := map[string]bool{}
	line := regexp.MustCompile(`\$([a-z0-9_]+)`).ReplaceAllStringFunc(format, func(name string) string {
		value, ok := values[name[1:]]
		if !ok {
			unknown[name[1:]] = true
			return "0" // numeric fields (bytes, timings) and empty strings parse either way
		}
		return value
	})
	// The pre-rename variable names are never written by the modules (rename
	// 10-21); the format must not read them.
	for _, name := range []string{"cdnfly" + "_security_type", "cdnfly" + "_security_action", "cdnfly" + "_security_emit"} {
		if strings.Contains(format, "$"+name) {
			t.Fatalf("format reads %s", name)
		}
	}
	line = regexp.MustCompile(`"(\w+)":"0"`).ReplaceAllString(line, `"$1":""`)
	result, err := Normalize([]byte(line), registry, mapSites{digest: site}, nodeID)
	if err != nil {
		t.Fatalf("%v\n%s\nunsubstituted %v", err, line, unknown)
	}
	// the same line from an L1's hop is skipped (fix-l2trust)
	if _, err := Normalize([]byte(strings.Replace(line, `"l2":false}}`, `"l2":true}}`, 1)), registry, mapSites{digest: site}, nodeID); !errors.Is(err, ErrL2Hop) {
		t.Fatalf("hop line: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(result.Line, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["type"] != "security.v1" || fields["security_type"] != "cc" || fields["action"] != "block" ||
		fields["rule_id"] != "cc_rule:10001" || fields["listen_port"] != float64(8080) || fields["config_version_id"] != "cfg-s-1" {
		t.Fatalf("line %s", result.Line)
	}
	envelope, err := eventspool.ParseSourceLineBound(result.Line, result.CapturePolicy, result.Identity)
	if err != nil || envelope.Type != eventspool.EventSecurity || envelope.SecurityType != "cc" || envelope.Action != "block" ||
		envelope.RuleID != "cc_rule:10001" || envelope.SiteID != site.SiteID {
		t.Fatalf("spool parse %v\n%s", err, result.Line)
	}
}

// An aggregated CC line (sec-log-agg: the plain security line with "count"
// before the attribution, written by the flush server) is attributed like
// any line: the spool keeps its count; a forged attribution is refused; an
// access line may not carry a count.
func TestNormalizeAggregatedSecurityLine(t *testing.T) {
	site := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000004", "g.example.test", nil, false, 8080)
	other := testSite(scopeB, tenantB, "0d120000-0000-4000-8000-000000000005", "o.example.test", nil, false, 8080)
	digest, otherDigest := digestOf(t, site), digestOf(t, other)
	registry := NewRegistry()
	if err := registry.Register(3, 3, map[string]string{scopeA: "cfg-g-1", scopeB: "cfg-o-1"}); err != nil {
		t.Fatal(err)
	}
	sites := mapSites{digest: site, otherDigest: other}
	line := `{"schema_version":1,"type":"security.v1","occurred_at":"2026-10-21T10:00:59+00:00","tenant_id":"` + tenantA +
		`","site_id":"` + site.SiteID + `","node_id":"","config_version_id":"","installation_id":"","task_id":null,"request_id":"r1",` +
		`"trace_id":"","host":"g.example.test","path":"/a","client_ip":"127.0.0.7","method":"GET","listen_port":8080,"protocol":"http",` +
		`"request_class":"standard","status_code":503,"request_bytes":80,"response_bytes":900,"security_type":"cc","action":"challenge",` +
		`"severity":"medium","rule_id":"cc_rule:10001","policy_id":"","detector":"","matched":"","user_agent":"","request_body_excerpt":"",` +
		`"request_headers":null,"response_headers":null,"request_body":null,"response_body":null,"ja4":"","origin_connect_us":null,` +
		`"origin_first_byte_us":null,"origin_total_us":null,"count":10,"cdnca":{"generation":3,"scope":"` + scopeA + `","digest":"` +
		digest + `","port":8080}}`
	result, err := Normalize([]byte(line), registry, sites, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := eventspool.ParseSourceLineBound(result.Line, result.CapturePolicy, result.Identity)
	if err != nil || envelope.Count != 10 || envelope.Action != "challenge" || envelope.SiteID != site.SiteID {
		t.Fatalf("spool %v count %d\n%s", err, envelope.Count, result.Line)
	}
	forged := strings.Replace(line, `"digest":"`+digest, `"digest":"`+otherDigest, 1)
	if _, err := Normalize([]byte(forged), registry, sites, nodeID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged attribution: %v", err)
	}
	over := strings.Replace(line, `"count":10`, `"count":1000000001`, 1)
	if result, err := Normalize([]byte(over), registry, sites, nodeID); err == nil {
		if _, err := eventspool.ParseSourceLineBound(result.Line, result.CapturePolicy, result.Identity); err == nil {
			t.Fatal("count above the bound accepted")
		}
	}
	access := accessLine(site, digest, "g.example.test", 3, 8080)
	access = strings.Replace(access, `,"cdnca":`, `,"count":2,"cdnca":`, 1)
	if result, err := Normalize([]byte(access), registry, sites, nodeID); err == nil {
		if _, err := eventspool.ParseSourceLineBound(result.Line, result.CapturePolicy, result.Identity); err == nil {
			t.Fatal("access line with a count accepted")
		}
	}
}
