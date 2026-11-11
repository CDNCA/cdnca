package dyntelemetry

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// recordingSender keeps every record the publisher hands to the transport.
type recordingSender struct{ records []telemetryclient.Record }

func (s *recordingSender) Send(_ context.Context, batch telemetryclient.Batch) (telemetryclient.SendAck, error) {
	s.records = append(s.records, batch.Records...)
	return telemetryclient.SendAck{Accepted: len(batch.Records)}, nil
}

// goldenLines is a fixed corpus of node log lines: both formats (plain
// log_format, capture JSON built by Lua) and the edge cases of their bytes.
func goldenLines(t *testing.T, sites []perfSite, at string) (access, security []string) {
	fill := func(kind string, site perfSite, rid string) string {
		raw, err := os.ReadFile(filepath.Join("testdata", "perf-"+kind+".jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		return strings.NewReplacer("__SITE__", site.site.SiteID, "__TENANT__", site.site.TenantID,
			"__SCOPE__", site.site.ConfigurationScopeID, "__DIGEST__", site.digest, "__HOST__", site.site.Hosts.Primary,
			"__RID__", rid, "__AT__", at, "__CONN__", "7").Replace(strings.TrimSpace(string(raw)))
	}
	formats := regexp.MustCompile(`log_format (\S+) escape=json '([^']*)';`).FindAllStringSubmatch(edgeconfig.RenderDynamicRoutingTelemetryHTTP(), -1)
	plain := func(format string, site perfSite, rid, uri string) string {
		for _, match := range formats {
			if match[1] != format {
				continue
			}
			values := map[string]string{"time_iso8601": at, "cdnca_tenant_id": site.site.TenantID, "cdnca_site_id": site.site.SiteID,
				"request_id": rid, "host": site.site.Hosts.Primary, "uri": uri, "cdnca_security_path": uri,
				"cdnca_telemetry_client_ip": "203.0.113.9", "request_method": "POST", "server_protocol": "HTTP/2.0", "scheme": "https",
				"connection": "42", "connection_requests": "3", "cdnca_telemetry_cache_status": "HIT", "status": "429",
				"request_length": "512", "bytes_sent": "77", "cdnca_duration_us": "1500", "cdnca_origin_connect_us": "null",
				"cdnca_origin_first_byte_us": "null", "cdnca_origin_total_us": "null", "cdnca_security_block_page_log": "true",
				"cdnca_client_browser": "other", "cdnca_client_os": "other", "cdnca_upstream_addr_log": "",
				"cdnca_security_request_class": "standard", "cdnca_security_type": "cc", "cdnca_security_action": "block",
				"cdnca_security_severity": "high", "cdnca_security_rule_id": "cc_rule:10001", "cdnca_security_user_agent": "curl\\/8 <x>&",
				"cdnca_site_generation": "1", "cdnca_site_scope": site.site.ConfigurationScopeID, "cdnca_site_digest": site.digest,
				"cdnca_site_port": "80", "cdnca_telemetry_l2": "false"}
			line := regexp.MustCompile(`\$([a-z0-9_]+)`).ReplaceAllStringFunc(match[2], func(name string) string { return values[name[1:]] })
			return regexp.MustCompile(`"(\w+)":"0"`).ReplaceAllString(line, `"$1":""`)
		}
		t.Fatalf("no %s", format)
		return ""
	}
	a, b := sites[0], sites[1]
	ua := `"User-Agent":"Grafana k6\/2.3.0"`
	access = []string{
		fill("access", a, "a01"),
		fill("access", b, "a02"),
		strings.Replace(fill("access", a, "a03"), ua, `"User-Agent":"Mozilla\/5.0 \u00e9\u4e2d \ud83d\ude00 <b>&amp;"`, 1),
		strings.Replace(fill("access", a, "a04"), ua, `"User-Agent":"`+"caf\xc3\xa9 \xe2\x80\xa8 raw"+`"`, 1),
		strings.Replace(fill("access", a, "a05"), ua, `"User-Agent":"`+"bad\xff\xfeutf8"+`"`, 1),
		strings.Replace(strings.Replace(fill("access", a, "a06"), `,"site_id":`, `, "site_id" :`, 1), `"status_code":200`, `"status_code": 200 `, 1),
		strings.Replace(fill("access", b, "a07"), `"request_body":null`, `"request_body":{"a":1.50,"b":1e3,"c":"x\/y","d":[1,{"e":-0}]}`, 1),
		strings.Replace(fill("access", a, "a08"), `"response_bytes":1304`, `"response_bytes":1304,"response_bytes":1`, 1),
		`{"type":"access.v1",broken`,
		strings.Replace(fill("access", a, "a10"), `"l2":false`, `"l2":true`, 1),
		plain("cdnca_access_json", a, "a11", `/p/<x>&\"q\"\\\\`),
		fill("access", a, "a12"),
	}
	security = []string{
		fill("security", a, "s01"),
		fill("security", b, "s02"),
		strings.Replace(fill("security", a, "s03"), `"listen_port":80`, `"listen_port":80,"count":7`, 1),
		plain("cdnca_security_json", b, "s04", "/login"),
		strings.Replace(fill("security", a, "s05"), `"matched":"Grafana k6\/2.3.0"`, `"matched":"\u0000\u001f\t"`, 1),
		fill("security", a, "s06"),
	}
	return access, security
}

var goldenIDs = regexp.MustCompile(`(evt|msg)_[0-9a-f]{64}`)

// TestPipelineGolden fixes what the agent sends for a corpus of node lines
// (tail results, quarantined lines, every record handed to the transport:
// kind, sequences, payload bytes); event and message ids, which depend on
// the source file's inode, are numbered in order of appearance. A change to
// the pipeline must leave testdata/pipeline-golden.txt byte for byte as is
// (CDNCA_GOLDEN_UPDATE=1 rewrites it).
func TestPipelineGolden(t *testing.T) {
	got := runGoldenPipeline(t)
	path := filepath.Join("testdata", "pipeline-golden.txt")
	if os.Getenv("CDNCA_GOLDEN_UPDATE") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		_ = os.WriteFile(filepath.Join(t.TempDir(), "got.txt"), got, 0o644)
		gotLines, wantLines := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("golden differs at line %d:\n got %q\nwant %q", i+1, gotLines[i], wantLines[i])
			}
		}
		t.Fatalf("golden differs in length: got %d lines want %d", len(gotLines), len(wantLines))
	}
}

type goldenCorpus struct {
	now              time.Time
	sites            mapSites
	registry         *Registry
	access, security []string
}

// goldenFixture: three sites (two with capture, one plain), one generation,
// and the corpus of goldenLines bound to them.
func goldenFixture(t *testing.T) goldenCorpus {
	t.Helper()
	now := time.Date(2026, 11, 10, 9, 31, 31, 0, time.UTC)
	at := now.Add(-time.Minute).Format("2006-01-02T15:04:05+00:00")
	objects := mapSites{}
	scopes := map[string]string{}
	var sites []perfSite
	for i := 0; i < 3; i++ {
		site := testSite(fmt.Sprintf("0d120000-0000-4000-8000-%012d", 500+i), fmt.Sprintf("0d120000-0000-4000-8000-%012d", 600+i),
			fmt.Sprintf("0d120000-0000-4000-8000-%012d", 700+i), fmt.Sprintf("g%d.perf.test", i), nil, i < 2, 80)
		if i < 2 {
			site.Telemetry.Capture.ResponseHeaderAllowlist = []string{"Content-Type"}
			site.Telemetry.Capture.RequestBodyFieldAllowlist = []string{"a", "b", "c", "d"}
		}
		digest := digestOf(t, site)
		objects[digest] = site
		scopes[site.ConfigurationScopeID] = fmt.Sprintf("0d120000-0000-4000-8000-%012d", 800+i)
		sites = append(sites, perfSite{site: site, digest: digest})
	}
	registry := NewRegistry()
	if err := registry.Register(1, 1, scopes); err != nil {
		t.Fatal(err)
	}
	access, security := goldenLines(t, []perfSite{sites[0], sites[1], sites[2]}, at)
	// the plain-format lines belong to the site without capture
	access[10] = strings.NewReplacer(sites[0].site.SiteID, sites[2].site.SiteID, sites[0].site.TenantID, sites[2].site.TenantID,
		sites[0].site.ConfigurationScopeID, sites[2].site.ConfigurationScopeID, sites[0].digest, sites[2].digest,
		sites[0].site.Hosts.Primary, sites[2].site.Hosts.Primary).Replace(access[10])
	security[3] = strings.NewReplacer(sites[1].site.SiteID, sites[2].site.SiteID, sites[1].site.TenantID, sites[2].site.TenantID,
		sites[1].site.ConfigurationScopeID, sites[2].site.ConfigurationScopeID, sites[1].digest, sites[2].digest,
		sites[1].site.Hosts.Primary, sites[2].site.Hosts.Primary).Replace(security[3])
	return goldenCorpus{now: now, sites: objects, registry: registry, access: access, security: security}
}

func runGoldenPipeline(t *testing.T) []byte {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	corpus := goldenFixture(t)
	now, objects, registry, access, security := corpus.now, corpus.sites, corpus.registry, corpus.access, corpus.security
	paths := []string{filepath.Join(root, "access.jsonl"), filepath.Join(root, "security.jsonl")}
	for index, lines := range [][]string{access, security} {
		if err := os.WriteFile(paths[index], []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	lineAt := func(lines []string, offset int64) int {
		position := int64(0)
		for index, line := range lines {
			if position == offset {
				return index
			}
			position += int64(len(line)) + 1
		}
		return -1
	}
	clock := func() time.Time { return now }
	spool, err := eventspool.New(eventspool.Config{Root: filepath.Join(root, "spool"), MaxEventBytes: 64 << 10, MaxSegmentBytes: 16 << 20,
		SoftLimitBytes: 1 << 30, HardLimitBytes: 2 << 30, MaxTenantBytes: 1 << 30, MaxBatchEvents: 10000,
		PressureMode: eventspool.PressureBackpressure, SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 168 * time.Hour, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &Resolver{Registry: registry, Sites: objects, NodeID: nodeID, Grace: time.Minute, Now: clock}
	var out strings.Builder
	stateDir := filepath.Join(root, "tail-state")
	for _, path := range paths {
		tailer, err := eventspool.NewTailer(eventspool.TailConfig{SourcePath: path, StateDir: stateDir,
			Identity: eventspool.TrustedIdentity{EnrollmentNodeID: nodeID}, MaxLineBytes: 64 << 10, MaxBatchEvents: 10000,
			MaxQuarantineBytes: 64 << 20, Resolve: resolver.ResolveTail, Now: clock})
		if err != nil {
			t.Fatal(err)
		}
		result, err := tailer.TailOnce(context.Background(), spool)
		fmt.Fprintf(&out, "tail %s err=%v completed=%d appended=%d quarantined=%d skipped=%d duplicate=%d\n", filepath.Base(path), err,
			result.CompletedLines, result.AppendedEvents, result.QuarantinedLines, result.SkippedLines, result.DuplicateEvents)
		lines := access
		if strings.HasSuffix(path, "security.jsonl") {
			lines = security
		}
		for _, issue := range result.Issues {
			fmt.Fprintf(&out, "  issue %s line=%d\n", issue.Code, lineAt(lines, issue.Offset))
		}
	}
	quarantined, _ := filepath.Glob(filepath.Join(stateDir, "quarantine", "line-*.json"))
	fmt.Fprintf(&out, "quarantine files=%d\n", len(quarantined))
	fmt.Fprintf(&out, "resolver %+v\n", resolver.Counts())
	sender := &recordingSender{}
	publisher, err := telemetryclient.NewPublisher(nodeID, sender)
	if err != nil {
		t.Fatal(err)
	}
	for {
		result, err := spool.Flush(context.Background(), publisher, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if result.Published == 0 {
			break
		}
	}
	ids := map[string]string{}
	number := func(text string) string {
		return goldenIDs.ReplaceAllStringFunc(text, func(id string) string {
			if _, ok := ids[id]; !ok {
				ids[id] = fmt.Sprintf("%s#%d", id[:3], len(ids)+1)
			}
			return ids[id]
		})
	}
	for _, record := range sender.records {
		fmt.Fprintf(&out, "record kind=%s seq=%d-%d events=%d message=%s last=%s\n  %s\n", record.Kind, record.FirstSequence,
			record.LastSequence, record.EventCount, number(record.MessageID), number(record.LastEventID), number(string(record.Payload)))
	}
	return []byte(out.String())
}
