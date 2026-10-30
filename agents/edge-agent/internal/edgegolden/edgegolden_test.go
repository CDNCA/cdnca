package edgegolden

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeScenario(t *testing.T, directory, name, body string) string {
	t.Helper()
	path := filepath.Join(directory, name+".json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

const minimalScenario = `{
  "name": "%s", "description": "d", "covers": ["c"],
  "facts": {"document": {"x": "${trust:origin}"}, "node": {"health_port": 1}},
  "origins": [{"name": "o", "address": "127.0.0.1:1"}],
  "steps": [{"id": "s", "port": 1}]
}`

func TestLoadScenarioChecksShapeAndDefaults(t *testing.T) {
	directory := t.TempDir()
	scenario, err := LoadScenario(writeScenario(t, directory, "ok", fmt.Sprintf(minimalScenario, "ok")))
	if err != nil {
		t.Fatal(err)
	}
	if scenario.Steps[0].Kind != "http" || len(scenario.Digest()) != 64 || !contains(scenario.Mask.ResponseHeaders, "date") {
		t.Fatalf("defaults not applied: %+v", scenario)
	}
	for name, body := range map[string]string{
		"wrong-name":  fmt.Sprintf(minimalScenario, "other"),
		"unknown-key": strings.Replace(fmt.Sprintf(minimalScenario, "unknown-key"), `"covers"`, `"cover": [], "covers"`, 1),
		"dup-step":    strings.Replace(fmt.Sprintf(minimalScenario, "dup-step"), `[{"id": "s", "port": 1}]`, `[{"id": "s", "port": 1}, {"id": "s", "port": 1}]`, 1),
		"bad-kind":    strings.Replace(fmt.Sprintf(minimalScenario, "bad-kind"), `{"id": "s", "port": 1}`, `{"id": "s", "kind": "x"}`, 1),
		"no-port":     strings.Replace(fmt.Sprintf(minimalScenario, "no-port"), `{"id": "s", "port": 1}`, `{"id": "s"}`, 1),
		"bad-pattern": strings.Replace(fmt.Sprintf(minimalScenario, "bad-pattern"), `"steps"`, `"mask": {"patterns": ["("]}, "steps"`, 1),
		"dup-origin":  strings.Replace(fmt.Sprintf(minimalScenario, "dup-origin"), `[{"name": "o", "address": "127.0.0.1:1"}]`, `[{"name": "o", "address": "a"}, {"name": "o", "address": "b"}]`, 1),
		"no-health":   strings.Replace(fmt.Sprintf(minimalScenario, "no-health"), `"health_port": 1`, `"health_port": 0`, 1),
	} {
		if _, err := LoadScenario(writeScenario(t, directory, name, body)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestExpandReplacesKnownPlaceholdersAndRejectsUnknown(t *testing.T) {
	raw := []byte(`{"a": "${trust:origin}", "b": "${deployment_root}/x"}`)
	if got := Placeholders(raw); strings.Join(got, ",") != "deployment_root,trust:origin" {
		t.Fatalf("placeholders %v", got)
	}
	expanded, err := Expand(raw, map[string]string{"trust:origin": "sha256:ab", "deployment_root": "/d"})
	if err != nil || string(expanded) != `{"a": "sha256:ab", "b": "/d/x"}` {
		t.Fatalf("expanded %s %v", expanded, err)
	}
	if _, err := Expand(raw, map[string]string{"trust:origin": "x"}); err == nil || !strings.Contains(err.Error(), "deployment_root") {
		t.Fatalf("unknown placeholder: %v", err)
	}
}

func observationWith(steps ...StepResult) *Observation {
	return &Observation{Schema: ObservationSchema, Scenario: "s", Digest: "d", Steps: steps}
}

func TestCompareMatchesStepsByIDAndAppliesRules(t *testing.T) {
	expected := observationWith(
		StepResult{ID: "a", Kind: "http", Responses: []Response{{Status: 200, Headers: map[string]string{"server": "openresty", "x": "1"}, Origin: []OriginRequest{}}}},
		StepResult{ID: "b", Kind: "tls", TLS: &TLSResult{Error: "tls_alert_unrecognized_name"}},
	)
	actual := observationWith(
		StepResult{ID: "b", Kind: "tls", TLS: &TLSResult{Error: "tls_alert_internal_error"}},
		StepResult{ID: "a", Kind: "http", Responses: []Response{{Status: 200, Headers: map[string]string{"server": "openresty", "x": "2", "y": "3"}, Origin: []OriginRequest{}}}},
	)
	rules := Rules{Schema: RulesSchema,
		Incomparable:    []Rule{{Path: "*/a/responses/*/headers/x", Reason: "detail"}},
		SemanticChanges: []Rule{{Path: "**/tls/error", Reason: "ADR 0009 §6", Renderers: []string{"dynamic"}}}}

	report, err := Compare(rules, "cdnca-v7", expected, actual)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]Difference{}
	for _, difference := range report.Differences {
		byPath[difference.Path] = difference
	}
	if len(byPath) != 3 || byPath["s/a/responses/0/headers/x"].Waived != "incomparable" ||
		byPath["s/a/responses/0/headers/y"].Kind != "extra" || byPath["s/a/responses/0/headers/y"].Waived != "" ||
		byPath["s/b/tls/error"].Waived != "" {
		t.Fatalf("differences %+v", report.Differences)
	}
	// The semantic change waives the TLS difference only for its renderer.
	report, _ = Compare(rules, "dynamic", expected, actual)
	for _, difference := range report.Differences {
		if difference.Path == "s/b/tls/error" && difference.Waived != "semantic_change" {
			t.Fatalf("semantic change not applied: %+v", difference)
		}
	}
	whole := &Report{Scenarios: []ScenarioReport{report}}
	if whole.Defects() != 1 {
		t.Fatalf("defects %d", whole.Defects())
	}

	// A rule on a prefix waives the subtree.
	if _, ok := matchRule([]Rule{{Path: "*/a/responses", Reason: "r"}}, "s/a/responses/0/body/sha256", ""); !ok {
		t.Fatal("prefix rule did not cover the subtree")
	}
	if _, ok := matchRule([]Rule{{Path: "*/a/responses/*/body", Reason: "r"}}, "s/a/responses/0/headers/x", ""); ok {
		t.Fatal("rule matched a sibling")
	}

	same, _ := Compare(rules, "cdnca-v7", expected, expected)
	if same.Status != "same" || len(same.Differences) != 0 {
		t.Fatalf("self comparison %+v", same)
	}
	stale := *actual
	stale.Digest = "other"
	if report, _ := Compare(rules, "cdnca-v7", expected, &stale); report.Status != "stale_golden" {
		t.Fatalf("stale golden: %+v", report)
	}
}

func TestLoadRulesRequiresReasons(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	_ = os.WriteFile(path, []byte(`{"schema":"cdnca.edge-golden.compare/v1","incomparable":[{"path":"a"}],"semantic_changes":[]}`), 0o644)
	if _, err := LoadRules(path); err == nil {
		t.Fatal("rule without reason accepted")
	}
	_ = os.WriteFile(path, []byte(`{"schema":"cdnca.edge-golden.compare/v1","incomparable":[{"path":"a/[","reason":"x"}],"semantic_changes":[]}`), 0o644)
	if _, err := LoadRules(path); err == nil {
		t.Fatal("bad pattern accepted")
	}
}

func TestClassifyErrorIsStable(t *testing.T) {
	for text, want := range map[string]string{
		"dial tcp 127.0.0.1:1: connect: connection refused":                 "connect_refused",
		"remote error: tls: unrecognized name":                              "tls_alert_unrecognized_name",
		"remote error: tls: internal error":                                 "tls_alert_internal_error",
		"read tcp 127.0.0.1:5->127.0.0.1:6: read: connection reset by peer": "connection_reset",
		"unexpected EOF":                         "unexpected_eof",
		`Get "http://x/": EOF`:                   "eof",
		"something at 10.0.0.1:443 and [::1]:80": "error: something at <address> and <address>",
	} {
		if got := classifyError(errors.New(text)); got != want {
			t.Errorf("%q: %q, want %q", text, got, want)
		}
	}
}

// proxyRenderer is a stand-in runtime (a Go reverse proxy per listener port):
// it lets the runner be tested without OpenResty.
type proxyRenderer struct {
	listen, origin string
}

func (renderer proxyRenderer) Name() string { return "test-proxy" }

func (renderer proxyRenderer) Start(context.Context, Env, *Scenario) (Instance, error) {
	target, _ := url.Parse("http://" + renderer.origin)
	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(request *http.Request) {
		director(request)
		request.Header.Set("X-Forwarded-Proto", "http")
	}
	listener, err := net.Listen("tcp", renderer.listen)
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: proxy}
	go func() { _ = server.Serve(listener) }()
	return &proxyInstance{server: server}, nil
}

type proxyInstance struct{ server *http.Server }

func (instance *proxyInstance) Logs(context.Context) ([]LogRecord, error) {
	return []LogRecord{{Stream: "access", Fields: map[string]any{"status_code": 200, "occurred_at": time.Now().String()}}}, nil
}
func (instance *proxyInstance) CacheEntries(context.Context, string) ([]string, error) {
	return nil, nil
}
func (instance *proxyInstance) Task(context.Context, TaskSpec) (*TaskResult, error) {
	return &TaskResult{State: "succeeded"}, nil
}
func (instance *proxyInstance) Stop(context.Context) error { return instance.server.Close() }
func (instance *proxyInstance) Publish(context.Context, Publication) error { return nil }

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func TestRunIsReproducible(t *testing.T) {
	edge, origin := freePort(t), freePort(t)
	_, edgePort, _ := net.SplitHostPort(edge)
	scenarioJSON := fmt.Sprintf(`{
  "name": "proxy", "description": "d", "covers": ["c"],
  "facts": {"document": {}, "node": {"health_port": 1}},
  "origins": [{"name": "o", "address": %q, "routes": [
    {"path": "/missing", "status": 404, "body": "nope"},
    {"path": "/gz", "body": "zipped ${request}", "gzip": true, "headers": {"Cache-Control": "max-age=60"}},
    {"path": "/nonce", "body": "token=abcdef0123456789abcdef0123456789"}]}],
  "mask": {"patterns": ["[0-9a-f]{32}"]},
  "steps": [
    {"id": "get", "port": %s, "host": "a.example.test", "path": "/p?q=1"},
    {"id": "missing", "port": %s, "host": "a.example.test", "path": "/missing"},
    {"id": "gz", "port": %s, "host": "a.example.test", "path": "/gz", "headers": {"Accept-Encoding": "gzip"}},
    {"id": "nonce", "port": %s, "host": "a.example.test", "path": "/nonce"},
    {"id": "post", "method": "POST", "port": %s, "host": "a.example.test", "path": "/f", "body": "a=1", "chunked": true},
    {"id": "repeat", "port": %s, "host": "a.example.test", "repeat": 3, "summary": true},
    {"id": "burst", "port": %s, "host": "a.example.test", "repeat": 3, "concurrent": true},
    {"id": "logs", "kind": "logs"},
    {"id": "refused", "port": 1, "host": "a.example.test"}
  ]
}`, origin, edgePort, edgePort, edgePort, edgePort, edgePort, edgePort, edgePort)
	directory := t.TempDir()
	scenario, err := LoadScenario(writeScenario(t, directory, "proxy", scenarioJSON))
	if err != nil {
		t.Fatal(err)
	}
	pki, err := NewPKI()
	if err != nil {
		t.Fatal(err)
	}
	renderer := proxyRenderer{listen: edge, origin: origin}
	var encoded [][]byte
	for range 2 {
		// A fresh PKI per run, as every real run has.
		env := Env{WorkDir: t.TempDir(), PKI: pki}
		pki, _ = NewPKI()
		observation, err := Run(t.Context(), renderer, env, scenario)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := observation.Encode()
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, raw)
	}
	if !bytes.Equal(encoded[0], encoded[1]) {
		t.Fatalf("two runs differ:\n%s\n---\n%s", encoded[0], encoded[1])
	}
	text := string(encoded[0])
	for _, want := range []string{`"text": "o a.example.test /p?q=1"`, `"status": 404`, `"content-encoding": "gzip"`,
		`"text": "token=<masked>"`, `"transfer-encoding"`, `"statuses": {` + "\n" + `          "200": 3`,
		`"occurred_at": "<masked>"`, `"error": "connect_refused"`, `"user-agent": "cdnca-edge-golden/1"`, `"date": "<masked>"`} {
		if !strings.Contains(text, want) {
			t.Errorf("observation lacks %q:\n%s", want, text)
		}
	}
	if err := WriteObservation(directory, mustObservation(t, encoded[0])); err != nil {
		t.Fatal(err)
	}
	read, found, err := ReadObservation(directory, "proxy")
	if err != nil || !found {
		t.Fatalf("read back: %v %v", found, err)
	}
	again, _ := read.Encode()
	if !bytes.Equal(again, encoded[0]) {
		t.Fatal("golden does not round trip")
	}
}

func mustObservation(t *testing.T, raw []byte) *Observation {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxy.json")
	_ = os.WriteFile(path, raw, 0o644)
	observation, _, err := ReadObservation(filepath.Dir(path), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func TestRunSkipsWhatTheEnvironmentLacks(t *testing.T) {
	scenario := &Scenario{Name: "s", Requires: []string{"managed_waf"}}
	_, err := Run(t.Context(), proxyRenderer{}, Env{}, scenario)
	var skipped ErrSkipped
	if !errors.As(err, &skipped) || skipped.Missing[0] != "managed_waf" {
		t.Fatalf("err %v", err)
	}
}

func TestReportText(t *testing.T) {
	report := &Report{Renderer: "r", Expected: "e", Scenarios: []ScenarioReport{{Scenario: "a", Status: "same"},
		{Scenario: "b", Status: "different", Differences: []Difference{{Path: "b/x", Kind: "changed", Expected: 1, Actual: 2}}}}}
	var output bytes.Buffer
	report.WriteText(&output)
	if !strings.Contains(output.String(), "DIFF b/x [changed] expected=1 actual=2") ||
		!strings.Contains(output.String(), "summary: 2 scenarios (different=1 same=1), 1 defects, 0 waived") {
		t.Fatalf("report:\n%s", output.String())
	}
	_, _ = io.Discard.Write(nil)
}
