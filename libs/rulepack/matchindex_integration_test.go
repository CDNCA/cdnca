//go:build integration

package rulepack

// Match index (ADR 0011 §6.5, RI-16) in a real OpenResty (the node image's
// release, one --rm container): every plan is run by the interpreter twice,
// linear (the D6 path, index dropped) and indexed, on the same requests.
//
//	TestMatchIndexDifferential  decisions, trace, body read and inspect
//	                            evidence must be identical per request
//	                            (D6 golden corpus + generated 20..50 000-rule plans)
//	TestMatchIndexBenchmark     CDNCA_RULE_BENCH=1: p50 / p99 per request and
//	                            memory at 1k / 10k / 50k rules, both paths
//
// Run through the machine queue (BATCH-PLUGIN 25):
//
//	go -C libs/rulepack test -tags integration -run TestMatchIndex -count=1 -v .

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const indexImage = "openresty/openresty@sha256:035818c9596ce60cdc816fc1941db0414d50398644ec9567b45fded04a76e7d0"

const indexBasePort = 18080

type indexServer struct {
	t         *testing.T
	work      string
	container string
}

func startIndexServer(t *testing.T, plans []edgeconfig.RulePlan) *indexServer {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if output, err := exec.Command("docker", "image", "inspect", indexImage).CombinedOutput(); err != nil {
		t.Fatalf("image %s missing: %s", indexImage, output)
	}
	repo, _ := filepath.Abs("../..")
	work := t.TempDir()
	for _, dir := range []string{"lua", "plans", "logs"} {
		if err := os.MkdirAll(filepath.Join(work, dir), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	copyFile := func(source, target string) {
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, target), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(filepath.Join(repo, "edge/openresty/lua/cdnca_rule_interp.lua"), "lua/cdnca_rule_interp.lua")
	copyFile(filepath.Join(repo, "edge/openresty/lua/cdnca_waf.lua"), "lua/cdnca_waf.lua")
	for _, name := range []string{"index_harness.lua", "cdnca_iplib.lua", "rule_client.lua"} {
		copyFile(filepath.Join("rulegen/lua", name), "lua/"+name)
	}
	for index, plan := range plans {
		encoded, err := edgeconfig.EncodeRulePlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, "plans", fmt.Sprintf("%d.json", index)), encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	conf := fmt.Sprintf(`worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 1024; }
http {
  access_log off;
  lua_package_path "$prefix/lua/?.lua;;";
  client_body_temp_path /tmp/rule-index-body;
  client_body_buffer_size 128k;
  client_max_body_size 1m;
  large_client_header_buffers 8 16k;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  lua_shared_dict cdnca_waf_state 4m;
  init_by_lua_block { require("index_harness").preload(%d) }
  server {
    listen 127.0.0.1:%d;
    listen 127.0.0.1:%d;
    listen 127.0.0.1:%d;
    server_name _;
    set $cdnca_security_emit 0;
    set $cdnca_security_type "";
    set $cdnca_security_action "";
    set $cdnca_security_severity "";
    set $cdnca_security_rule_id "";
    set $cdnca_security_block_page 0;
    set $cdnca_security_policy_id "";
    set $cdnca_security_detector "";
    set $cdnca_security_matched "";
    set $cdnca_security_body "";
    set $cdnca_ja4 $http_x_test_ja4;
    location = /__stats { content_by_lua_block { require("index_harness").stats() } }
    location / { content_by_lua_block { require("index_harness").content() } }
  }
}
`, len(plans), indexBasePort, indexBasePort+1, indexBasePort+2)
	if err := os.WriteFile(filepath.Join(work, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("chmod", "-R", "a+rwX", work).Run(); err != nil {
		t.Fatal(err)
	}
	server := &indexServer{t: t, work: work, container: fmt.Sprintf("cdnca-ri-16-%d", time.Now().UnixNano())}
	if output, err := exec.Command("docker", "run", "-d", "--rm", "--name", server.container, "--network", "none",
		"-v", work+":/w", "--entrypoint", "sh", indexImage, "-c", "sleep 7200").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", server.container).Run() })
	if output, err := server.exec("openresty -p /w/ -c nginx.conf"); err != nil {
		t.Fatalf("nginx start: %v %s", err, output)
	}
	return server
}

func (server *indexServer) exec(command string) ([]byte, error) {
	return exec.Command("docker", "exec", server.container, "sh", "-c", command).CombinedOutput()
}

type indexResult struct {
	Status int
	Result string
}

// send runs raw requests (id -> bytes, port) through the in-container client.
func (server *indexServer) send(requests map[string][]byte, ports map[string]int) map[string]indexResult {
	server.t.Helper()
	ids := make([]string, 0, len(requests))
	for id := range requests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// Requests go in on stdin and results come back on stdout: a large file
	// written on the host may reach the container through the Docker Desktop
	// bind mount incomplete.
	var lines bytes.Buffer
	for _, id := range ids {
		line, _ := json.Marshal(map[string]any{"id": id, "port": ports[id], "raw": base64.StdEncoding.EncodeToString(requests[id])})
		lines.Write(line)
		lines.WriteByte('\n')
	}
	command := exec.Command("docker", "exec", "-i", server.container, "sh", "-c",
		"cat > /tmp/requests.jsonl && cd /w && resty lua/rule_client.lua /tmp/requests.jsonl /tmp/results.jsonl 8 >/dev/null && cat /tmp/results.jsonl")
	command.Stdin = &lines
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		server.t.Fatalf("client: %v %s", err, stderr.Bytes())
	}
	results := map[string]indexResult{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		var line struct {
			ID     string `json:"id"`
			Status int    `json:"status"`
			Result string `json:"result"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			server.t.Fatal(err)
		}
		results[line.ID] = indexResult{Status: line.Status, Result: line.Result}
	}
	if len(results) != len(requests) {
		server.t.Fatalf("%d results for %d requests", len(results), len(requests))
	}
	return results
}

func (server *indexServer) checkErrorLog() {
	server.t.Helper()
	content, _ := os.ReadFile(filepath.Join(server.work, "logs/error.log"))
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "[error]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[alert]") ||
			strings.Contains(line, "[emerg]") {
			server.t.Fatalf("error log: %s", line)
		}
	}
}

// goldenRequest is edgeconfig's fuzzRequest (testdata/ruleplan/golden.json).
type goldenRequest struct {
	Port    int    `json:"port"`
	Method  string `json:"method"`
	Target  string `json:"target"`
	Host    string `json:"host"`
	RealIP  string `json:"real_ip,omitempty"`
	JA4     string `json:"ja4,omitempty"`
	Headers []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"headers,omitempty"`
	Filler      int    `json:"filler,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
}

func (request goldenRequest) raw(caseHeader string) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "%s %s HTTP/1.1\r\nHost: %s\r\nX-Cdnca-Case: %s\r\nConnection: close\r\n", request.Method, request.Target, request.Host, caseHeader)
	if request.RealIP != "" {
		fmt.Fprintf(&out, "X-Real-IP: %s\r\n", request.RealIP)
	}
	if request.JA4 != "" {
		fmt.Fprintf(&out, "X-Test-JA4: %s\r\n", request.JA4)
	}
	for _, header := range request.Headers {
		fmt.Fprintf(&out, "%s: %s\r\n", header.Name, header.Value)
	}
	for index := 0; index < request.Filler; index++ {
		fmt.Fprintf(&out, "X-Filler-%d: %d\r\n", index, index)
	}
	if request.Body != "" {
		fmt.Fprintf(&out, "Content-Type: %s\r\nContent-Length: %d\r\n", request.ContentType, len(request.Body))
	}
	out.WriteString("\r\n")
	out.WriteString(request.Body)
	return []byte(out.String())
}

// goldenPlans: the D6 differential golden corpus as indexed plans.
func goldenPlans(t *testing.T) ([]edgeconfig.RulePlan, [][]goldenRequest) {
	t.Helper()
	content, err := os.ReadFile("../edgeconfig/testdata/ruleplan/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Set struct {
			Layered        bool                              `json:"layered"`
			OverflowBlocks bool                              `json:"overflow_blocks"`
			Telemetry      bool                              `json:"telemetry"`
			Policies       []edgeconfig.SecurityPolicy       `json:"policies"`
			Segments       []edgeconfig.RulePlanSegmentInput `json:"segments"`
		} `json:"set"`
		Requests []goldenRequest `json:"requests"`
	}
	if err := json.Unmarshal(content, &corpus); err != nil {
		t.Fatal(err)
	}
	var plans []edgeconfig.RulePlan
	var requests [][]goldenRequest
	for index, item := range corpus {
		var plan edgeconfig.RulePlan
		if item.Set.Layered {
			plan, err = edgeconfig.CompileLayeredRulePlan(item.Set.Segments, item.Set.OverflowBlocks, item.Set.Telemetry)
		} else {
			plan, err = edgeconfig.CompileSecurityRulePlan(item.Set.Policies, item.Set.OverflowBlocks, item.Set.Telemetry)
		}
		if err != nil {
			t.Fatalf("golden set %d: %v", index, err)
		}
		if err := AttachMatchIndex(&plan); err != nil {
			t.Fatalf("golden set %d index: %v", index, err)
		}
		plans, requests = append(plans, plan), append(requests, item.Requests)
	}
	return plans, requests
}

func TestMatchIndexDifferential(t *testing.T) {
	plans, golden := goldenPlans(t)
	raws, ports := map[string][]byte{}, map[string]int{}
	add := func(set int, number int, raw func(string) []byte, port int) {
		for _, mode := range []string{"linear", "index"} {
			id := fmt.Sprintf("%03d-%06d-%s", set, number, mode)
			raws[id], ports[id] = raw(mode+":"+strconv.Itoa(set)), port
		}
	}
	for set, requests := range golden {
		for number, request := range requests {
			add(set, number, request.raw, request.Port)
		}
	}
	goldenSets := len(plans)
	sizes := []int{20, 20, 200, 200, 2000, 10000, 50000}
	perSet := ruleEnvInt("CDNCA_RULE_INDEX_REQUESTS", 1500)
	for seed, size := range sizes {
		g := newRuleGen(uint64(1000 + seed))
		plans = append(plans, genPlan(t, g, size, true))
		set := len(plans) - 1
		for number := 0; number < perSet; number++ {
			add(set, number, g.Request(g.Pct(70)).Raw, indexBasePort)
		}
	}
	server := startIndexServer(t, plans)
	started := time.Now()
	results := server.send(raws, ports)
	server.checkErrorLog()
	var differences, compared, hits, blocks, logs, bodies int
	for id, linear := range results {
		if !strings.HasSuffix(id, "-linear") {
			continue
		}
		indexed := results[strings.TrimSuffix(id, "-linear")+"-index"]
		compared++
		if linear.Status != 200 && linear.Status != 403 {
			t.Errorf("%s: status %d %s", id, linear.Status, linear.Result)
		}
		if linear != indexed {
			differences++
			if differences <= 10 {
				t.Errorf("DIFF %s\n linear %+v\n index  %+v", id, linear, indexed)
			}
		}
		fields := strings.Split(linear.Result, "|")
		if len(fields) > 5 {
			switch fields[0] {
			case "block":
				blocks++
			case "log":
				logs++
			}
			if fields[2] != "" && !strings.HasSuffix(fields[2], ":default") {
				hits++
			}
			if fields[5] == "body" {
				bodies++
			}
		}
	}
	t.Logf("plans %d (golden %d, generated %v), requests %d x 2 in %s: rule hits %d, block %d, log %d, body read %d; differences %d",
		len(plans), goldenSets, sizes, compared, time.Since(started).Round(time.Millisecond), hits, blocks, logs, bodies, differences)
	if differences > 0 {
		t.Fatalf("%d differences between the linear and the indexed interpreter", differences)
	}
	if hits == 0 || blocks == 0 || logs == 0 || bodies == 0 {
		t.Fatal("corpus too weak")
	}
}

func ruleEnvInt(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && value > 0 {
		return value
	}
	return fallback
}

// TestMatchIndexBenchmark: per-request evaluation time (CLOCK_MONOTONIC
// around interp.evaluate) per size, indexed over 10 000 attack + 10 000
// normal requests (no body / large JSON body / long query), the D6 linear
// path over a sample (CDNCA_RULE_BENCH_LINEAR, it is linear in the rules).
// cold includes extracting the request values; warm times matching only.
func TestMatchIndexBenchmark(t *testing.T) {
	if os.Getenv("CDNCA_RULE_BENCH") != "1" {
		t.Skip("set CDNCA_RULE_BENCH=1")
	}
	requests := ruleEnvInt("CDNCA_RULE_BENCH_REQUESTS", 10000)
	linearSample := ruleEnvInt("CDNCA_RULE_BENCH_LINEAR", 400)
	type timing struct {
		P50, P99 float64
		N        int
	}
	type row struct {
		Rules                     int
		Timing                    map[string]timing
		LinearHeapKB, IndexHeapKB float64
		RSSKB                     float64
		// RSSSplitKB: worker RSS at start (base), after the indexed program
		// and after the linear program too (before any request).
		RSSSplitKB map[string]float64
		Cost       MatchCost
	}
	var rows []row
	// CDNCA_RULE_BENCH_SIZES (comma separated) runs one size per queue slot
	// (BATCH-PLUGIN 25: one benchmark <= 10 minutes).
	sizes := []int{1000, 10000, 50000}
	if value := os.Getenv("CDNCA_RULE_BENCH_SIZES"); value != "" {
		sizes = nil
		for _, field := range strings.Split(value, ",") {
			size, err := strconv.Atoi(field)
			if err != nil {
				t.Fatalf("CDNCA_RULE_BENCH_SIZES %q", value)
			}
			sizes = append(sizes, size)
		}
	}
	for _, size := range sizes {
		g := newRuleGen(uint64(size))
		plan := genPlan(t, g, size, true)
		var index MatchIndex
		_ = json.Unmarshal(plan.Index, &index)
		server := startIndexServer(t, []edgeconfig.RulePlan{plan})
		// Batches keep the request file small (large JSON bodies).
		raws, ports := map[string][]byte{}, map[string]int{}
		for number := 0; number < 2*requests; number++ {
			request := g.Request(number%2 == 0)
			modes := []string{"index"}
			if number < linearSample {
				modes = append(modes, "linear")
			}
			for _, mode := range modes {
				for _, kind := range []string{"cold", "warm"} {
					id := fmt.Sprintf("%06d-%s-%s", number, mode, kind)
					raws[id] = request.Raw(mode + ":0\r\nX-Cdnca-Time: " + kind)
					// The same sample once more under its request class.
					raws[id+"-c"] = request.Raw(mode + ":0\r\nX-Cdnca-Time: " + kind + "\r\nX-Cdnca-Class: " + request.Class())
					ports[id+"-c"] = indexBasePort
					ports[id] = indexBasePort
				}
			}
			if len(raws) >= 2000 || number == 2*requests-1 {
				server.send(raws, ports)
				raws, ports = map[string][]byte{}, map[string]int{}
			}
		}
		server.checkErrorLog()
		output, err := server.exec(fmt.Sprintf("curl -sS http://127.0.0.1:%d/__stats", indexBasePort))
		if err != nil {
			t.Fatalf("stats: %v %s", err, output)
		}
		var stats struct {
			RSSKB      float64            `json:"rss_kb"`
			RSSSplitKB map[string]float64 `json:"rss_split_kb"`
			HeapKB     map[string]float64 `json:"heap_kb"`
			Timing     map[string]timing  `json:"timing"`
		}
		if err := json.Unmarshal(output, &stats); err != nil {
			t.Fatalf("stats %q: %v", output, err)
		}
		if stats.Timing["index:warm"].N != 2*requests || stats.Timing["linear:warm"].N != min(linearSample, 2*requests) {
			t.Fatalf("%d rules: samples %+v", size, stats.Timing)
		}
		for key, value := range stats.Timing {
			stats.Timing[key] = timing{P50: value.P50 / 1000, P99: value.P99 / 1000, N: value.N}
		}
		rows = append(rows, row{Rules: size, Timing: stats.Timing, LinearHeapKB: stats.HeapKB["linear:0"],
			IndexHeapKB: stats.HeapKB["index:0"], RSSKB: stats.RSSKB, RSSSplitKB: stats.RSSSplitKB, Cost: index.Cost})
		_ = exec.Command("docker", "rm", "-f", server.container).Run()
	}
	report, _ := json.MarshalIndent(rows, "", "  ")
	t.Logf("report:\n%s", report)
	for _, item := range rows {
		line := fmt.Sprintf("%6d rules |", item.Rules)
		for _, key := range []string{"linear:cold", "linear:warm", "index:cold", "index:warm", "index:warm:nobody",
			"index:warm:json", "index:warm:query", "linear:warm:nobody", "linear:warm:json", "linear:warm:query"} {
			value := item.Timing[key]
			line += fmt.Sprintf(" %s p50 %.1fus p99 %.1fus (n %d) |", key, value.P50, value.P99, value.N)
		}
		split := item.RSSSplitKB
		t.Logf("%s heap linear %.1f MiB index %.1f MiB, worker RSS %.1f MiB (base %.1f, +indexed program %.1f, +linear program %.1f, +requests %.1f)",
			line, item.LinearHeapKB/1024, item.IndexHeapKB/1024, item.RSSKB/1024, split["base"]/1024,
			(split["index"]-split["base"])/1024, (split["linear"]-split["index"])/1024, (item.RSSKB-split["linear"])/1024)
	}
	if path := os.Getenv("CDNCA_RULE_BENCH_REPORT"); path != "" {
		_ = os.WriteFile(path, report, 0o644)
	}
}
