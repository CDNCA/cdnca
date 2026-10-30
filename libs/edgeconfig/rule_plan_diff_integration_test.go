//go:build integration

package edgeconfig

// Differential test of the rule plan interpreter against the rendered rewrite
// Lua, in a real OpenResty (the node image's OpenResty release, one --rm
// container with --network none):
//
//	go -C libs/edgeconfig test -tags integration -run TestRulePlanInterpreterDifferential -count=1 .
//
// Every generated rule set is served twice by one nginx: the oracle
// (renderWAF output as a Lua module, with its geo variables) and
// cdnca_rule_interp with the compiled plan. Each request is sent once per
// mode with identical bytes but the X-Cdnca-Case header; status, security
// telemetry variables, per-segment verdict trace and the call counts of the
// side-effecting conditions must be equal.
//
//	CDNCA_RULE_DIFF_SEEDS     comma-separated seeds (default: the fixed regression seeds)
//	CDNCA_RULE_DIFF_SETS      rule sets per seed (default 120)
//	CDNCA_RULE_DIFF_REQUESTS  requests per rule set (default 40)
//	CDNCA_RULE_DIFF_UPDATE_GOLDEN=1  rewrite testdata/ruleplan/golden.json from the oracle
//	CDNCA_RULE_BENCH=1        TestRulePlanInterpreterBenchmark (1000 rules, p50/p99)
//	CDNCA_RULE_DIFF_IMAGE     OpenResty image (default the pinned node release)

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
)

// The node container image's OpenResty base (edge/openresty/Dockerfile
// OPENRESTY_IMAGE): OpenResty 1.31.1.1, same ngx_lua as the node runtime.
const ruleDiffDefaultImage = "openresty/openresty@sha256:035818c9596ce60cdc816fc1941db0414d50398644ec9567b45fded04a76e7d0"

// Seeds that run by default; add the seed of any difference found here.
var ruleDiffRegressionSeeds = []uint64{20261017, 1, 42, 7340033}

type ruleDiffCase struct {
	index int
	set   fuzzRuleset
}

type ruleDiffGolden struct {
	Set      fuzzRuleset      `json:"set"`
	Requests []fuzzRequest    `json:"requests"`
	Expected []ruleDiffResult `json:"expected"`
}

type ruleDiffResult struct {
	Status int    `json:"status"`
	Result string `json:"result"`
}

func ruleDiffEnvInt(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && value > 0 {
		return value
	}
	return fallback
}

func ruleDiffImage(t *testing.T) string {
	image := os.Getenv("CDNCA_RULE_DIFF_IMAGE")
	if image == "" {
		image = ruleDiffDefaultImage
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if output, err := exec.Command("docker", "image", "inspect", image).CombinedOutput(); err != nil {
		t.Fatalf("image %s missing: %s", image, output)
	}
	return image
}

type ruleDiffServer struct {
	t         *testing.T
	work      string
	container string
}

// startRuleDiffServer writes the release (Lua, plans, oracle modules,
// nginx.conf) into a temp dir and starts nginx in a container.
func startRuleDiffServer(t *testing.T, image string, cases []ruleDiffCase) *ruleDiffServer {
	t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	// lua/resty: the vendored lua-resty-ipmatcher (IP list conditions,
	// ge36-waf), as the node image installs it.
	for _, dir := range []string{"lua/rules", "lua/resty", "plans", "logs"} {
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
	copyFile(filepath.Join(repo, "edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua"), "lua/resty/ipmatcher.lua")
	for _, name := range []string{"rule_harness.lua", "cdnca_iplib.lua", "rule_client.lua"} {
		copyFile(filepath.Join("testdata/ruleplan", name), "lua/"+name)
	}
	var geo strings.Builder
	for _, item := range cases {
		policies, plan, err := item.set.compile()
		if err != nil {
			t.Fatalf("rule set %d: %v", item.index, err)
		}
		module, geoBlocks := renderCompiledRuleModule(item.index, policies, item.set.OverflowBlocks, item.set.Telemetry)
		geo.WriteString(geoBlocks)
		encoded, err := EncodeRulePlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, "lua/rules", fmt.Sprintf("r%d.lua", item.index)), []byte(module), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(work, "plans", fmt.Sprintf("%d.json", item.index)), encoded, 0o644); err != nil {
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
  client_body_temp_path /tmp/rule-diff-body;
  client_body_buffer_size 128k;
  large_client_header_buffers 8 16k;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  lua_shared_dict cdnca_waf_state 4m;
  init_by_lua_block { require("rule_harness") }
%s  server {
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
    location = /__bench {
      content_by_lua_block { require("rule_harness").bench() }
    }
    location / {
      rewrite_by_lua_block { require("rule_harness").rewrite() }
      header_filter_by_lua_block { require("rule_harness").header_filter() }
      content_by_lua_block { ngx.say("ok") }
    }
  }
}
`, geo.String(), fuzzBasePort, fuzzBasePort+1, fuzzBasePort+2)
	if err := os.WriteFile(filepath.Join(work, "nginx.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("chmod", "-R", "a+rwX", work).Run(); err != nil {
		t.Fatal(err)
	}
	server := &ruleDiffServer{t: t, work: work, container: fmt.Sprintf("cdnca-dr-d6-ruleinterp-%d", time.Now().UnixNano())}
	if output, err := exec.Command("docker", "run", "-d", "--rm", "--name", server.container, "--network", "none",
		"-v", work+":/w", "--entrypoint", "sh", image, "-c", "sleep 3600").CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", server.container).Run() })
	if output, err := server.exec("openresty -p /w/ -c nginx.conf"); err != nil {
		t.Fatalf("nginx start: %v %s", err, output)
	}
	return server
}

func (server *ruleDiffServer) exec(command string) ([]byte, error) {
	return exec.Command("docker", "exec", server.container, "sh", "-c", command).CombinedOutput()
}

// send runs every request through the in-container client and returns the
// results by request id.
func (server *ruleDiffServer) send(requests map[string][]byte, ports map[string]int) map[string]ruleDiffResult {
	server.t.Helper()
	ids := make([]string, 0, len(requests))
	for id := range requests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var lines bytes.Buffer
	for _, id := range ids {
		line, _ := json.Marshal(map[string]any{"id": id, "port": ports[id], "raw": base64.StdEncoding.EncodeToString(requests[id])})
		lines.Write(line)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(server.work, "requests.jsonl"), lines.Bytes(), 0o666); err != nil {
		server.t.Fatal(err)
	}
	if output, err := server.exec("cd /w && resty lua/rule_client.lua requests.jsonl results.jsonl 8"); err != nil {
		server.t.Fatalf("client: %v %s", err, output)
	}
	file, err := os.Open(filepath.Join(server.work, "results.jsonl"))
	if err != nil {
		server.t.Fatal(err)
	}
	defer file.Close()
	results := map[string]ruleDiffResult{}
	scanner := bufio.NewScanner(file)
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
		results[line.ID] = ruleDiffResult{Status: line.Status, Result: line.Result}
	}
	if len(results) != len(requests) {
		server.t.Fatalf("%d results for %d requests", len(results), len(requests))
	}
	return results
}

// errorLog fails on any Lua error or nginx [error]/[crit]/[alert] line.
func (server *ruleDiffServer) checkErrorLog() {
	server.t.Helper()
	content, _ := os.ReadFile(filepath.Join(server.work, "logs/error.log"))
	var bad []string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "[error]") || strings.Contains(line, "[crit]") || strings.Contains(line, "[alert]") ||
			strings.Contains(line, "[emerg]") {
			bad = append(bad, line)
		}
	}
	if len(bad) > 0 {
		server.t.Fatalf("%d error log lines, first: %s", len(bad), bad[0])
	}
}

func TestRulePlanInterpreterDifferential(t *testing.T) {
	image := ruleDiffImage(t)
	seeds := ruleDiffRegressionSeeds
	if raw := os.Getenv("CDNCA_RULE_DIFF_SEEDS"); raw != "" {
		seeds = nil
		for _, field := range strings.Split(raw, ",") {
			seed, err := strconv.ParseUint(strings.TrimSpace(field), 10, 64)
			if err != nil {
				t.Fatalf("seed %q: %v", field, err)
			}
			seeds = append(seeds, seed)
		}
	}
	setsPerSeed := ruleDiffEnvInt("CDNCA_RULE_DIFF_SETS", 120)
	requestsPerSet := ruleDiffEnvInt("CDNCA_RULE_DIFF_REQUESTS", 40)

	goldenPath := filepath.Join("testdata", "ruleplan", "golden.json")
	updateGolden := os.Getenv("CDNCA_RULE_DIFF_UPDATE_GOLDEN") == "1"
	var golden []ruleDiffGolden
	if !updateGolden {
		content, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("golden corpus: %v (CDNCA_RULE_DIFF_UPDATE_GOLDEN=1 writes it)", err)
		}
		if err := json.Unmarshal(content, &golden); err != nil {
			t.Fatal(err)
		}
	}

	type plannedRequest struct {
		set     int
		seed    uint64
		request fuzzRequest
		golden  *ruleDiffResult
	}
	var cases []ruleDiffCase
	var planned []plannedRequest
	for index, item := range golden {
		cases = append(cases, ruleDiffCase{index: index, set: item.Set})
		for requestIndex, request := range item.Requests {
			expected := item.Expected[requestIndex]
			planned = append(planned, plannedRequest{set: index, request: request, golden: &expected})
		}
	}
	if updateGolden {
		g := newFuzzGenerator(9001)
		g.actions = false
		for index := 0; index < 24; index++ {
			set := g.ruleset(index%3 == 2)
			cases = append(cases, ruleDiffCase{index: index, set: set})
			golden = append(golden, ruleDiffGolden{Set: set})
			for request := 0; request < 16; request++ {
				generated := g.request(set)
				golden[index].Requests = append(golden[index].Requests, generated)
				planned = append(planned, plannedRequest{set: index, request: generated})
			}
		}
	}
	goldenSets := len(cases)
	for _, seed := range seeds {
		g := newFuzzGenerator(seed)
		for setIndex := 0; setIndex < setsPerSeed; setIndex++ {
			set := g.ruleset(setIndex%3 == 2)
			index := len(cases)
			cases = append(cases, ruleDiffCase{index: index, set: set})
			for request := 0; request < requestsPerSet; request++ {
				planned = append(planned, plannedRequest{set: index, seed: seed, request: g.request(set)})
			}
		}
	}
	server := startRuleDiffServer(t, image, cases)

	raws, ports := map[string][]byte{}, map[string]int{}
	for index, item := range planned {
		for _, mode := range []string{"compiled", "interp"} {
			id := fmt.Sprintf("%06d-%s", index, mode)
			// Each request (and mode) has its own WAF v2 state (bans, auto
			// block counters): the pair index scopes it.
			raws[id] = item.request.raw(fmt.Sprintf("%s:%d:%d", mode, item.set, index))
			ports[id] = item.request.Port
		}
	}
	started := time.Now()
	results := server.send(raws, ports)
	elapsed := time.Since(started)
	server.checkErrorLog()

	statuses := map[int]int{}
	verdicts := map[string]int{}
	var differences, goldenDrift, ruleHits, iplibCalls, inspectCalls, overflow int
	for index, item := range planned {
		compiled := results[fmt.Sprintf("%06d-compiled", index)]
		interpreted := results[fmt.Sprintf("%06d-interp", index)]
		statuses[compiled.Status]++
		// 503 / 307 challenge, 405 / 403 the challenge verification endpoint.
		if compiled.Status != 200 && compiled.Status != 403 && compiled.Status != 400 && compiled.Status != 503 &&
			compiled.Status != 307 && compiled.Status != 405 {
			t.Errorf("request %d (set %d seed %d): status %d %s", index, item.set, item.seed, compiled.Status, compiled.Result)
		}
		if compiled != interpreted {
			differences++
			if differences <= 10 {
				encodedSet, _ := json.Marshal(cases[item.set].set)
				encodedRequest, _ := json.Marshal(item.request)
				t.Errorf("DIFF request %d set %d seed %d\n compiled %+v\n interp   %+v\n request %s\n set %s",
					index, item.set, item.seed, compiled, interpreted, encodedRequest, encodedSet)
			}
		}
		// The golden corpus predates the attack evidence fields (ge-waf S4):
		// it pins status and the first nine result fields.
		goldenView := func(result ruleDiffResult) ruleDiffResult {
			fields := strings.Split(result.Result, "|")
			if len(fields) > 9 {
				result.Result = strings.Join(fields[:9], "|")
			}
			return result
		}
		if item.golden != nil && goldenView(*item.golden) != goldenView(compiled) {
			goldenDrift++
			if goldenDrift <= 5 {
				t.Errorf("golden drift request %d set %d: recorded %+v, compiled now %+v", index, item.set, *item.golden, compiled)
			}
		}
		if updateGolden && item.set < goldenSets {
			golden[item.set].Expected = append(golden[item.set].Expected, goldenView(compiled))
		}
		fields := strings.Split(compiled.Result, "|")
		if len(fields) == 12 {
			verdict := "allow"
			if compiled.Status == 403 {
				verdict = "block"
			} else if fields[2] == "log" {
				verdict = "log"
			}
			verdicts[verdict]++
			for _, entry := range strings.Split(fields[6], ",") {
				if entry != "" && !strings.HasSuffix(entry, ":default") {
					ruleHits++
					break
				}
			}
			if fields[7] != "0" {
				iplibCalls++
			}
			if fields[8] != "0" {
				inspectCalls++
			}
			if compiled.Status == 403 && fields[6] == "" {
				overflow++
			}
		}
	}
	t.Logf("rule sets %d (golden %d), requests %d x 2 modes in %s; statuses %v; verdicts %v; requests with a rule hit %d, iplib %d, inspect %d, header-overflow 403 %d; differences %d",
		len(cases), goldenSets, len(planned), elapsed.Round(time.Millisecond), statuses, verdicts, ruleHits, iplibCalls, inspectCalls, overflow, differences)
	if differences > 0 {
		t.Fatalf("%d differences between the rendered Lua and the interpreter", differences)
	}
	// The corpus must exercise every outcome, or a zero difference is vacuous.
	if verdicts["block"] == 0 || verdicts["log"] == 0 || verdicts["allow"] == 0 || ruleHits == 0 || iplibCalls == 0 || inspectCalls == 0 {
		t.Fatalf("corpus too weak: verdicts %v rule hits %d iplib %d inspect %d", verdicts, ruleHits, iplibCalls, inspectCalls)
	}
	if updateGolden {
		// One rule set per line: compact, and diffs stay per rule set.
		lines := make([]string, len(golden))
		for index, item := range golden {
			encoded, err := json.Marshal(item)
			if err != nil {
				t.Fatal(err)
			}
			lines[index] = string(encoded)
		}
		if err := os.WriteFile(goldenPath, []byte("[\n"+strings.Join(lines, ",\n")+"\n]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d rule sets)", goldenPath, len(golden))
	}
}

// TestRulePlanInterpreterBenchmark compares the per-request cost of the
// rendered Lua and the interpreter for a 1000-rule plan in real OpenResty.
//
//	CDNCA_RULE_BENCH=1 go -C libs/edgeconfig test -tags integration -run TestRulePlanInterpreterBenchmark -count=1 -v .
func TestRulePlanInterpreterBenchmark(t *testing.T) {
	if os.Getenv("CDNCA_RULE_BENCH") != "1" {
		t.Skip("set CDNCA_RULE_BENCH=1")
	}
	image := ruleDiffImage(t)
	set := benchRuleset()
	_, plan, err := set.compile()
	if err != nil {
		t.Fatal(err)
	}
	rules := 0
	for _, segment := range plan.Segments {
		rules += len(segment.Rules)
	}
	if rules != 1000 {
		t.Fatalf("bench plan has %d rules", rules)
	}
	server := startRuleDiffServer(t, image, []ruleDiffCase{{index: 0, set: set}})
	rounds := ruleDiffEnvInt("CDNCA_RULE_BENCH_ROUNDS", 20)
	command := fmt.Sprintf("curl -sS --max-time 600 -H 'Host: bench.example.com' -H 'X-Real-IP: 192.0.2.10' "+
		"-H 'X-Token: fine' -H 'X-Cdnca-Bench: 0' -H 'X-Cdnca-Rounds: %d' -H 'X-Cdnca-Block: 1000' "+
		"http://127.0.0.1:%d/__bench", rounds, fuzzBasePort)
	output, err := server.exec(command)
	if err != nil {
		t.Fatalf("bench: %v %s", err, output)
	}
	server.checkErrorLog()
	type percentiles struct {
		P50, P90, P99, Mean float64
		N                   int
	}
	var report struct {
		Compiled      percentiles `json:"compiled"`
		Interp        percentiles `json:"interp"`
		Load          percentiles `json:"load"`
		PlanBytes     int         `json:"plan_bytes"`
		ProgramHeapKB float64     `json:"program_heap_kb"`
		Verdict       string      `json:"verdict"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output), &report); err != nil {
		t.Fatalf("bench output %q: %v", output, err)
	}
	if report.Verdict != "allow" {
		t.Fatalf("bench request must match no rule, verdict %q", report.Verdict)
	}
	us := func(ns float64) string { return strconv.FormatFloat(ns/1000, 'f', 1, 64) + "us" }
	t.Logf("1000 rules, %d runs each: rendered p50 %s p90 %s p99 %s mean %s | interp p50 %s p90 %s p99 %s mean %s | ratio p50 %.2f p99 %.2f",
		report.Compiled.N, us(report.Compiled.P50), us(report.Compiled.P90), us(report.Compiled.P99), us(report.Compiled.Mean),
		us(report.Interp.P50), us(report.Interp.P90), us(report.Interp.P99), us(report.Interp.Mean),
		report.Interp.P50/report.Compiled.P50, report.Interp.P99/report.Compiled.P99)
	t.Logf("plan %d bytes, load (decode+compile) p50 %s p99 %s, program heap %.0f KiB",
		report.PlanBytes, us(report.Load.P50), us(report.Load.P99), report.ProgramHeapKB)
}
