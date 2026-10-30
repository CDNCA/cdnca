package main

// -only perf: ADR 0011 §6.5 rule matching cost on the real node runtime.
// Per size (-perf-sizes, default 1000; 10k / 50k on the evaluation worker)
// libs/rulepack/rulegen generates a plan (literal 60 %, regex 25 %, IP /
// discrete 15 %, 30 % multi-condition), compiles its match index with the
// publish budget (rulepack.AttachMatchIndex) and replays -perf-requests
// attack + as many normal requests (no body / large JSON body / long query)
// through the interpreter (cdnca_rule_interp, the D6 path) in one worker.
// Each request is timed around evaluate() after its values are extracted
// ("warm": matching only); a sample also runs the linear path, whose
// decisions must equal the indexed ones. Over the §6.5 target (p50 / p99 /
// worker RSS) is a failure; the JSON report goes to stdout (PERF ...).

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/libs/rulepack/rulegen"
)

var (
	perfSizes    = flag.String("perf-sizes", "1000", "-only perf: comma separated rule counts")
	perfRequests = flag.Int("perf-requests", 10000, "-only perf: attack requests (and as many normal ones) per size")
	perfLinear   = flag.Int("perf-linear", 200, "-only perf: requests also run on the linear path (decisions compared)")
)

const perfPort = 18411

// perfTarget is the ADR 0011 §6.5 table (us, us, MiB).
type perfTarget struct{ P50, P99, RSSMiB float64 }

var perfTargets = map[int]perfTarget{1000: {10, 40, 8}, 10000: {20, 80, 32}, 50000: {40, 150, 96}}

type perfTiming struct {
	P50 float64 `json:"p50"`
	P99 float64 `json:"p99"`
	N   int     `json:"n"`
}

type perfRow struct {
	Rules int                   `json:"rules"`
	Cost  rulepack.MatchCost    `json:"cost"`
	Warm  map[string]perfTiming `json:"warm_us"`
	// ProgramRSSMiB: worker RSS growth from loading the indexed program
	// (the program and its automata); WorkerRSSMiB at the end.
	ProgramRSSMiB float64 `json:"program_rss_mib"`
	WorkerRSSMiB  float64 `json:"worker_rss_mib"`
	Differences   int     `json:"differences"`
}

func perfRun() {
	var rows []perfRow
	for _, field := range strings.Split(*perfSizes, ",") {
		size, err := strconv.Atoi(field)
		if err != nil || size <= 0 {
			check("perf", false, "size %q", field)
			continue
		}
		row, err := perfSize(size)
		if err != nil {
			check("perf", false, "%d rules: %v", size, err)
			continue
		}
		rows = append(rows, row)
		target, known := perfTargets[size]
		warm := row.Warm["all"]
		if warm.N != 2**perfRequests {
			check(fmt.Sprintf("perf-%d", size), false, "%d timed samples, want %d", warm.N, 2**perfRequests)
			continue
		}
		check(fmt.Sprintf("perf-%d", size), row.Differences == 0, "linear and indexed decisions: %d differences", row.Differences)
		if known {
			check(fmt.Sprintf("perf-%d", size), warm.P50 <= target.P50 && warm.P99 <= target.P99 && row.ProgramRSSMiB <= target.RSSMiB,
				"p50 %.1fus (<= %.0f) p99 %.1fus (<= %.0f) program RSS %.1f MiB (<= %.0f), worker RSS %.1f MiB, cost %+v",
				warm.P50, target.P50, warm.P99, target.P99, row.ProgramRSSMiB, target.RSSMiB, row.WorkerRSSMiB, row.Cost)
		}
	}
	encoded, _ := json.Marshal(rows)
	fmt.Printf("PERF %s\n", encoded)
}

func perfSize(size int) (perfRow, error) {
	g := rulegen.New(uint64(size))
	plan, err := g.Plan(size)
	if err != nil {
		return perfRow{}, err
	}
	if err := rulepack.AttachMatchIndex(&plan); err != nil {
		return perfRow{}, err
	}
	var index rulepack.MatchIndex
	if err := json.Unmarshal(plan.Index, &index); err != nil {
		return perfRow{}, err
	}
	root := filepath.Join(*state, "perf")
	_ = os.RemoveAll(root)
	for _, dir := range []string{"lua", "plans", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o777); err != nil {
			return perfRow{}, err
		}
	}
	for _, name := range []string{"index_harness.lua", "cdnca_iplib.lua"} {
		content, err := fs.ReadFile(rulegen.Lua, "lua/"+name)
		if err != nil {
			return perfRow{}, err
		}
		if err := os.WriteFile(filepath.Join(root, "lua", name), content, 0o644); err != nil {
			return perfRow{}, err
		}
	}
	encoded, err := edgeconfig.EncodeRulePlan(plan)
	if err != nil {
		return perfRow{}, err
	}
	if err := os.WriteFile(filepath.Join(root, "plans", "0.json"), encoded, 0o644); err != nil {
		return perfRow{}, err
	}
	// The node's interpreter and inspect engine; the IP library is the
	// harness stand-in (no data set in the check image). $cdnca_ja4 is the
	// runtime's own (native patch 21): plain HTTP has none, so JA4 rules
	// never match here.

	conf := fmt.Sprintf(`worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 1024; }
http {
  access_log off;
  lua_package_path "$prefix/lua/?.lua;%s/security/?.lua;;";
  client_body_temp_path %s/body;
  client_body_buffer_size 128k;
  client_max_body_size 1m;
  large_client_header_buffers 8 16k;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  lua_shared_dict cdnca_waf_state 4m;
  init_by_lua_block { require("index_harness").preload(1) }
  server {
    listen 127.0.0.1:%d;
    server_name _;
    set $cdnca_security_emit 0;
    set $cdnca_security_type "";
    set $cdnca_security_action "";
    set $cdnca_security_severity "";
    set $cdnca_security_rule_id "";
    set $cdnca_block_page 0;
    set $cdnca_security_policy_id "";
    set $cdnca_security_detector "";
    set $cdnca_security_matched "";
    set $cdnca_security_body "";
    location = /__stats { content_by_lua_block { require("index_harness").stats() } }
    location / { content_by_lua_block { require("index_harness").content() } }
  }
}
`, *luaRoot, root, perfPort)
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte(conf), 0o644); err != nil {
		return perfRow{}, err
	}
	run := func(args ...string) error {
		output, err := runOpenResty(root, args...)
		if err != nil {
			return fmt.Errorf("openresty %v: %v %s", args, err, output)
		}
		return nil
	}
	if err := run(); err != nil {
		return perfRow{}, err
	}
	defer func() { _ = run("-s", "stop") }()
	if err := waitPort(perfPort); err != nil {
		return perfRow{}, err
	}
	// Timed requests, then the linear / indexed decision comparison.
	var timed [][]byte
	var compared [][2][]byte
	for number := 0; number < 2**perfRequests; number++ {
		request := g.Request(number%2 == 0)
		// Once for the whole distribution, once under its request class.
		timed = append(timed, request.Raw("index:0\r\nX-Cdnca-Time: warm"),
			request.Raw("index:0\r\nX-Cdnca-Time: warm\r\nX-Cdnca-Class: "+request.Class()))
		if number < *perfLinear {
			compared = append(compared, [2][]byte{request.Raw("linear:0"), request.Raw("index:0")})
		}
	}
	perfSend(timed)
	row := perfRow{Rules: size, Cost: index.Cost}
	for _, pair := range compared {
		results := perfSend(pair[:])
		if results[0] != results[1] {
			row.Differences++
			if row.Differences <= 5 {
				fmt.Printf("DIFF %d rules: linear %q index %q\n", size, results[0], results[1])
			}
		}
	}
	body, err := perfGet("/__stats")
	if err != nil {
		return perfRow{}, err
	}
	var stats struct {
		RSSKB      float64               `json:"rss_kb"`
		RSSSplitKB map[string]float64    `json:"rss_split_kb"`
		Timing     map[string]perfTiming `json:"timing"`
	}
	if err := json.Unmarshal(body, &stats); err != nil {
		return perfRow{}, fmt.Errorf("stats %q: %v", body, err)
	}
	row.Warm = map[string]perfTiming{}
	for key, value := range stats.Timing {
		name := strings.TrimPrefix(strings.TrimPrefix(key, "index:warm"), ":")
		if name == "" {
			name = "all"
		}
		row.Warm[name] = perfTiming{P50: value.P50 / 1000, P99: value.P99 / 1000, N: value.N}
	}
	row.ProgramRSSMiB = (stats.RSSSplitKB["index"] - stats.RSSSplitKB["base"]) / 1024
	row.WorkerRSSMiB = stats.RSSKB / 1024
	if lines := perfErrors(root); len(lines) > 0 {
		return row, fmt.Errorf("error log: %s", lines[0])
	}
	return row, nil
}

// perfSend sends raw requests over 8 connections at a time; returns the
// X-Cdnca-Result header (or the status line) of each.
func perfSend(raws [][]byte) []string {
	results := make([]string, len(raws))
	var wait sync.WaitGroup
	next := make(chan int)
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range next {
				results[index] = perfOne(raws[index])
			}
		}()
	}
	for index := range raws {
		next <- index
	}
	close(next)
	wait.Wait()
	return results
}

// perfRaw sends one raw request (Connection: close) and returns the
// whole response.
func perfRaw(raw []byte) (string, error) {
	connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", perfPort), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := connection.Write(raw); err != nil {
		return "", err
	}
	response, err := io.ReadAll(connection)
	return string(response), err
}

func perfOne(raw []byte) string {
	response, err := perfRaw(raw)
	if err != nil {
		return "error: " + err.Error()
	}
	head, _, _ := strings.Cut(response, "\r\n\r\n")
	status, rest, _ := strings.Cut(head, "\r\n")
	for _, line := range strings.Split(rest, "\r\n") {
		if name, value, ok := strings.Cut(line, ": "); ok && strings.EqualFold(name, "X-Cdnca-Result") {
			return status + " " + value
		}
	}
	return status
}

func perfGet(path string) ([]byte, error) {
	// HTTP/1.0: the body comes unchunked.
	response, err := perfRaw([]byte("GET " + path + " HTTP/1.0\r\nHost: perf\r\n\r\n"))
	if err != nil {
		return nil, err
	}
	head, body, _ := strings.Cut(response, "\r\n\r\n")
	if !strings.HasPrefix(head, "HTTP/1.1 200 ") && !strings.HasPrefix(head, "HTTP/1.0 200 ") {
		return nil, fmt.Errorf("GET %s: %s", path, head)
	}
	return []byte(strings.TrimSpace(body)), nil
}

func runOpenResty(prefix string, args ...string) ([]byte, error) {
	return exec.Command("openresty", append([]string{"-p", prefix + "/", "-c", "nginx.conf"}, args...)...).CombinedOutput()
}

func perfErrors(root string) []string {
	content, _ := os.ReadFile(filepath.Join(root, "logs/error.log"))
	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		for _, level := range []string{"[error]", "[crit]", "[alert]", "[emerg]"} {
			if strings.Contains(line, level) {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

func waitPort(port int) error {
	for attempt := 0; attempt < 100; attempt++ {
		if connection, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			_ = connection.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %d not listening", port)
}
