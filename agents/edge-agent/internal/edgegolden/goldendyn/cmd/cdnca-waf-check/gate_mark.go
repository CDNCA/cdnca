package main

// Gate mode on rule intelligence mark packs (system/scanner-signatures,
// system/autodefense-intel: waf_v2 rules that only log, ADR 0011 §6.1): G3
// replays the corpus on the base and candidate versions of each pack.
// The packs never decide a request,
// so the outcome is whether the pack marks it: b marked, p not, e no answer
// (x for a public dataset sample). The report has mode "mark" and one tier
// per candidate pack; a pack without a base version marks nothing on the
// base side. evalreport.Decide then holds the hit rate on attacks and on
// normal requests as it holds a CRS tier's block and false positive rates.
//
// The rules run in the node's interpreter (cdnca_rule_interp, the mount plan
// rulepack.MountRulePlan builds as the agent does) in a real OpenResty. The
// client attributes the packs match on come from the request's Client
// (evalreport.Client): JA4 replaces $cdnca_ja4 for the request, country and
// ASN answer the IP library conditions (a stand-in cdnca_iplib, the check
// image has no data set).

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/evalreport"
	"github.com/cdnca/cdnca/libs/rulepack"
)

const markPort = 18412

// markHarness serves X-Cdnca-Plan: <name> with plans/<name>.json (absent:
// nothing marks) and answers X-Cdnca-Mark: <verdict>.
const markHarness = `local interp = require("cdnca_rule_interp")
local _M = {}
local programs = {}
local root = ngx.config.prefix()

local function program(name)
    local cached = programs[name]
    if cached ~= nil then return cached end
    local file = io.open(root .. "plans/" .. name .. ".json", "rb")
    if not file then
        programs[name] = false
        return false
    end
    local raw = file:read("*a")
    file:close()
    cached = assert(interp.compile_json(raw))
    programs[name] = cached
    return cached
end

function _M.content()
    local name = ngx.var.http_x_cdnca_plan or ""
    if not name:match("^[%w_-]+$") then return ngx.exit(400) end
    -- the body first (the only yield), then the client's TLS fingerprint for
    -- this request: ngx.var is a plain table under its metatable, a raw field
    -- shadows the native variable until the next request sets it again
    ngx.req.read_body()
    rawset(ngx.var, "cdnca_ja4", ngx.var.http_x_cdnca_ja4 or "")
    local compiled = program(name)
    local verdict = "allow"
    if compiled then verdict = interp.evaluate(compiled, nil) or "allow" end
    rawset(ngx.var, "cdnca_ja4", nil)
    ngx.header["X-Cdnca-Mark"] = verdict
    ngx.say("ok")
end

return _M
`

// markIPLib answers IP library condition specs (edgeconfig
// IPIntelConditionSpec) from X-Cdnca-Country / X-Cdnca-ASN.
const markIPLib = `local _M = {}

function _M.match(spec)
    local field, negate, list = spec:match("^(%l+)(!?)=([%w,]+)$")
    local have
    if field == "country" then have = ngx.var.http_x_cdnca_country elseif field == "asn" then have = ngx.var.http_x_cdnca_asn end
    local hit = false
    if have and have ~= "" then
        for value in list:gmatch("[^,]+") do
            if value == have then hit = true end
        end
    end
    if negate == "!" then return not hit end
    return hit
end

return _M
`

// loadMarkPacks reads a directory of mark packs by pack ID; any other pack
// is an error (the caller then takes the directory as CRS profile packs).
func loadMarkPacks(dir string) (map[string]*rulepack.CompiledPack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	packs := map[string]*rulepack.CompiledPack{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		compiled, err := rulepack.Compile(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if !rulepack.IsIntelMarkPack(compiled.Pack.PackID) {
			return nil, fmt.Errorf("%s: %s is no mark pack", entry.Name(), compiled.Pack.PackID)
		}
		if _, dup := packs[compiled.Pack.PackID]; dup {
			return nil, fmt.Errorf("%s: two versions of %s", dir, compiled.Pack.PackID)
		}
		packs[compiled.Pack.PackID] = compiled
	}
	return packs, nil
}

// markPlan is the mount plan of one pack as the agent writes it.
func markPlan(pack *rulepack.CompiledPack) ([]byte, error) {
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: pack, Priority: rulepack.DefaultPriority}}, rulepack.Target{})
	if resolution.Security == nil {
		return nil, fmt.Errorf("%s: mount conflicts %v", pack.Pack.PackID, resolution.Conflicts)
	}
	plan, err := rulepack.MountRulePlan(resolution.Rules, func(string) string { return pack.SHA256 }, false)
	if err != nil {
		return nil, err
	}
	return edgeconfig.EncodeRulePlan(plan)
}

// markGateRun is gateRun for mark packs: both versions run on one harness
// (plans base-<i> and candidate-<i>).
func markGateRun(candidates map[string]*rulepack.CompiledPack, corpus []evalreport.Request, crsVersion, digest string,
	std *evalreport.StdSource) {
	bases, err := loadMarkPacks(*gateBase)
	if err != nil {
		check("gate mark base packs", false, "%v", err)
		return
	}
	ids := make([]string, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for id := range bases {
		if candidates[id] == nil {
			check("gate mark base packs", false, "base %s has no candidate", id)
			return
		}
	}
	root := filepath.Join(*state, "mark")
	_ = os.RemoveAll(root)
	for _, dir := range []string{"lua", "plans", "logs", "body"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o777); err != nil {
			check("gate mark", false, "%v", err)
			return
		}
	}
	for name, content := range map[string]string{"mark_harness.lua": markHarness, "cdnca_iplib.lua": markIPLib} {
		if err := os.WriteFile(filepath.Join(root, "lua", name), []byte(content), 0o644); err != nil {
			check("gate mark", false, "%v", err)
			return
		}
	}
	reports := map[string]*evalreport.Report{}
	for _, label := range []string{"base", "candidate"} {
		reports[label] = &evalreport.Report{Schema: evalreport.Schema, CRSVersion: crsVersion, Corpus: digest, Std: std,
			Mode: evalreport.ModeMark}
	}
	for index, id := range ids {
		for label, pack := range map[string]*rulepack.CompiledPack{"base": bases[id], "candidate": candidates[id]} {
			tier := evalreport.Tier{PackID: id, Name: id}
			if pack != nil {
				tier.Name, tier.Version, tier.SHA256 = pack.Pack.Name, pack.Pack.Version, pack.SHA256
				plan, err := markPlan(pack)
				if err != nil {
					check("gate mark plan", false, "%v", err)
					return
				}
				if err := os.WriteFile(filepath.Join(root, "plans", fmt.Sprintf("%s-%d.json", label, index)), plan, 0o644); err != nil {
					check("gate mark plan", false, "%v", err)
					return
				}
			}
			reports[label].Tiers = append(reports[label].Tiers, tier)
		}
	}
	conf := fmt.Sprintf(`worker_processes %d;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 1024; }
http {
  access_log off;
  lua_package_path "$prefix/lua/?.lua;%s/security/?.lua;;";
  client_body_temp_path %s/body;
  client_body_buffer_size 128k;
  client_max_body_size 64m;
  large_client_header_buffers 8 64k;
  lua_shared_dict cdnca_waf_state 4m;
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
    location / { content_by_lua_block { require("mark_harness").content() } }
  }
}
`, max(*workers, 1), *luaRoot, root, markPort)
	if err := os.WriteFile(filepath.Join(root, "nginx.conf"), []byte(conf), 0o644); err != nil {
		check("gate mark", false, "%v", err)
		return
	}
	if output, err := runOpenResty(root); err != nil {
		check("gate mark start", false, "%v %s", err, output)
		return
	}
	defer func() { _, _ = runOpenResty(root, "-s", "stop") }()
	if err := waitPort(markPort); err != nil {
		check("gate mark start", false, "%v", err)
		return
	}
	if !markReplay(reports, len(ids), corpus, std) {
		return
	}
	if lines := perfErrors(root); len(lines) > 0 {
		for _, line := range lines {
			check("gate mark error log", false, "%s", line)
		}
		return
	}
	for _, label := range []string{"base", "candidate"} {
		report := reports[label]
		if err := writeGateReport(*gateReport+"."+label+".json", *report); err != nil {
			check("gate report", false, "%v", err)
			return
		}
		for index, tier := range report.Tiers {
			counts := map[byte]int{}
			for _, result := range report.Results {
				key := result.Outcome[index]
				if !result.Attack {
					key -= 32 // upper case: benign
				}
				counts[key]++
			}
			keys := make([]string, 0, len(counts))
			for key, n := range counts {
				keys = append(keys, fmt.Sprintf("%c=%d", key, n))
			}
			sort.Strings(keys)
			fmt.Printf("GATE mode=mark version=%s pack=%s@%s %s\n", label, tier.PackID, tier.Version, strings.Join(keys, " "))
		}
	}
	check("gate reports", true, "%s.{base,candidate}.json mode=mark corpus=%s requests=%d", *gateReport, digest, len(corpus))
}

type markJob struct {
	position int
	result   evalreport.Result
	send     func(plan string) byte
}

// markReplay fills both reports' results: every request on every plan.
func markReplay(reports map[string]*evalreport.Report, tiers int, corpus []evalreport.Request, std *evalreport.StdSource) bool {
	total := len(corpus)
	if std != nil {
		for _, file := range std.Files {
			total += file.Requests
		}
	}
	for _, report := range reports {
		report.Results = make([]evalreport.Result, total)
	}
	jobs := make(chan markJob, max(*gateWorkers, 1)*4)
	var wait sync.WaitGroup
	for range max(*gateWorkers, 1) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for job := range jobs {
				for label, report := range reports {
					outcome := make([]byte, tiers)
					for index := range tiers {
						outcome[index] = job.send(fmt.Sprintf("%s-%d", label, index))
					}
					result := job.result
					result.Outcome = string(outcome)
					report.Results[job.position] = result
				}
			}
		}()
	}
	for position, request := range corpus {
		jobs <- markJob{position: position, result: evalreport.Result{ID: request.ID, Attack: request.Attack, Category: request.Category},
			send: func(plan string) byte { return markOutcome(plan, request) }}
	}
	position, scanErr := len(corpus), error(nil)
	if std != nil {
		for _, file := range std.Files {
			if scanErr = gateStdScan(file.Name, std.Mode, func(request stdRequest) {
				if position < total {
					data, headers := stdWire(request)
					jobs <- markJob{position: position, result: evalreport.Result{ID: evalreport.StdPrefix + file.Name + ":" + request.ID,
						Attack: request.Attack, Category: file.Name + ":" + request.Category},
						send: func(plan string) byte {
							switch marked, ok := markSend(plan, request.Method, request.URI, headers, data, nil); {
							case !ok:
								return evalreport.Excluded
							case marked:
								return evalreport.Blocked
							}
							return evalreport.Passed
						}}
				}
				position++
			}); scanErr != nil {
				break
			}
		}
	}
	close(jobs)
	wait.Wait()
	if scanErr != nil || position != total {
		check("gate mark std", false, "datasets changed during the run: %d of %d requests (%v)", position, total, scanErr)
		return false
	}
	return true
}

// markOutcome sends every variant of a corpus request: b if the plan marks
// any, else e if any got no answer, else p.
func markOutcome(plan string, request evalreport.Request) byte {
	outcome := byte(evalreport.Passed)
	for _, variant := range variants(evalRequest{ID: request.ID, Method: request.Method, URI: request.URI,
		Headers: request.Headers, Data: request.Data, Value: request.Value, Attack: request.Attack}) {
		marked, ok := markSend(plan, variant.Method, variant.URI, variant.Headers, variant.Data, request.Client)
		switch {
		case marked:
			return evalreport.Blocked
		case !ok:
			outcome = evalreport.Failed
		}
	}
	return outcome
}

// markSend sends one request to the harness; ok false: no answer or not 200.
func markSend(plan, method, uri string, headers map[string]string, body string, client *evalreport.Client) (marked, ok bool) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", markPort), 5*time.Second)
	if err != nil {
		return false, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\nHost: mark.waf.test\r\nX-Cdnca-Plan: %s\r\n", method, uri, plan)
	if client != nil {
		for name, value := range map[string]string{"X-Cdnca-JA4": client.JA4, "X-Cdnca-Country": client.Country, "X-Cdnca-ASN": client.ASN} {
			if value != "" {
				fmt.Fprintf(&request, "%s: %s\r\n", name, value)
			}
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		if !strings.EqualFold(name, "Host") && !strings.HasPrefix(strings.ToLower(name), "x-cdnca-") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&request, "%s: %s\r\n", name, headers[name])
	}
	if body != "" || method == "POST" || method == "PUT" || method == "PATCH" {
		fmt.Fprintf(&request, "Content-Length: %d\r\n", len(body))
	}
	request.WriteString("Connection: close\r\n\r\n")
	request.WriteString(body)
	if _, err := conn.Write([]byte(request.String())); err != nil {
		return false, false
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	fields := strings.Fields(line)
	if err != nil || len(fields) < 2 {
		return false, false
	}
	code, _ := strconv.Atoi(fields[1])
	for {
		header, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(header) == "" {
			break
		}
		if name, value, found := strings.Cut(strings.TrimSpace(header), ":"); found && strings.EqualFold(name, "X-Cdnca-Mark") {
			marked = strings.TrimSpace(value) == "log"
		}
	}
	return marked, code == 200
}
