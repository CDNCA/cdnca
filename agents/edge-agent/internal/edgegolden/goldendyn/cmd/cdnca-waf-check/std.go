package main

// -only eval -corpus-set std: the four WAF tiers on the public datasets,
// corpora made by
// scripts/security/datasets/convert.py (one JSON request per line, gzip):
//   wafcomp-mal / wafcomp-legit  openappsec/waf-comparison-project, replayed
//                                as its python client sends them
//   gotestwaf                    wallarm/gotestwaf payload x encoder x placeholder
//   leipzig                      go-ftw quantitative Leipzig sentences (query, form)
// Blocked is 403 for every dataset (both projects' default). Counting follows
// each project: waf-comparison leaves status 0 out; GoTestWAF counts only 403
// (blocked) and 200/404 (passed), the rest is unresolved and left out.
// Output: STD lines per dataset x tier with Wilson 95% intervals, STDHIT for
// each request some tier blocked (attack misses are the complement), STDBA
// the waf-comparison balanced accuracy.

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

var (
	corpusSet  = flag.String("corpus-set", "", "std: the public datasets in -std-dir instead of the built-in corpus")
	stdDir     = flag.String("std-dir", "/std", "directory of the convert.py corpora (<dataset>.jsonl.gz)")
	stdSets    = flag.String("std-sets", "wafcomp-mal,wafcomp-legit,gotestwaf,leipzig", "datasets to run")
	stdShard   = flag.String("std-shard", "0/1", "i/n: only every n-th request starting at i (batches under 10 minutes)")
	stdFast    = flag.Bool("std-fast", false, "waf-comparison: only its --fast subset (seed 42, 15%)")
	stdWorkers = flag.Int("std-workers", 32, "concurrent requests")
	// waf-cookie-fp: which CRS rules on which variables a tier's verdict
	// came from (one request at a time, so the audit log tail is its own)
	stdRules = flag.Bool("std-rules", false, "one request at a time; STDRULE lines: the tier's audited rule IDs and matched variables")
	// waf-gap6 S1 (learned weights): the PL4 rule hit vector of each request
	// on the log-only probe site, with the detector verdicts the context
	// carries, for the offline weight training (scripts/security/datasets/learn_weights.py)
	stdProbe = flag.Bool("std-probe", false, "with -std-rules: send each request to the paranoia 4 log-only probe site only; STDVEC lines")
)

// stdMatch is one audited CRS message: rule ID and the variable it matched.
type stdMatch struct {
	Rule     string `json:"rule"`
	Variable string `json:"var"`
}

// auditMatches reads the CRS messages of the audit records after offset.
func auditMatches(offset int64) ([]stdMatch, int64) {
	path := filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log")
	size := fileSize(path)
	var matches []stdMatch
	if offset >= size {
		return nil, size
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, size
	}
	defer file.Close()
	tail := make([]byte, size-offset)
	if _, err := file.ReadAt(tail, offset); err != nil {
		return nil, size
	}
	for _, record := range strings.Split(string(tail), "\n") {
		if !strings.HasPrefix(record, "{") {
			continue
		}
		var value struct {
			Transaction struct {
				Messages []struct {
					Details struct {
						RuleID string `json:"ruleId"`
						Data   string `json:"data"`
					} `json:"details"`
				} `json:"messages"`
			} `json:"transaction"`
		}
		if json.Unmarshal([]byte(record), &value) != nil {
			continue
		}
		for _, message := range value.Transaction.Messages {
			if !strings.HasPrefix(message.Details.RuleID, "9") {
				continue
			}
			variable := ""
			if match := auditDataVariable.FindStringSubmatch(message.Details.Data); match != nil {
				variable = match[1]
			}
			matches = append(matches, stdMatch{Rule: message.Details.RuleID, Variable: variable})
		}
	}
	return matches, size
}

type stdRequest struct {
	Dataset  string            `json:"dataset"`
	Category string            `json:"category"`
	ID       string            `json:"id"`
	Method   string            `json:"method"`
	URI      string            `json:"uri"`
	Headers  map[string]string `json:"headers"`
	Data     string            `json:"data"`
	Latin1   bool              `json:"latin1"`
	Attack   bool              `json:"attack"`
	Fast     bool              `json:"fast"`
}

// latin1 is the bytes python's http.client sends for a str (ISO-8859-1).
func latin1(value string) string {
	out := make([]byte, 0, len(value))
	for _, r := range value {
		out = append(out, byte(r))
	}
	return string(out)
}

// stdWire is the body and headers as the dataset's client sends them.
func stdWire(request stdRequest) (string, map[string]string) {
	if !request.Latin1 {
		return request.Data, request.Headers
	}
	headers := make(map[string]string, len(request.Headers))
	for name, value := range request.Headers {
		headers[name] = latin1(value)
	}
	return latin1(request.Data), headers
}

// wilson is the 95% Wilson score interval of k of n.
func wilson(k, n int) (float64, float64) {
	if n == 0 {
		return 0, 0
	}
	const z = 1.959964
	p, nn := float64(k)/float64(n), float64(n)
	center := (p + z*z/(2*nn)) / (1 + z*z/nn)
	half := z * math.Sqrt(p*(1-p)/nn+z*z/(4*nn*nn)) / (1 + z*z/nn)
	return math.Max(0, center-half), math.Min(1, center+half)
}

type stdTally struct {
	counted, blocked, excluded int
	codes                      map[int]int // status of the excluded
}

// stdKey: each dataset is tallied separately for its attacks and its benign requests.
func stdKey(dataset string, attack bool) string {
	if attack {
		return dataset + "/attack"
	}
	return dataset + "/benign"
}

func stdCounted(dataset string, code int) (counted, blocked bool) {
	if dataset == "gotestwaf" {
		return code == 403 || code == 200 || code == 404, code == 403
	}
	return code != 0, code == 403
}

func stdRun(names []string) {
	var shard, shards int
	if _, err := fmt.Sscanf(*stdShard, "%d/%d", &shard, &shards); err != nil || shards < 1 || shard < 0 || shard >= shards {
		check("std shard", false, "bad -std-shard %q", *stdShard)
		return
	}
	tallies := map[string][]stdTally{}
	var keys []string
	var mu sync.Mutex
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for _, dataset := range strings.Split(*stdSets, ",") {
		file, err := os.Open(filepath.Join(*stdDir, dataset+".jsonl.gz"))
		if err != nil {
			check("std corpus", false, "%v", err)
			continue
		}
		reader, err := gzip.NewReader(file)
		if err != nil {
			check("std corpus", false, "%s: %v", dataset, err)
			file.Close()
			continue
		}
		started, sent := time.Now(), 0
		workers := *stdWorkers
		if *stdRules {
			workers = 1
		}
		jobs := make(chan stdRequest, workers*4)
		var wait sync.WaitGroup
		for range workers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				for request := range jobs {
					uri := request.URI
					data, headers := stdWire(request)
					codes := make([]int, len(names))
					var ruled [][]stdMatch
					for index := range names {
						var offset int64
						if *stdRules {
							offset = fileSize(filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log"))
						}
						codes[index] = rawStatus(fmt.Sprintf("eval%d.waf.test", index), request.Method, uri, headers, data)
						if *stdRules {
							// the audit record is written in the log phase, after the answer
							matches, _ := auditMatches(offset)
							for wait := 0; len(matches) == 0 && codes[index] != 200 && wait < 25; wait++ {
								time.Sleep(20 * time.Millisecond)
								matches, _ = auditMatches(offset)
							}
							ruled = append(ruled, matches)
						}
					}
					mu.Lock()
					if *stdRules {
						encoded, _ := json.Marshal(map[string]any{"id": request.ID, "codes": codes, "matches": ruled})
						fmt.Fprintf(out, "STDRULE %s\n", encoded)
					}
					hits := ""
					key := stdKey(dataset, request.Attack)
					if tallies[key] == nil {
						tallies[key] = make([]stdTally, len(names))
						keys = append(keys, key)
					}
					for index, code := range codes {
						counted, blocked := stdCounted(dataset, code)
						t := &tallies[key][index]
						if !counted {
							t.excluded++
							if t.codes == nil {
								t.codes = map[int]int{}
							}
							t.codes[code]++
							fmt.Fprintf(out, "STDEXC %s %s tier=%d code=%d\n", dataset, request.ID, index, code)
							continue
						}
						t.counted++
						if blocked {
							t.blocked++
							hits += strconv.Itoa(index)
						}
					}
					if hits != "" {
						fmt.Fprintf(out, "STDHIT %s %s tiers=%s attack=%t category=%s\n", dataset, request.ID, hits, request.Attack, request.Category)
					}
					mu.Unlock()
				}
			}()
		}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 1<<20), 64<<20)
		line := 0
		for scanner.Scan() {
			line++
			if (line-1)%shards != shard {
				continue
			}
			var request stdRequest
			if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
				check("std corpus", false, "%s line %d: %v", dataset, line, err)
				continue
			}
			if *stdFast && strings.HasPrefix(dataset, "wafcomp") && !request.Fast {
				continue
			}
			sent++
			jobs <- request
		}
		close(jobs)
		wait.Wait()
		fmt.Fprintf(out, "STDTIME dataset=%s requests=%d seconds=%.1f\n", dataset, sent, time.Since(started).Seconds())
		if err := scanner.Err(); err != nil {
			check("std corpus", false, "%s: %v", dataset, err)
		}
		reader.Close()
		file.Close()
	}
	sort.Strings(keys)
	for _, key := range keys {
		for index, t := range tallies[key] {
			low, high := wilson(t.blocked, t.counted)
			fmt.Fprintf(out, "STD dataset=%s tier=%s shard=%s counted=%d blocked=%d rate=%.4f ci95=%.4f-%.4f excluded=%d codes=%v\n", key,
				names[index], *stdShard, t.counted, t.blocked, float64(t.blocked)/float64(max(t.counted, 1)), low, high, t.excluded, t.codes)
		}
	}
	if attacks, benign := tallies["wafcomp-mal/attack"], tallies["wafcomp-legit/benign"]; attacks != nil && benign != nil {
		for index := range names {
			tpr := float64(attacks[index].blocked) / float64(max(attacks[index].counted, 1))
			tnr := 1 - float64(benign[index].blocked)/float64(max(benign[index].counted, 1))
			fmt.Fprintf(out, "STDBA tier=%s tpr=%.4f tnr=%.4f balanced=%.4f\n", names[index], tpr, tnr, (tpr+tnr)/2)
		}
	}
}

// auditVector reads the audit records after offset up to the sentinel's
// (its URI carries marker): the CRS rule IDs and the detector signal rules
// (30080+position, DynamicWAFDetectors order) of the records before it, and
// the offset after the sentinel's record (found false: not written yet).
func auditVector(offset int64, marker string) ([]int, []string, int64, bool) {
	path := filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log")
	size := fileSize(path)
	if offset >= size {
		return nil, nil, offset, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, offset, false
	}
	defer file.Close()
	tail := make([]byte, size-offset)
	if _, err := file.ReadAt(tail, offset); err != nil {
		return nil, nil, offset, false
	}
	at := strings.Index(string(tail), marker)
	if at < 0 {
		return nil, nil, offset, false
	}
	end := strings.IndexByte(string(tail[at:]), '\n')
	if end < 0 {
		return nil, nil, offset, false
	}
	before := string(tail[:at])
	if record := strings.LastIndexByte(before, '\n'); record >= 0 {
		before = before[:record]
	} else {
		before = ""
	}
	rules, detectors := map[int]bool{}, map[string]bool{}
	for _, match := range auditVectorID.FindAllStringSubmatch(before, -1) {
		id, _ := strconv.Atoi(match[1])
		if position := id - 30080; position >= 0 && position < len(edgeconfig.DynamicWAFDetectors) {
			detectors[edgeconfig.DynamicWAFDetectors[position].Name] = true
		} else if id >= 900000 {
			rules[id] = true
		}
	}
	ids := make([]int, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	names := make([]string, 0, len(detectors))
	for name := range detectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return ids, names, offset + int64(at+end+1), true
}

var auditVectorID = regexp.MustCompile(`"ruleId":"(9[0-9]{5}|300[89][0-9])"`)

// stdProbeRun sends every request of the datasets once, to the probe site
// only, one at a time (run with -workers 1): STDVEC {d, id, a, c, r, x} (dataset, request, attack,
// status, PL4 rule hits, detector verdicts).
func stdProbeRun() {
	var shard, shards int
	if _, err := fmt.Sscanf(*stdShard, "%d/%d", &shard, &shards); err != nil || shards < 1 || shard < 0 || shard >= shards {
		check("std shard", false, "bad -std-shard %q", *stdShard)
		return
	}
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	offset := fileSize(filepath.Join(*state, goldendyn.SharedDirectory, "modsecurity-audit.log"))
	for _, dataset := range strings.Split(*stdSets, ",") {
		file, err := os.Open(filepath.Join(*stdDir, dataset+".jsonl.gz"))
		if err != nil {
			check("std corpus", false, "%v", err)
			continue
		}
		reader, err := gzip.NewReader(file)
		if err != nil {
			check("std corpus", false, "%s: %v", dataset, err)
			file.Close()
			continue
		}
		started, sent := time.Now(), 0
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 1<<20), 64<<20)
		line := 0
		for scanner.Scan() {
			line++
			if (line-1)%shards != shard {
				continue
			}
			var request stdRequest
			if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
				check("std corpus", false, "%s line %d: %v", dataset, line, err)
				continue
			}
			if *stdFast && strings.HasPrefix(dataset, "wafcomp") && !request.Fast {
				continue
			}
			sent++
			data, headers := stdWire(request)
			code := rawExchange("probe.waf.test", request.Method, request.URI, headers, data, true)
			// a request no rule scored writes no audit record, and records
			// land after the answer: a sentinel every CRS tier scores (one
			// nginx worker: records in request order) closes the request's
			rules, detectors := []int{}, []string{}
			sentinel := fmt.Sprintf("/__cdnca_eval_sentinel/%d", sent)
			for attempt := 0; ; attempt++ {
				if attempt == 3 {
					check("std probe sentinel", false, "%s: no audit record of %s", request.ID, sentinel)
					return
				}
				rawExchange("probe.waf.test", "GET", sentinel+"?v=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, "", true)
				found := false
				for wait := 0; wait < 100 && !found; wait++ {
					var next int64
					rules, detectors, next, found = auditVector(offset, sentinel+"?")
					if found {
						offset = next
					} else {
						time.Sleep(5 * time.Millisecond)
					}
				}
				if found {
					break
				}
			}
			encoded, _ := json.Marshal(map[string]any{"d": dataset, "id": request.ID, "a": request.Attack, "c": code, "r": rules, "x": detectors})
			fmt.Fprintf(out, "STDVEC %s\n", encoded)
		}
		fmt.Fprintf(out, "STDTIME dataset=%s requests=%d seconds=%.1f\n", dataset, sent, time.Since(started).Seconds())
		if err := scanner.Err(); err != nil {
			check("std corpus", false, "%s: %v", dataset, err)
		}
		reader.Close()
		file.Close()
	}
}
