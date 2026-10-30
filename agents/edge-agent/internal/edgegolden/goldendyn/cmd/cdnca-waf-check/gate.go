package main

// -only eval -gate-base <dir> -gate-candidate <dir> -gate-corpus <file> -report <file>:
// the license service's G3 evaluation worker (ADR 0011 §5.5, RI-11). Each
// directory holds the CRS profile packs (or the rule intelligence mark packs,
// gate_mark.go) of one version (canonical bytes,
// <anything>.json); the base and the candidate run one after the other on a
// fresh node (one release cannot hold both: a set key's strong rules must
// agree across the profiles of a release), every corpus request goes to each
// tier and the report records the raw outcome per request and tier
// (p passed, b 403, c grey zone challenge, e error). No verdict here: the
// license service computes it from the two reports (evalreport.Decide), so
// stored reports are recomputable.
//
// -gate-std fast|full appends the waf-comparison datasets of -std-dir
// (wafcomp-mal, wafcomp-legit; fast: its --fast subset, the waf-eval-std
// counting): replayed as the dataset's client sent them, 403 b, no answer x
// (left out, as waf-comparison does), anything else p. The report records the
// dataset files' SHA-256 and request counts instead of the samples.

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ruleintel/evalreport"
	"github.com/cdnca/cdnca/libs/rulepack"
)

var (
	gateBase      = flag.String("gate-base", "", "-only eval: directory of the base CRS profile packs (G3 gate mode)")
	gateCandidate = flag.String("gate-candidate", "", "directory of the candidate CRS profile packs")
	gateCorpus    = flag.String("gate-corpus", "", "extra corpus after the built-in one and -corpus (evalreport.Request, one JSON per line)")
	gateReport    = flag.String("report", "", "write <file>.corpus.jsonl (the whole corpus run) and the reports <file>.base.json, <file>.candidate.json")
	gateWorkers   = flag.Int("gate-workers", 16, "concurrent requests")
	gateStd       = flag.String("gate-std", "", "fast|full: also the waf-comparison datasets in -std-dir (fast: its --fast subset)")
)

// gateStdSets are the public datasets a gate run takes (the waf-comparison
// project's two sets, user decision 10-20: every release with --fast).
var gateStdSets = []string{"wafcomp-mal", "wafcomp-legit"}

// gateStdScan streams one dataset file's requests of the mode, in file order.
func gateStdScan(name, mode string, visit func(stdRequest)) error {
	file, err := os.Open(filepath.Join(*stdDir, name+".jsonl.gz"))
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	for line := 1; scanner.Scan(); line++ {
		var request stdRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil || request.ID == "" {
			return fmt.Errorf("%s line %d: bad request (%v)", name, line, err)
		}
		if mode == evalreport.StdFast && !request.Fast {
			continue
		}
		visit(request)
	}
	return scanner.Err()
}

// gateStdSource is what the report records of the datasets: each file's
// SHA-256 and how many requests of the mode it holds.
func gateStdSource(mode string) (*evalreport.StdSource, error) {
	if mode != evalreport.StdFast && mode != evalreport.StdFull {
		return nil, fmt.Errorf("-gate-std %q: want fast or full", mode)
	}
	source := &evalreport.StdSource{Mode: mode}
	for _, name := range gateStdSets {
		file, err := os.Open(filepath.Join(*stdDir, name+".jsonl.gz"))
		if err != nil {
			return nil, err
		}
		hash := sha256.New()
		_, err = io.Copy(hash, file)
		file.Close()
		if err != nil {
			return nil, err
		}
		entry := evalreport.StdFile{Name: name, SHA256: hex.EncodeToString(hash.Sum(nil))}
		if err := gateStdScan(name, mode, func(stdRequest) { entry.Requests++ }); err != nil {
			return nil, err
		}
		source.Files = append(source.Files, entry)
	}
	return source, nil
}

// gateStdOutcome: the waf-eval-std counting of one dataset request.
func gateStdOutcome(host string, request stdRequest) byte {
	data, headers := stdWire(request)
	switch code := rawStatus(host, request.Method, request.URI, headers, data); {
	case code == 403:
		return evalreport.Blocked
	case code == statusGreyChallenge:
		return evalreport.Challenged
	case code == 0:
		return evalreport.Excluded
	default:
		return evalreport.Passed
	}
}

type gateJob struct {
	position int
	result   evalreport.Result
	send     func(host string) byte
}

// loadGatePacks reads a directory of CRS profile packs, ordered into tiers
// (narrowest first, rulepack.CRSTiers).
func loadGatePacks(dir string, manifest *edgeconfig.CRSManifest) ([]edgeconfig.CRSProfile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	byPack := map[string]edgeconfig.CRSProfile{}
	var all []edgeconfig.CRSProfile
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(content)
		_, profile, err := rulepack.LoadCRSProfile(content, hex.EncodeToString(sum[:]))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if _, dup := byPack[profile.Ref.PackID]; dup {
			return nil, fmt.Errorf("%s: two versions of %s", dir, profile.Ref.PackID)
		}
		byPack[profile.Ref.PackID] = profile
		all = append(all, profile)
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("%s: no CRS profile packs", dir)
	}
	ordered := make([]edgeconfig.CRSProfile, 0, len(all))
	for _, tier := range rulepack.CRSTiers(manifest, all, nil) {
		ordered = append(ordered, byPack[tier.PackID])
	}
	return ordered, nil
}

// gateCorpusOf is the corpus a gate run replays, in order: the built-in
// attacks, the CRS regression tests (-corpus), the built-in benign requests,
// then -gate-corpus (the license service's rule_intel_corpus and samples of
// the public datasets).
func gateCorpusOf(path string) ([]evalreport.Request, error) {
	var corpus []evalreport.Request
	seen := map[string]bool{}
	for _, request := range append(attackCorpus(), benignCorpus()...) {
		seen[request.ID] = true
		corpus = append(corpus, evalreport.Request{ID: request.ID, Attack: request.Attack, Category: request.Category,
			Method: request.Method, URI: request.URI, Headers: request.Headers, Data: request.Data, Value: request.Value})
	}
	if path == "" {
		return corpus, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 16<<20)
	for scanner.Scan() {
		if len(strings.TrimSpace(scanner.Text())) == 0 {
			continue
		}
		var request evalreport.Request
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			return nil, fmt.Errorf("corpus line %d: %w", len(corpus)+1, err)
		}
		if request.ID == "" || seen[request.ID] || request.Value == "" && (request.Method == "" || request.URI == "") {
			return nil, fmt.Errorf("corpus line %d: bad or duplicate request %q", len(corpus)+1, request.ID)
		}
		seen[request.ID] = true
		corpus = append(corpus, request)
	}
	return corpus, scanner.Err()
}

// gateOutcome sends every variant of a request: b if any is 403, else c if
// any is the grey zone challenge, else e if any failed (no answer or 5xx),
// else p.
func gateOutcome(host string, request evalreport.Request) byte {
	outcome := byte(evalreport.Passed)
	for _, variant := range variants(evalRequest{ID: request.ID, Method: request.Method, URI: request.URI,
		Headers: request.Headers, Data: request.Data, Value: request.Value, Attack: request.Attack}) {
		code := rawStatus(host, variant.Method, variant.URI, variant.Headers, variant.Data)
		switch {
		case code == 403:
			return evalreport.Blocked
		case code == statusGreyChallenge:
			outcome = evalreport.Challenged
		case (code == 0 || code >= 500) && outcome == evalreport.Passed:
			outcome = evalreport.Failed
		}
	}
	return outcome
}

// statusGreyChallenge: the grey zone challenge as rawStatus reports it once
// RI-03's challenge page is in (X-Cdnca-WAF: challenge, the client never sees
// the 599 the rules deny with); until then a tier never challenges.
const statusGreyChallenge = -1

func gateRunVersion(label string, packs []edgeconfig.CRSProfile, corpus []evalreport.Request, crsVersion, corpusDigest string,
	std *evalreport.StdSource) (evalreport.Report, bool) {
	all := map[string]edgeconfig.CRSProfile{}
	report := evalreport.Report{Schema: evalreport.Schema, CRSVersion: crsVersion, Corpus: corpusDigest, Std: std}
	sites := []edgesite.Site{}
	for index, profile := range packs {
		all[profile.Ref.SHA256] = profile
		report.Tiers = append(report.Tiers, evalreport.Tier{PackID: profile.Ref.PackID, Name: profile.Name,
			Version: profile.Ref.Version, SHA256: profile.Ref.SHA256})
		sites = append(sites, makeSite(40+index, fmt.Sprintf("eval%d.waf.test", index), &wafSpec{profile: profile}))
	}
	evalProfiles = all
	defer func() { evalProfiles = nil }()
	if _, err := startNode(sites, true); err != nil {
		check("gate "+label+" start", false, "%v", err)
		return report, false
	}
	defer stop()
	if rawStatus("eval0.waf.test", "GET", "/t?v=hello", nil, "") != 200 {
		check("gate "+label+" start", false, "clean request not 200")
		return report, false
	}
	total := len(corpus)
	if std != nil {
		for _, file := range std.Files {
			total += file.Requests
		}
	}
	report.Results = make([]evalreport.Result, total)
	jobs := make(chan gateJob, max(*gateWorkers, 1)*4)
	var wait sync.WaitGroup
	for range max(*gateWorkers, 1) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for job := range jobs {
				outcome := make([]byte, len(packs))
				for index := range packs {
					outcome[index] = job.send(fmt.Sprintf("eval%d.waf.test", index))
				}
				job.result.Outcome = string(outcome)
				report.Results[job.position] = job.result
			}
		}()
	}
	for position, request := range corpus {
		jobs <- gateJob{position: position, result: evalreport.Result{ID: request.ID, Attack: request.Attack, Category: request.Category},
			send: func(host string) byte { return gateOutcome(host, request) }}
	}
	position, scanErr := len(corpus), error(nil)
	if std != nil {
		for _, file := range std.Files {
			if scanErr = gateStdScan(file.Name, std.Mode, func(request stdRequest) {
				if position < total {
					jobs <- gateJob{position: position, result: evalreport.Result{ID: evalreport.StdPrefix + file.Name + ":" + request.ID,
						Attack: request.Attack, Category: file.Name + ":" + request.Category},
						send: func(host string) byte { return gateStdOutcome(host, request) }}
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
		check("gate "+label+" std", false, "datasets changed during the run: %d of %d requests (%v)", position, total, scanErr)
		return report, false
	}
	for _, line := range errorLines() {
		check("gate "+label+" error log", false, "%s", line)
	}
	return report, true
}

// writeGateCorpus writes the corpus as CorpusDigest hashes it (one
// json.Marshal per line), so the stored file recomputes corpus_sha256.
func writeGateCorpus(path string, corpus []evalreport.Request) error {
	var out strings.Builder
	for _, request := range corpus {
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(out.String()), 0o644)
}

func writeGateReport(path string, report evalreport.Report) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o644)
}

// gateRun is -only eval in gate mode; summary lines GATE per version and tier.
func gateRun() {
	bundle := rulecatalog.CRSRulesBundle()
	files, err := rulecatalog.DecodeWAFEngineBundle(*bundle)
	if err != nil {
		check("gate CRS text", false, "%v", err)
		return
	}
	manifest, err := edgeconfig.DeriveCRSManifest(&edgeconfig.CRSRuleText{Version: bundle.Version, Files: files})
	if err != nil {
		check("gate CRS text", false, "%v", err)
		return
	}
	corpus, err := gateCorpusOf(*gateCorpus)
	if err != nil || len(corpus) == 0 {
		check("gate corpus", false, "%s: %v (%d requests)", *gateCorpus, err, len(corpus))
		return
	}
	digest := evalreport.CorpusDigest(corpus)
	var std *evalreport.StdSource
	if *gateStd != "" {
		if std, err = gateStdSource(*gateStd); err != nil {
			check("gate std", false, "%v", err)
			return
		}
	}
	if err := writeGateCorpus(*gateReport+".corpus.jsonl", corpus); err != nil {
		check("gate corpus", false, "%v", err)
		return
	}
	// rule intelligence mark packs (scanner-signatures / autodefense-intel): replayed on the interpreter (gate_mark.go)
	if marks, err := loadMarkPacks(*gateCandidate); err == nil && len(marks) > 0 {
		markGateRun(marks, corpus, bundle.Version, digest, std)
		return
	}
	for _, version := range []struct{ label, dir string }{{"base", *gateBase}, {"candidate", *gateCandidate}} {
		packs, err := loadGatePacks(version.dir, manifest)
		if err != nil {
			check("gate "+version.label+" packs", false, "%v", err)
			return
		}
		report, ok := gateRunVersion(version.label, packs, corpus, bundle.Version, digest, std)
		if !ok {
			return
		}
		if err := writeGateReport(*gateReport+"."+version.label+".json", report); err != nil {
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
			fmt.Printf("GATE version=%s tier=%s pack=%s@%s %s\n", version.label, tier.Name, tier.PackID, tier.Version, strings.Join(keys, " "))
		}
	}
	check("gate reports", true, "%s.{base,candidate}.json corpus=%s requests=%d", *gateReport, digest, len(corpus))
}
