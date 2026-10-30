// Command cdnca-edge-golden records the edge golden corpus with a renderer
// and compares a renderer's answers with it (tests/edge-golden/README.md).
//
//	cdnca-edge-golden record -scenarios DIR -out DIR [-renderer cdnca-dynroute] [-only a,b]
//	cdnca-edge-golden check  -scenarios DIR -expected DIR [-rules FILE] [-renderer NAME] [-actual DIR] [-report FILE]
//	cdnca-edge-golden diff   -expected DIR -actual DIR [-rules FILE] [-renderer NAME] [-report FILE]
//
// record and check run inside the node runtime image (tests/edge-golden/run.sh).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden"
	_ "github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "record":
		err = record(os.Args[2:])
	case "check":
		code, err = check(os.Args[2:])
	case "diff":
		code, err = diff(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cdnca-edge-golden:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cdnca-edge-golden record|check|diff [flags] (see tests/edge-golden/README.md)")
	os.Exit(2)
}

type common struct {
	scenarios, renderer, only, workDir, openResty, luaRoot, modSecurity, http3 string
	timeout                                                                    time.Duration
}

func (options *common) register(flags *flag.FlagSet) {
	flags.StringVar(&options.scenarios, "scenarios", "", "scenario directory")
	flags.StringVar(&options.renderer, "renderer", "cdnca-dynroute", "renderer name")
	flags.StringVar(&options.only, "only", "", "comma separated scenario names (default all)")
	flags.StringVar(&options.workDir, "work", os.TempDir(), "work directory")
	flags.StringVar(&options.openResty, "openresty", "/usr/local/openresty/bin/openresty", "OpenResty binary")
	flags.StringVar(&options.luaRoot, "lua-root", "/usr/local/share/cdnca", "node Lua tree")
	flags.StringVar(&options.modSecurity, "modsecurity", os.Getenv("CDNCA_EDGE_GOLDEN_MODSECURITY"), "managed WAF engine extension directory")
	flags.StringVar(&options.http3, "http3", os.Getenv("CDNCA_EDGE_GOLDEN_HTTP3"), "HTTP/3 client binary (tests/dynroute-filters/probe)")
	flags.DurationVar(&options.timeout, "timeout", 2*time.Minute, "timeout per scenario")
}

func (options *common) load() (edgegolden.Renderer, edgegolden.Env, []*edgegolden.Scenario, error) {
	renderer, err := edgegolden.Lookup(options.renderer)
	if err != nil {
		return nil, edgegolden.Env{}, nil, err
	}
	var only []string
	if options.only != "" {
		only = strings.Split(options.only, ",")
	}
	scenarios, err := edgegolden.LoadScenarios(options.scenarios, only...)
	if err != nil {
		return nil, edgegolden.Env{}, nil, err
	}
	pki, err := edgegolden.NewPKI()
	if err != nil {
		return nil, edgegolden.Env{}, nil, err
	}
	workDir, err := os.MkdirTemp(options.workDir, "cdnca-edge-golden-")
	if err != nil {
		return nil, edgegolden.Env{}, nil, err
	}
	return renderer, edgegolden.Env{WorkDir: workDir, OpenResty: options.openResty, LuaRoot: options.luaRoot,
		ModSecurity: options.modSecurity, HTTP3: options.http3, PKI: pki}, scenarios, nil
}

func runOne(options common, renderer edgegolden.Renderer, env edgegolden.Env, scenario *edgegolden.Scenario) (*edgegolden.Observation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	return edgegolden.Run(ctx, renderer, env, scenario)
}

func record(args []string) error {
	flags := flag.NewFlagSet("record", flag.ExitOnError)
	var options common
	options.register(flags)
	out := flags.String("out", "", "golden directory written")
	_ = flags.Parse(args)
	if options.scenarios == "" || *out == "" {
		return errors.New("record needs -scenarios and -out")
	}
	renderer, env, scenarios, err := options.load()
	if err != nil {
		return err
	}
	defer os.RemoveAll(env.WorkDir)
	failed := 0
	for _, scenario := range scenarios {
		observation, err := runOne(options, renderer, env, scenario)
		var skipped edgegolden.ErrSkipped
		switch {
		case errors.As(err, &skipped):
			fmt.Printf("SKIPPED  %s: %v (its golden is left as is)\n", scenario.Name, err)
			continue
		case err != nil:
			failed++
			fmt.Printf("ERROR    %s: %v\n", scenario.Name, err)
			continue
		}
		if err := edgegolden.WriteObservation(*out, observation); err != nil {
			return err
		}
		fmt.Printf("RECORDED %s (%d steps)\n", scenario.Name, len(observation.Steps))
	}
	if failed != 0 {
		return fmt.Errorf("%d scenarios failed", failed)
	}
	return nil
}

func check(args []string) (int, error) {
	flags := flag.NewFlagSet("check", flag.ExitOnError)
	var options common
	options.register(flags)
	expected := flags.String("expected", "", "golden directory")
	actual := flags.String("actual", "", "write this run's observations here")
	rulesFile := flags.String("rules", "", "compare rules")
	reportFile := flags.String("report", "", "write the JSON report here")
	strict := flags.Bool("strict", false, "a skipped scenario fails the check")
	_ = flags.Parse(args)
	if options.scenarios == "" || *expected == "" {
		return 0, errors.New("check needs -scenarios and -expected")
	}
	rules, err := edgegolden.LoadRules(*rulesFile)
	if err != nil {
		return 0, err
	}
	renderer, env, scenarios, err := options.load()
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(env.WorkDir)
	report := &edgegolden.Report{Renderer: renderer.Name(), Expected: *expected}
	skipped := 0
	for _, scenario := range scenarios {
		golden, found, err := edgegolden.ReadObservation(*expected, scenario.Name)
		if err != nil {
			report.Scenarios = append(report.Scenarios, edgegolden.ScenarioReport{Scenario: scenario.Name, Status: "error", Detail: err.Error()})
			continue
		}
		observation, err := runOne(options, renderer, env, scenario)
		var skip edgegolden.ErrSkipped
		switch {
		case errors.As(err, &skip):
			skipped++
			report.Scenarios = append(report.Scenarios, edgegolden.ScenarioReport{Scenario: scenario.Name, Status: "skipped", Detail: err.Error()})
			continue
		case err != nil:
			report.Scenarios = append(report.Scenarios, edgegolden.ScenarioReport{Scenario: scenario.Name, Status: "error", Detail: err.Error()})
			continue
		}
		if *actual != "" {
			if err := edgegolden.WriteObservation(*actual, observation); err != nil {
				return 0, err
			}
		}
		if !found {
			report.Scenarios = append(report.Scenarios, edgegolden.ScenarioReport{Scenario: scenario.Name, Status: "no_golden"})
			continue
		}
		compared, err := edgegolden.Compare(rules, renderer.Name(), golden, observation)
		if err != nil {
			return 0, err
		}
		report.Scenarios = append(report.Scenarios, compared)
	}
	if options.only == "" {
		addOrphans(report, *expected, scenarios)
	}
	return finish(report, *reportFile, *strict && skipped != 0)
}

// addOrphans reports goldens whose scenario no longer exists.
func addOrphans(report *edgegolden.Report, expected string, scenarios []*edgegolden.Scenario) {
	names := map[string]bool{}
	for _, scenario := range scenarios {
		names[scenario.Name] = true
	}
	paths, _ := filepath.Glob(filepath.Join(expected, "*.json"))
	sort.Strings(paths)
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		if !names[name] {
			report.Scenarios = append(report.Scenarios, edgegolden.ScenarioReport{Scenario: name, Status: "error",
				Detail: "golden without a scenario"})
		}
	}
}

func diff(args []string) (int, error) {
	flags := flag.NewFlagSet("diff", flag.ExitOnError)
	expected := flags.String("expected", "", "golden directory")
	actual := flags.String("actual", "", "observation directory")
	rulesFile := flags.String("rules", "", "compare rules")
	renderer := flags.String("renderer", "cdnca-dynroute", "renderer that produced -actual (selects semantic change rules)")
	reportFile := flags.String("report", "", "write the JSON report here")
	_ = flags.Parse(args)
	if *expected == "" || *actual == "" {
		return 0, errors.New("diff needs -expected and -actual")
	}
	rules, err := edgegolden.LoadRules(*rulesFile)
	if err != nil {
		return 0, err
	}
	report := &edgegolden.Report{Renderer: *renderer, Expected: *expected}
	paths, err := filepath.Glob(filepath.Join(*expected, "*.json"))
	if err != nil {
		return 0, err
	}
	sort.Strings(paths)
	seen := map[string]bool{}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		seen[name] = true
		golden, _, err := edgegolden.ReadObservation(*expected, name)
		if err != nil {
			return 0, err
		}
		observation, found, err := edgegolden.ReadObservation(*actual, name)
		if err != nil {
			return 0, err
		}
		if !found {
			report.Scenarios = append(report.Scenarios, edgegolden.ScenarioReport{Scenario: name, Status: "error", Detail: "no observation"})
			continue
		}
		compared, err := edgegolden.Compare(rules, *renderer, golden, observation)
		if err != nil {
			return 0, err
		}
		report.Scenarios = append(report.Scenarios, compared)
	}
	others, _ := filepath.Glob(filepath.Join(*actual, "*.json"))
	sort.Strings(others)
	for _, path := range others {
		if name := strings.TrimSuffix(filepath.Base(path), ".json"); !seen[name] {
			report.Scenarios = append(report.Scenarios, edgegolden.ScenarioReport{Scenario: name, Status: "no_golden"})
		}
	}
	return finish(report, *reportFile, false)
}

func finish(report *edgegolden.Report, reportFile string, failSkipped bool) (int, error) {
	report.WriteText(os.Stdout)
	if reportFile != "" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return 0, err
		}
		if err := os.WriteFile(reportFile, append(encoded, '\n'), 0o644); err != nil {
			return 0, err
		}
	}
	if report.Defects() != 0 || failSkipped {
		return 1, nil
	}
	return 0, nil
}
