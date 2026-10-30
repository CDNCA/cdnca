package edgegolden

import (
	"path/filepath"
	"strings"
	"testing"
)

const corpus = "../../../../tests/edge-golden/cdnca-v7"

// TestCorpusGoldenMatchesScenarios: every scenario of the committed corpus
// loads, has a golden recorded for exactly this version of it (a scenario
// edited without recording again fails here, without Docker), and every
// golden has a scenario. The compare rules file loads.
func TestCorpusGoldenMatchesScenarios(t *testing.T) {
	scenarios, err := LoadScenarios(filepath.Join(corpus, "scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, scenario := range scenarios {
		names[scenario.Name] = true
		golden, found, err := ReadObservation(filepath.Join(corpus, "expected"), scenario.Name)
		if err != nil || !found {
			t.Fatalf("%s: golden found=%v err=%v (tests/edge-golden/run.sh record %s)", scenario.Name, found, err, scenario.Name)
		}
		if golden.Digest != scenario.Digest() {
			t.Errorf("%s: golden recorded for another version of the scenario (tests/edge-golden/run.sh record %s)", scenario.Name, scenario.Name)
		}
		if len(golden.Steps) != len(scenario.Steps) {
			t.Errorf("%s: golden has %d steps, scenario %d", scenario.Name, len(golden.Steps), len(scenario.Steps))
		}
		for index, step := range scenario.Steps {
			if index < len(golden.Steps) && golden.Steps[index].ID != step.ID {
				t.Errorf("%s: golden step %d is %q, scenario %q", scenario.Name, index, golden.Steps[index].ID, step.ID)
			}
		}
	}
	paths, _ := filepath.Glob(filepath.Join(corpus, "expected", "*.json"))
	for _, path := range paths {
		if name := strings.TrimSuffix(filepath.Base(path), ".json"); !names[name] {
			t.Errorf("golden %s has no scenario", name)
		}
	}
	if _, err := LoadRules(filepath.Join(corpus, "compare.json")); err != nil {
		t.Fatal(err)
	}
}
