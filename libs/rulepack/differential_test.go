package rulepack

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/differential")

// DifferentialFixture is the shared input of the control plane / agent
// differential tests (services/control-api/internal/rulepackcontrol,
// agents/edge-agent/internal/rulepackprecheck): the authored packs, the
// mount settings and the security document this package resolves them to.
func differentialRequests(t *testing.T) []MountRequest {
	t.Helper()
	sqli := compileFile(t, "system-sqli.json")
	cc := compileFile(t, "system-cc.json")
	user := compileFile(t, "user-allow.json")
	return []MountRequest{
		{Pack: sqli, Priority: 500, Params: Params{"action": json.RawMessage(`"log"`)}, RuleStates: map[string]bool{"r020": false}},
		{Pack: cc, Priority: 200, Params: Params{"requests": json.RawMessage(`300`)}},
		{Pack: user, Priority: 500},
	}
}

func TestDifferentialGolden(t *testing.T) {
	resolution := Resolve(differentialRequests(t), Target{})
	if resolution.Security == nil {
		t.Fatalf("conflicts = %+v", resolution.Conflicts)
	}
	directory := filepath.Join("testdata", "differential")
	security, _ := json.MarshalIndent(resolution.Security, "", "  ")
	if *updateGolden {
		_ = os.RemoveAll(directory)
		if err := os.MkdirAll(filepath.Join(directory, "objects"), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, request := range differentialRequests(t) {
			if err := os.WriteFile(filepath.Join(directory, "objects", request.Pack.SHA256), request.Pack.Canonical, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, "security.json"), append(security, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	golden, err := os.ReadFile(filepath.Join(directory, "security.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(golden) != string(security)+"\n" {
		t.Fatalf("resolved security drifted from the golden (go test -update after an intended format change):\n%s", security)
	}
	for _, request := range differentialRequests(t) {
		stored, err := os.ReadFile(filepath.Join(directory, "objects", request.Pack.SHA256))
		if err != nil || string(stored) != string(request.Pack.Canonical) {
			t.Fatalf("golden object %s drifted", request.Pack.Pack.PackID)
		}
	}
}
