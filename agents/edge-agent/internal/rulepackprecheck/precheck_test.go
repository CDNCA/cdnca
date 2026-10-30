package rulepackprecheck

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The golden is produced by libs/rulepack (TestDifferentialGolden) and
// reproduced by the control plane (internal/rulepackcontrol): the agent must
// accept the same document from the same objects.
var golden = filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "differential")

func objects(t *testing.T) Objects {
	return func(sha string) ([]byte, error) { return os.ReadFile(filepath.Join(golden, "objects", sha)) }
}

func TestAgentAcceptsControlResolvedMounts(t *testing.T) {
	document, err := os.ReadFile(filepath.Join(golden, "security.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Check(document, objects(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0].Layer != "user" || rules[1].CC == nil || rules[1].CC.Limit.Requests != 300 ||
		rules[2].WAF == nil || rules[2].WAF.Action != "log" {
		t.Fatalf("rules = %+v", rules)
	}
	tampered := strings.Replace(string(document), `"requests": 300`, `"requests": 301`, 1)
	if tampered == string(document) {
		t.Fatal("fixture changed: tamper target missing")
	}
	if _, err := Check([]byte(tampered), objects(t)); !errors.Is(err, ErrRejected) {
		t.Fatalf("tampered params: %v", err)
	}
	missing := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	if _, err := Check(document, missing); !errors.Is(err, ErrRejected) {
		t.Fatalf("missing object: %v", err)
	}
}
