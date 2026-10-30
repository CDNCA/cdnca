package rulepack

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack/rulegen"
)

func newRuleGen(seed uint64) *rulegen.Gen { return rulegen.New(seed) }

func genUUID(n int, salt uint32) string { return rulegen.UUID(n, salt) }

// genPlan is rulegen Plan of total rules, with its match index if indexed.
func genPlan(t testing.TB, g *rulegen.Gen, total int, indexed bool) edgeconfig.RulePlan {
	t.Helper()
	plan, err := g.Plan(total)
	if err != nil {
		t.Fatal(err)
	}
	if indexed {
		if err := AttachMatchIndex(&plan); err != nil {
			t.Fatalf("index of %d rules: %v", total, err)
		}
	}
	return plan
}
