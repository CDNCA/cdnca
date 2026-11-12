package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestValidateNodeStringSetOverBudget(t *testing.T) {
	good := []*agentv1.NodeStringSetOverBudgetV1{
		{SetId: "a", Revision: 1, Mode: "exact", EstimateBytes: 1, LiveBytes: 2, BudgetBytes: 64 << 20},
		{SetId: "b", Revision: 7, Mode: "contains", Members: 3},
	}
	if !validateNodeStringSetOverBudget(nil) || !validateNodeStringSetOverBudget(good) {
		t.Fatal("valid list refused")
	}
	bad := map[string][]*agentv1.NodeStringSetOverBudgetV1{
		"nil entry":  {nil},
		"empty id":   {{SetId: "", Revision: 1, Mode: "exact"}},
		"unsorted":   {good[1], good[0]},
		"duplicate":  {good[0], good[0]},
		"revision 0": {{SetId: "a", Revision: 0, Mode: "exact"}},
		"no mode":    {{SetId: "a", Revision: 1}},
		"huge":       {{SetId: "a", Revision: 1, Mode: "exact", LiveBytes: 1 << 63}},
		"too many":   make([]*agentv1.NodeStringSetOverBudgetV1, 257),
	}
	for name, sets := range bad {
		if validateNodeStringSetOverBudget(sets) {
			t.Fatalf("%s accepted", name)
		}
	}
}
