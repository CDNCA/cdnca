package securitypublication

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

func TestSEC11CountMatchersProjectIntoCanonicalCCV2Carrier(t *testing.T) {
	policy := ccV2PolicyForTest()
	rule := &policy.Rules[0]
	rule.Conditions = append(rule.Conditions,
		securitypolicy.Condition{Field: "distinct_user_agents", Operator: "number_gte", Values: []string{"3"}},
		securitypolicy.Condition{Field: "status_404_count", Operator: "number_gte", Values: []string{"2"}},
	)
	compiled, err := compileCCV2(baseSite(), nil, activeBinding(t, policy))
	if err != nil {
		t.Fatalf("compileCCV2: %v", err)
	}
	match := compiled.Policy.Rules[0].Match
	if match.DistinctUserAgents != 3 || match.Status404Count != 2 || match.Port != 8080 {
		t.Fatalf("compiled SEC-11 match = %#v", match)
	}
}
