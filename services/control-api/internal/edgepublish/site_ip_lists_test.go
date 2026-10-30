package edgepublish

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// An ip_list condition compiles to the list's resolved
// contents; an unresolved list refuses the publication.
func TestCompileSecurityRuleIPListCondition(t *testing.T) {
	listID := uuid.MustParse("0190a000-0000-7000-8000-000000000001")
	lists := securitypolicy.ResolvedIPLists{listID: {ListID: listID.String(), Revision: 4,
		CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}}}
	conditions := []securitypolicy.Condition{
		{Field: "method", Operator: "equals", Values: []string{"POST"}},
		{Field: "ip_list", Operator: "not_in_ip_list", Values: []string{listID.String()}},
	}
	matches, err := compileSecurityRuleMatchesFor([]string{"a.example.test"}, 80, conditions, lists)
	if err != nil || len(matches) != 1 || len(matches[0].IPLists) != 1 {
		t.Fatalf("%+v %v", matches, err)
	}
	got := matches[0].IPLists[0]
	if got.ListID != listID.String() || got.Revision != 4 || !got.Negate || len(got.CIDRs) != 2 {
		t.Fatalf("list %+v", got)
	}
	if !edgeconfig.WAFMatchUsesV4Conditions(matches[0]) {
		t.Fatal("IP list must require WAF v4")
	}
	if _, err := compileSecurityRuleMatchesFor([]string{"a.example.test"}, 80, conditions, nil); !errors.Is(err, ErrUnsupportedSecurityPolicy) {
		t.Fatalf("unresolved list: %v", err)
	}
}
