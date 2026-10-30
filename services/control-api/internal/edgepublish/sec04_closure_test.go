package edgepublish

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
)

func TestSEC04CompilesRepeatedClientIPConditionsAsIntersection(t *testing.T) {
	conditions := []securitypolicy.Condition{
		{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"0.0.0.0/0", "2001:db8::/32"}},
		{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.129/25", "2001:db8:1::1/48"}},
	}
	got, err := compileSecurityRuleMatches("cdn.example.com", 443, conditions)
	if err != nil {
		t.Fatalf("compileSecurityRuleMatches() error = %v", err)
	}
	want := []edgeconfig.WAFMatch{
		{Host: "cdn.example.com", Port: 443, SourceCIDR: "192.0.2.128/25"},
		{Host: "cdn.example.com", Port: 443, SourceCIDR: "2001:db8:1::/48"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("matches = %#v, want %#v", got, want)
	}
}

func TestSEC04RepeatedClientIPConditionsRemainFailClosed(t *testing.T) {
	t.Run("disjoint intersection", func(t *testing.T) {
		got, err := compileSecurityRuleMatches("cdn.example.com", 80, []securitypolicy.Condition{
			{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}},
			{Field: "client_ip", Operator: "equals", Values: []string{"198.51.100.9"}},
		})
		if err != nil || len(got) != 0 {
			t.Fatalf("matches = %#v, error = %v, want no matches", got, err)
		}
	})

	t.Run("duplicate non client field", func(t *testing.T) {
		_, err := compileSecurityRuleMatches("cdn.example.com", 80, []securitypolicy.Condition{
			{Field: "method", Operator: "equals", Values: []string{"GET"}},
			{Field: "method", Operator: "equals", Values: []string{"POST"}},
		})
		if !errors.Is(err, ErrUnsupportedSecurityPolicy) {
			t.Fatalf("error = %v, want ErrUnsupportedSecurityPolicy", err)
		}
	})
}
