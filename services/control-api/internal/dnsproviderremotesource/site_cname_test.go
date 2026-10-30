package dnsproviderremotesource

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

const (
	testOwner = "www.example.com."
	testSplit = "s1.cdn.example.net."
)

func TestSiteCNAMEPlanCreatesWhenNameIsEmpty(t *testing.T) {
	operation, before, err := siteCNAMEPlan(nil, testOwner, testSplit)
	if err != nil || before != "" || operation == nil || operation.Action != dnscheck.ProviderCreate ||
		operation.Type != dnscheck.RecordCNAME || operation.Value != testSplit || operation.TTL != siteCNAMETTL ||
		operation.Name != testOwner || operation.Line != "" {
		t.Fatalf("plan = %+v %q %v", operation, before, err)
	}
}

func TestSiteCNAMEPlanUpdatesTheSharedCNAMEInPlace(t *testing.T) {
	current := []dnsproviderremote.ZoneRecord{{ID: "r1", Name: testOwner, Type: dnscheck.RecordCNAME,
		Value: "pkg.cdn.example.net.", TTL: 300, Line: "默认"}}
	operation, before, err := siteCNAMEPlan(current, testOwner, testSplit)
	if err != nil || before != "pkg.cdn.example.net" || operation == nil || operation.Action != dnscheck.ProviderUpdate ||
		operation.RecordID != "r1" || operation.Value != testSplit || operation.TTL != 300 ||
		operation.PreviousValue != "pkg.cdn.example.net." || operation.Line != "默认" {
		t.Fatalf("plan = %+v %q %v", operation, before, err)
	}
}

func TestSiteCNAMEPlanAlreadyPointedIsNoOp(t *testing.T) {
	current := []dnsproviderremote.ZoneRecord{{ID: "r1", Type: dnscheck.RecordCNAME, Value: "S1.cdn.example.net", TTL: 600}}
	operation, before, err := siteCNAMEPlan(current, testOwner, testSplit)
	if err != nil || operation != nil || before != "s1.cdn.example.net" {
		t.Fatalf("plan = %+v %q %v", operation, before, err)
	}
}

// Anything but one default-line CNAME is left alone: nothing is deleted.
func TestSiteCNAMEPlanConflicts(t *testing.T) {
	for name, current := range map[string][]dnsproviderremote.ZoneRecord{
		"a record":   {{ID: "r1", Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 600}},
		"aaaa":       {{ID: "r1", Type: dnscheck.RecordAAAA, Value: "2001:db8::1", TTL: 600}},
		"two":        {{ID: "r1", Type: dnscheck.RecordCNAME, Value: "a.", TTL: 600}, {ID: "r2", Type: dnscheck.RecordCNAME, Value: "b.", TTL: 600, Line: "境外"}},
		"other line": {{ID: "r1", Type: dnscheck.RecordCNAME, Value: "a.", TTL: 600, Line: "电信"}},
		"weighted":   {{ID: "r1", Type: dnscheck.RecordCNAME, Value: "a.", TTL: 600, Weight: 10}},
	} {
		operation, _, err := siteCNAMEPlan(current, testOwner, testSplit)
		if operation != nil || CNAMEFailureCode(err) != CNAMECodeConflict {
			t.Fatalf("%s: plan = %+v %v", name, operation, err)
		}
	}
}

func TestSiteCNAMEConverged(t *testing.T) {
	good := []dnsproviderremote.ZoneRecord{{Type: dnscheck.RecordCNAME, Value: "s1.cdn.example.net", Line: "默认"}}
	if !siteCNAMEConverged(good, testSplit) {
		t.Fatal("converged record rejected")
	}
	if siteCNAMEConverged(append(good, good[0]), testSplit) ||
		siteCNAMEConverged([]dnsproviderremote.ZoneRecord{{Type: dnscheck.RecordCNAME, Value: "other."}}, testSplit) {
		t.Fatal("unconverged records accepted")
	}
}

func TestCNAMEFailureCode(t *testing.T) {
	for err, want := range map[error]string{
		&CNAMEError{Code: CNAMECodeApex}:                                  CNAMECodeApex,
		&dnsproviderremote.Error{Code: dnsproviderremote.CodeUnsupported}: "dns_provider_" + string(dnsproviderremote.CodeUnsupported),
		ErrNoManagedZone: CNAMECodeNotHosted,
		ErrUnavailable:   CNAMECodeUnavailable,
	} {
		if got := CNAMEFailureCode(err); got != want {
			t.Fatalf("%v: %q, want %q", err, got, want)
		}
	}
}

// A wildcard domain is refused before any provider call.
func TestSiteCNAMEWriterRefusesWildcard(t *testing.T) {
	var writer *SiteCNAMEWriter
	_, err := writer.Point(context.Background(), uuid.New(), "*.example.com", testSplit)
	if CNAMEFailureCode(err) != CNAMECodeWildcard {
		t.Fatalf("Point = %v", err)
	}
}

// n10-dnshosted: a site domain under the hosted domain (868yun.com) but
// outside the CNAME zone (cdn.868yun.com) is only rewritten while its record
// already points into the CNAME zone.
func TestWithinZone(t *testing.T) {
	for _, test := range []struct {
		name, zone string
		want       bool
	}{
		{"pkg1.cdn.868yun.com", "cdn.868yun.com", true},
		{"cdnca-t1.868yun.com", "cdn.868yun.com", false},
		{"cdn.868yun.com", "cdn.868yun.com", false},
		{"xcdn.868yun.com", "cdn.868yun.com", false},
		{"", "cdn.868yun.com", false},
		{"a.cdn.868yun.com", "", false},
	} {
		if got := withinZone(test.name, test.zone); got != test.want {
			t.Fatalf("withinZone(%q, %q) = %v", test.name, test.zone, got)
		}
	}
}
