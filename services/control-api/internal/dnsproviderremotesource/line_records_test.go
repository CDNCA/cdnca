package dnsproviderremotesource

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
)

func lineRecord(id string, recordType dnscheck.RecordType, value string, ttl uint32) dnsproviderremote.ZoneRecord {
	return dnsproviderremote.ZoneRecord{ID: id, Name: "s1.cdn.example.com.", Type: recordType, Value: value, TTL: ttl, Line: "境外"}
}

func TestLinePlan(t *testing.T) {
	const owner, line = "s1.cdn.example.com.", "境外"
	// Nothing there: one create.
	plan := linePlan(nil, owner, line, "cf.example.net.", 60)
	if len(plan) != 1 || plan[0].Action != dnscheck.ProviderCreate || plan[0].Line != line || plan[0].Value != "cf.example.net." {
		t.Fatalf("create plan = %+v", plan)
	}
	// Converged: nothing to write.
	current := []dnsproviderremote.ZoneRecord{lineRecord("c1", dnscheck.RecordCNAME, "cf.example.net.", 60)}
	if plan = linePlan(current, owner, line, "cf.example.net.", 60); len(plan) != 0 || !lineConverged(current, "cf.example.net.", 60) {
		t.Fatalf("converged plan = %+v", plan)
	}
	// Switch: the CNAME is updated in place (no gap), A records on the line
	// deleted first.
	current = append(current, lineRecord("a1", dnscheck.RecordA, "192.0.2.1", 300), lineRecord("c2", dnscheck.RecordCNAME, "x.example.net.", 60))
	plan = linePlan(current, owner, line, "backup.example.net.", 60)
	if len(plan) != 3 || plan[0].Action != dnscheck.ProviderDelete || plan[1].Action != dnscheck.ProviderDelete ||
		plan[2].Action != dnscheck.ProviderUpdate || plan[2].RecordID != "c1" || plan[2].PreviousValue != "cf.example.net." ||
		plan[2].Sequence != 3 {
		t.Fatalf("switch plan = %+v", plan)
	}
	// Follow the default line: every record on the line goes.
	plan = linePlan(current, owner, line, "", 60)
	if len(plan) != 3 {
		t.Fatalf("follow-default plan = %+v", plan)
	}
	for _, operation := range plan {
		if operation.Action != dnscheck.ProviderDelete || operation.Line != line {
			t.Fatalf("follow-default op = %+v", operation)
		}
	}
	if lineConverged(current, "", 60) || !lineConverged(nil, "", 60) {
		t.Fatal("follow-default convergence")
	}
}

func TestAddressLinePlan(t *testing.T) {
	const owner, line = "s1.cdn.example.com.", "电信"
	record := func(id string, recordType dnscheck.RecordType, value string, ttl, weight uint32) dnsproviderremote.ZoneRecord {
		return dnsproviderremote.ZoneRecord{ID: id, Name: owner, Type: recordType, Value: value, TTL: ttl, Line: line, Weight: weight}
	}
	desired, ok := desiredAddresses(AddressPublication{A: []string{"192.0.2.1", "192.0.2.2"}, AAAA: []string{"2001:db8::1"},
		Weights: map[string]uint32{"192.0.2.2": 20}})
	if !ok {
		t.Fatal("valid publication rejected")
	}
	plan := addressLinePlan(nil, owner, line, desired, 300)
	if len(plan) != 3 {
		t.Fatalf("create plan = %+v", plan)
	}
	for _, operation := range plan {
		if operation.Action != dnscheck.ProviderCreate || operation.Line != line || operation.TTL != 300 {
			t.Fatalf("create op = %+v", operation)
		}
		if operation.Value == "192.0.2.2" && operation.Weight != 20 {
			t.Fatalf("weight lost: %+v", operation)
		}
	}
	// A CNAME and a stale value go first, a TTL drift is updated in place,
	// the missing value is created last; a duplicate is deleted.
	current := []dnsproviderremote.ZoneRecord{
		record("c", dnscheck.RecordCNAME, "x.example.net.", 300, 0),
		record("a1", dnscheck.RecordA, "192.0.2.1", 600, 0),
		record("a1dup", dnscheck.RecordA, "192.0.2.1", 300, 0),
		record("old", dnscheck.RecordA, "192.0.2.9", 300, 0),
		record("v6", dnscheck.RecordAAAA, "2001:db8::1", 300, 0),
	}
	plan = addressLinePlan(current, owner, line, desired, 300)
	actions := ""
	for _, operation := range plan {
		actions += string(operation.Action[:1]) + ":" + operation.Value + " "
	}
	if want := "d:x.example.net. d:192.0.2.1 d:192.0.2.9 u:192.0.2.1 c:192.0.2.2 "; actions != want {
		t.Fatalf("plan = %q, want %q", actions, want)
	}
	if plan[len(plan)-1].Sequence != len(plan) {
		t.Fatal("sequences not assigned")
	}
	converged := []dnsproviderremote.ZoneRecord{record("a1", dnscheck.RecordA, "192.0.2.1", 300, 0),
		record("a2", dnscheck.RecordA, "192.0.2.2", 300, 20), record("v6", dnscheck.RecordAAAA, "2001:db8::1", 300, 0)}
	if plan = addressLinePlan(converged, owner, line, desired, 300); len(plan) != 0 || !addressLineConverged(converged, desired, 300) {
		t.Fatalf("converged plan = %+v", plan)
	}
	// Empty set: everything on the line goes.
	empty, _ := desiredAddresses(AddressPublication{})
	if plan = addressLinePlan(converged, owner, line, empty, 300); len(plan) != 3 || !addressLineConverged(nil, empty, 300) {
		t.Fatalf("empty plan = %+v", plan)
	}
	for _, bad := range []AddressPublication{{A: []string{"2001:db8::1"}}, {AAAA: []string{"192.0.2.1"}},
		{A: []string{"192.0.2.01"}}, {A: []string{"192.0.2.1"}, Weights: map[string]uint32{"192.0.2.1": 101}}} {
		if _, ok := desiredAddresses(bad); ok {
			t.Fatalf("%+v accepted", bad)
		}
	}
}
