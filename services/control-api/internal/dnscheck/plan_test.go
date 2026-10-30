package dnscheck

import (
	"testing"
	"time"
)

func TestRepairPlanProducesExactRevisionGuardedOperations(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.TTL = 300
	request.Expected = []ExpectedRecord{
		{Type: RecordA, Values: []string{"192.0.2.10"}},
		{Type: RecordAAAA, Values: []string{"2001:db8::10"}},
	}
	request.Provider.Records = []ProviderRecord{
		{RecordID: "record-a", Name: request.Name, Type: RecordA, Value: "192.0.2.9", TTL: 60},
		{RecordID: "record-extra", Name: request.Name, Type: RecordA, Value: "192.0.2.8", TTL: 60},
		{RecordID: "record-cname", Name: request.Name, Type: RecordCNAME, Value: "old.example.test", TTL: 60},
	}
	normalized, err := normalizeRequest(request, now)
	if err != nil {
		t.Fatalf("normalizeRequest() error = %v", err)
	}
	first, err := buildRepairPlan(normalized)
	if err != nil {
		t.Fatalf("buildRepairPlan() error = %v", err)
	}
	second, _ := buildRepairPlan(normalized)
	if first.PreconditionRevision != 7 || first.ZoneID != testZoneID || first.Digest == "" || first.Digest != second.Digest {
		t.Fatalf("plan metadata = %#v", first)
	}
	if len(first.Operations) != 4 {
		t.Fatalf("operations = %#v", first.Operations)
	}
	counts := map[ProviderAction]int{}
	for index, operation := range first.Operations {
		counts[operation.Action]++
		if operation.Sequence != index+1 || operation.Name != "www.example.test." {
			t.Fatalf("operation %d = %#v", index, operation)
		}
		if operation.Action != ProviderCreate && operation.RecordID == "" {
			t.Fatalf("mutation lacks provider record id: %#v", operation)
		}
	}
	if counts[ProviderDelete] != 2 || counts[ProviderUpdate] != 1 || counts[ProviderCreate] != 1 {
		t.Fatalf("action counts = %#v; operations = %#v", counts, first.Operations)
	}
}

func TestRepairPlanNoopForMatchingProviderSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	request, err := normalizeRequest(baseRequest(now, RecordA, "192.0.2.10"), now)
	if err != nil {
		t.Fatalf("normalizeRequest() error = %v", err)
	}
	plan, err := buildRepairPlan(request)
	if err != nil || len(plan.Operations) != 0 || plan.Digest == "" {
		t.Fatalf("buildRepairPlan() = (%#v, %v)", plan, err)
	}
}
