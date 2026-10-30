package dnscheck

import (
	"testing"
	"time"
)

func TestDNS02RepairPlanDetectsLineAndWeightDrift(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.TTL = 300
	request.Line = "境外"
	request.Weight = 80
	request.Provider.Records = []ProviderRecord{{
		RecordID: "record-1", Name: request.Name, Type: RecordA,
		Value: "192.0.2.10", TTL: 300, Line: "默认", Weight: 20,
	}}

	normalized, err := normalizeRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := buildRepairPlan(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Operations) != 1 {
		t.Fatalf("operations = %#v", plan.Operations)
	}
	operation := plan.Operations[0]
	if operation.Action != ProviderUpdate || operation.RecordID != "record-1" ||
		operation.Line != "境外" || operation.Weight != 80 ||
		operation.PreviousLine != "默认" || operation.PreviousWeight != 20 ||
		operation.PreviousValue != operation.Value || operation.PreviousTTL != operation.TTL ||
		operation.Reason != "routing_mismatch" {
		t.Fatalf("operation = %#v", operation)
	}

	changed := normalized
	changed.Weight = 81
	changedPlan, err := buildRepairPlan(changed)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Digest == changedPlan.Digest {
		t.Fatal("plan digest did not cover weight")
	}
	changed = normalized
	changed.Line = "电信"
	changedPlan, err = buildRepairPlan(changed)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Digest == changedPlan.Digest {
		t.Fatal("plan digest did not cover line")
	}
}

func TestDNS02DeletePreservesExactLineAndWeightIdentity(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	request := baseRequest(now, RecordAAAA, "2001:db8::10")
	request.Provider.Records = append(request.Provider.Records, ProviderRecord{
		RecordID: "record-stale", Name: request.Name, Type: RecordA,
		Value: "192.0.2.20", TTL: 600, Line: "教育网", Weight: 35,
	})
	normalized, err := normalizeRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := buildRepairPlan(normalized)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range plan.Operations {
		if operation.RecordID == "record-stale" {
			if operation.Action != ProviderDelete || operation.Line != "教育网" || operation.Weight != 35 {
				t.Fatalf("delete operation = %#v", operation)
			}
			return
		}
	}
	t.Fatalf("stale delete missing: %#v", plan.Operations)
}

func TestDNS02SafeStagesPreserveCurrentAndPreviousRoutingIdentity(t *testing.T) {
	operation := ProviderOperation{
		Sequence: 4, Action: ProviderUpdate, RecordID: "record-old", Name: "www.example.test.",
		Type: RecordA, Value: "192.0.2.20", TTL: 300, Line: "境外", Weight: 80,
		PreviousValue: "192.0.2.10", PreviousTTL: 600, PreviousLine: "默认", PreviousWeight: 20,
	}
	operations, deferred := safeOperationStages(RepairPlan{Operations: []ProviderOperation{operation}})
	if len(operations) != 1 || len(deferred) != 1 {
		t.Fatalf("operations = %#v; deferred = %#v", operations, deferred)
	}
	created := operations[0].Operation
	if created.Action != ProviderCreate || created.RecordID != "" ||
		created.Line != operation.Line || created.Weight != operation.Weight ||
		created.PreviousLine != "" || created.PreviousWeight != 0 {
		t.Fatalf("safe replacement create = %#v", created)
	}
	deleted := deferred[0].Operation
	if deleted.Action != ProviderDelete || deleted.RecordID != operation.RecordID ||
		deleted.Value != operation.PreviousValue || deleted.TTL != operation.PreviousTTL ||
		deleted.Line != operation.PreviousLine || deleted.Weight != operation.PreviousWeight {
		t.Fatalf("safe replacement delete = %#v", deleted)
	}
}

func TestDNS02AppliedCompensationPreservesExactRoutingIdentity(t *testing.T) {
	created := ProviderOperation{
		Action: ProviderCreate, Name: "new.example.test.", Type: RecordA,
		Value: "192.0.2.20", TTL: 300, Line: "境外", Weight: 80,
	}
	updated := ProviderOperation{
		Action: ProviderUpdate, RecordID: "record-update", Name: "www.example.test.",
		Type: RecordA, Value: "192.0.2.30", TTL: 300, Line: "联通", Weight: 70,
		PreviousValue: "192.0.2.10", PreviousTTL: 600, PreviousLine: "默认", PreviousWeight: 20,
	}
	compensation := compensationForApplied([]OperationResult{
		{Operation: created, ProviderRecordID: "record-created", Status: OperationSucceeded},
		{Operation: updated, Status: OperationSucceeded},
	})
	if len(compensation) != 2 {
		t.Fatalf("compensation = %#v", compensation)
	}
	inverseUpdate := compensation[0]
	if inverseUpdate.Action != ProviderUpdate || inverseUpdate.RecordID != updated.RecordID ||
		inverseUpdate.Value != updated.PreviousValue || inverseUpdate.TTL != updated.PreviousTTL ||
		inverseUpdate.Line != updated.PreviousLine || inverseUpdate.Weight != updated.PreviousWeight ||
		inverseUpdate.PreviousValue != updated.Value || inverseUpdate.PreviousTTL != updated.TTL ||
		inverseUpdate.PreviousLine != updated.Line || inverseUpdate.PreviousWeight != updated.Weight {
		t.Fatalf("update compensation = %#v", inverseUpdate)
	}
	inverseCreate := compensation[1]
	if inverseCreate.Action != ProviderDelete || inverseCreate.RecordID != "record-created" ||
		inverseCreate.Line != created.Line || inverseCreate.Weight != created.Weight {
		t.Fatalf("create compensation = %#v", inverseCreate)
	}
}

func TestDNS02CommittedDeleteCompensationPreservesExactRoutingIdentity(t *testing.T) {
	deleted := ProviderOperation{
		Action: ProviderDelete, RecordID: "record-deleted", Name: "old.example.test.", Type: RecordAAAA,
		Value: "2001:db8::10", TTL: 600, Line: "教育网", Weight: 35,
	}
	compensation := compensationForCommittedDeletes([]OperationResult{{
		Operation: deleted, Status: OperationSucceeded,
	}})
	if len(compensation) != 1 || compensation[0].Action != ProviderCreate ||
		compensation[0].Value != deleted.Value || compensation[0].TTL != deleted.TTL ||
		compensation[0].Line != deleted.Line || compensation[0].Weight != deleted.Weight {
		t.Fatalf("delete compensation = %#v", compensation)
	}
}
