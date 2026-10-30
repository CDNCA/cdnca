package dnscheck

import (
	"errors"
	"testing"
	"time"
)

// 节点管理 > DNS配置 "开启IP权重": each A value carries its endpoint weight.
func TestRepairPlanUsesPerValueWeights(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	request := baseRequest(now, RecordA, "192.0.2.10", "192.0.2.11")
	request.Line = "默认"
	request.Expected[0].Weights = map[string]uint32{"192.0.2.10": 80, "192.0.2.11": 20}
	request.Provider.Records[0].Line, request.Provider.Records[0].Weight = "默认", 80
	normalized, err := normalizeRequest(request, now)
	if err != nil {
		t.Fatalf("normalizeRequest() error = %v", err)
	}
	plan, err := buildRepairPlan(normalized)
	if err != nil {
		t.Fatalf("buildRepairPlan() error = %v", err)
	}
	if len(plan.Operations) != 1 {
		t.Fatalf("operations = %+v", plan.Operations)
	}
	create := plan.Operations[0]
	if create.Action != ProviderCreate || create.Value != "192.0.2.11" || create.Weight != 20 || create.Line != "默认" {
		t.Fatalf("create = %+v", create)
	}

	// A kept value whose weight moved is updated in place.
	request.Expected[0].Weights["192.0.2.10"] = 50
	normalized, err = normalizeRequest(request, now)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = buildRepairPlan(normalized)
	if err != nil {
		t.Fatal(err)
	}
	var update *ProviderOperation
	for index := range plan.Operations {
		if plan.Operations[index].Action == ProviderUpdate {
			update = &plan.Operations[index]
		}
	}
	if update == nil || update.Weight != 50 || update.PreviousWeight != 80 || update.Reason != "routing_mismatch" {
		t.Fatalf("update = %+v (all %+v)", update, plan.Operations)
	}
}

func TestPerValueWeightsAreValidated(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for name, weights := range map[string]map[string]uint32{
		"zero weight":      {"192.0.2.10": 0},
		"over 100":         {"192.0.2.10": 101},
		"unknown value":    {"192.0.2.99": 10},
		"more than values": {"192.0.2.10": 10, "192.0.2.11": 10},
	} {
		request := baseRequest(now, RecordA, "192.0.2.10")
		request.Expected[0].Weights = weights
		if _, err := normalizeRequest(request, now); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	// Without weights the request (and its digest input) is unchanged.
	request := baseRequest(now, RecordA, "192.0.2.10")
	normalized, err := normalizeRequest(request, now)
	if err != nil || normalized.Expected[0].Weights != nil {
		t.Fatalf("unweighted = %+v, %v", normalized.Expected, err)
	}
}
