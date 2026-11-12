package nodemetrics

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func stringSetOverDelivery(t *testing.T, sets []*agentv1.NodeStringSetOverBudgetV1) *testDelivery {
	t.Helper()
	delivery := testMetricDelivery(t, true)
	var report agentv1.NodeMonitoringReport
	if err := proto.Unmarshal(delivery.payload, &report); err != nil {
		t.Fatal(err)
	}
	report.LoadMetricsV1.Telemetry.StringSetOverBudget = sets
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&report)
	if err != nil {
		t.Fatal(err)
	}
	delivery.payload = payload
	return delivery
}

// Field 16 decodes into Telemetry.StringSetOverBudget (stored with the
// telemetry JSON, so the console sees which set is over); malformed entries
// refuse the sample.
func TestDecodeStringSetOverBudgetField16(t *testing.T) {
	valid := func() []*agentv1.NodeStringSetOverBudgetV1 {
		return []*agentv1.NodeStringSetOverBudgetV1{
			{SetId: "0190a000-0000-7000-8000-0000000000aa", Revision: 3, Mode: "contains", Members: 10000,
				EstimateBytes: 70 << 20, LiveBytes: 1 << 20, BudgetBytes: 64 << 20},
			{SetId: "0190a000-0000-7000-8000-0000000000bb", Revision: 1, Mode: "exact", Members: 5,
				EstimateBytes: 1000, LiveBytes: 64 << 20, BudgetBytes: 64 << 20},
		}
	}
	decoder := NewDecoder(DefaultDecoderConfig())
	sample, skip, err := decoder.Decode(stringSetOverDelivery(t, valid()))
	if err != nil || skip || sample.Telemetry == nil || len(sample.Telemetry.StringSetOverBudget) != 2 {
		t.Fatalf("decode: %v %+v", err, sample.Telemetry)
	}
	got := sample.Telemetry.StringSetOverBudget[0]
	if got.SetID != "0190a000-0000-7000-8000-0000000000aa" || got.Revision != 3 || got.Mode != "contains" ||
		got.Members != 10000 || got.EstimateBytes != 70<<20 || got.BudgetBytes != 64<<20 {
		t.Fatalf("decoded %+v", got)
	}
	if !validTelemetry(sample.Telemetry) {
		t.Fatal("stored telemetry refused")
	}
	for name, mutate := range map[string]func([]*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1{
		"unsorted": func(s []*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1 {
			return []*agentv1.NodeStringSetOverBudgetV1{s[1], s[0]}
		},
		"duplicate": func(s []*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1 {
			return append(s, s[1])
		},
		"empty id": func(s []*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1 {
			s[0].SetId = ""
			return s
		},
		"revision 0": func(s []*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1 {
			s[0].Revision = 0
			return s
		},
		"no mode": func(s []*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1 {
			s[0].Mode = ""
			return s
		},
		"huge estimate": func(s []*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1 {
			s[0].EstimateBytes = 1 << 63
			return s
		},
		"nil entry": func(s []*agentv1.NodeStringSetOverBudgetV1) []*agentv1.NodeStringSetOverBudgetV1 {
			return append(s, nil)
		},
	} {
		if _, _, err := decoder.Decode(stringSetOverDelivery(t, mutate(valid()))); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
