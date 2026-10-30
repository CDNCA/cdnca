package cnameallocation

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

// The reconcile request of a CNAME target must be accepted by dnscheck: a
// missing propagation window made every allocation fail with
// dns_reconcile_unavailable before any provider call.
func TestTargetCheckRequestIsAcceptedByReconcile(t *testing.T) {
	target := Target{TenantID: uuid.New(), SiteID: uuid.New(), OwnerName: "abc.cdn.example.com", TTL: 300,
		Values: TargetValues{A: []string{"192.0.2.1", "192.0.2.2"}, AAAA: []string{"2001:db8::1"}},
		ZoneID: uuid.New(), ZoneRevision: 3}
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{IdempotencyKey: "cname-test", Check: target.checkRequest()}, time.Now)
	if err != nil {
		t.Fatalf("PrepareReconcile() error = %v", err)
	}
	creates := 0
	for _, operation := range prepared.Result.Operations {
		if operation.Operation.Action != dnscheck.ProviderCreate || operation.Operation.TTL != 300 || operation.Operation.Weight != 0 {
			t.Fatalf("operation = %+v", operation)
		}
		creates++
	}
	if creates != 3 {
		t.Fatalf("operations = %+v", prepared.Result.Operations)
	}
}

func TestPublishSettingsApplyTTLAndWeights(t *testing.T) {
	tenantID, siteID := uuid.New(), uuid.New()
	values := TargetValues{A: []string{"192.0.2.1", "192.0.2.2"}}
	request := PublishCheckRequest(tenantID, siteID, uuid.New(), 1, "abc.cdn.example.com", values, PublishSettings{
		TTL: 600, Line: "默认", Weights: map[WeightKey]uint32{{Address: "192.0.2.1"}: 70, {Address: "192.0.2.2"}: 30},
	})
	if request.TTL != 600 || request.PropagationWindow != 20*time.Minute {
		t.Fatalf("request ttl/window = %d %s", request.TTL, request.PropagationWindow)
	}
	prepared, err := dnscheck.PrepareReconcile(dnscheck.ReconcileRequest{IdempotencyKey: "cname-weights", Check: request}, time.Now)
	if err != nil {
		t.Fatalf("PrepareReconcile() error = %v", err)
	}
	got := map[string]uint32{}
	for _, operation := range prepared.Result.Operations {
		if operation.Operation.TTL != 600 || operation.Operation.Line != "默认" {
			t.Fatalf("operation = %+v", operation)
		}
		got[operation.Operation.Value] = operation.Operation.Weight
	}
	if got["192.0.2.1"] != 70 || got["192.0.2.2"] != 30 {
		t.Fatalf("weights = %v", got)
	}
	// Short TTLs keep the 5 minute minimum window.
	if short := PublishCheckRequest(tenantID, siteID, uuid.New(), 1, "x.cdn.example.com", values, PublishSettings{TTL: 60}); short.PropagationWindow != 5*time.Minute {
		t.Fatalf("short window = %s", short.PropagationWindow)
	}
}

// NET-02（fp-net2）：同一 IP 挂在多条运营商线路时权重按 (carrier, address) 各自保留；
// 默认线路取默认运营商那条，没有则取运营商最小的那条，与行顺序无关。
func TestPublishSettingsWeightsKeepEachCarrier(t *testing.T) {
	settings := PublishSettings{Weights: map[WeightKey]uint32{
		{Carrier: "电信", Address: "192.0.2.1"}: 70, {Carrier: "联通", Address: "192.0.2.1"}: 20,
		{Address: "192.0.2.1"}: 50, {Carrier: "移动", Address: "192.0.2.2"}: 30, {Carrier: "联通", Address: "192.0.2.2"}: 90,
	}}
	if len(settings.Weights) != 5 {
		t.Fatalf("weights = %v", settings.Weights)
	}
	if weight, ok := settings.DefaultLineWeight("192.0.2.1"); !ok || weight != 50 {
		t.Fatalf("default carrier weight = %d %v", weight, ok)
	}
	// "移动" < "联通" in byte order.
	if weight, ok := settings.DefaultLineWeight("192.0.2.2"); !ok || weight != 30 {
		t.Fatalf("smallest carrier weight = %d %v", weight, ok)
	}
	if _, ok := settings.DefaultLineWeight("192.0.2.3"); ok {
		t.Fatal("unknown address has no weight")
	}
	request := PublishCheckRequest(uuid.New(), uuid.New(), uuid.New(), 1, "abc.cdn.example.com",
		TargetValues{A: []string{"192.0.2.1", "192.0.2.2"}}, settings)
	if got := request.Expected[0].Weights; got["192.0.2.1"] != 50 || got["192.0.2.2"] != 30 {
		t.Fatalf("default line weights = %v", got)
	}
}
