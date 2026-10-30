package gatewayclient

import (
	"reflect"
	"testing"
)

func deploymentItem(key string) workItem { return workItem{kind: workDeployment, key: key} }

func pendingKeys(pending []workItem) []string {
	keys := make([]string, 0, len(pending))
	for _, item := range pending {
		keys = append(keys, item.key)
	}
	return keys
}

func TestScopedEnqueueOrdersScopesByArrival(t *testing.T) {
	keys := map[workItem]string{}
	var pending []workItem
	for _, item := range []struct{ key, scope string }{{"a1", "scope-a"}, {"b1", "scope-b"}, {"c1", "scope-c"}} {
		var replaced *workItem
		var outcome scopedEnqueueOutcome
		pending, replaced, outcome = enqueueScopedDeployment(pending, keys, deploymentItem(item.key), item.scope)
		if outcome != scopedEnqueued || replaced != nil {
			t.Fatalf("enqueue(%s) = (%v, %v)", item.key, replaced, outcome)
		}
		keys[deploymentItem(item.key)] = item.scope
	}
	if got := pendingKeys(pending); !reflect.DeepEqual(got, []string{"a1", "b1", "c1"}) {
		t.Fatalf("pending = %v", got)
	}
}

func TestScopedEnqueueSupersedesPendingSameScopeInPlace(t *testing.T) {
	keys := map[workItem]string{deploymentItem("a1"): "scope-a", deploymentItem("b1"): "scope-b"}
	pending := []workItem{deploymentItem("a1"), deploymentItem("b1")}
	pending, replaced, outcome := enqueueScopedDeployment(pending, keys, deploymentItem("a2"), "scope-a")
	if outcome != scopedEnqueued || replaced == nil || replaced.key != "a1" {
		t.Fatalf("enqueue(a2) = (%v, %v), want a1 superseded", replaced, outcome)
	}
	if got := pendingKeys(pending); !reflect.DeepEqual(got, []string{"a2", "b1"}) {
		t.Fatalf("pending = %v, want a2 in a1's place", got)
	}
}

func TestScopedEnqueueNeverSupersedesUnkeyedOrOtherWork(t *testing.T) {
	keys := map[workItem]string{deploymentItem("cert"): ""}
	overlay := workItem{kind: workACMEHTTP01Overlay, key: "a1"}
	pending := []workItem{deploymentItem("cert"), overlay}
	pending, replaced, outcome := enqueueScopedDeployment(pending, keys, deploymentItem("cert2"), "")
	if outcome != scopedEnqueued || replaced != nil {
		t.Fatalf("unkeyed enqueue = (%v, %v)", replaced, outcome)
	}
	keys[deploymentItem("cert2")] = ""
	// A key matching an overlay item's record key must not replace it.
	pending, replaced, _ = enqueueScopedDeployment(pending, keys, deploymentItem("a2"), "a1")
	if replaced != nil {
		t.Fatalf("overlay work was superseded: %v", replaced)
	}
	if got := pendingKeys(pending); !reflect.DeepEqual(got, []string{"cert", "a1", "cert2", "a2"}) {
		t.Fatalf("pending = %v", got)
	}
}

func TestScopedEnqueueRejectsWhenFullButStillSupersedes(t *testing.T) {
	keys := map[workItem]string{}
	var pending []workItem
	for index := 0; index < multiTenantDeploymentQueueLimit; index++ {
		item := deploymentItem(string(rune('a'+index)) + "1")
		pending, _, _ = enqueueScopedDeployment(pending, keys, item, "scope-"+item.key)
		keys[item] = "scope-" + item.key
	}
	// Non-scoped work does not count toward the scoped limit.
	pending = append(pending, workItem{kind: workACMEHTTP01Overlay, key: "overlay"})
	if _, replaced, outcome := enqueueScopedDeployment(pending, keys, deploymentItem("new"), "scope-new"); outcome != scopedQueueFull || replaced != nil {
		t.Fatalf("enqueue into full queue = (%v, %v), want full", replaced, outcome)
	}
	pending, replaced, outcome := enqueueScopedDeployment(pending, keys, deploymentItem("a2"), "scope-a1")
	if outcome != scopedEnqueued || replaced == nil || replaced.key != "a1" || len(pending) != multiTenantDeploymentQueueLimit+1 {
		t.Fatalf("same-scope replacement in full queue = (%v, %v, len %d)", replaced, outcome, len(pending))
	}
}
