package eventspool

import (
	"context"
	"testing"
)

// TF-E03：节点在 flush 结果未知（500/断开/无响应）时保留冻结行与计数并重发，
// 同一聚合行可能在不同偏移再写一次。Agent 对聚合行按来源+节点+行内容给稳定
// EventID，spool 只计一次；普通事件仍按偏移区分。
func TestTailerCountsRepeatedAggregateLineOnce(t *testing.T) {
	source, spool, config := newTailHarness(t)
	aggregate := sourceAccess(tenantOne)
	aggregate.Type = EventSecurity
	aggregate.ListenPort, aggregate.Protocol, aggregate.RequestClass = 443, "https", "standard"
	aggregate.CacheStatus, aggregate.StatusCode = "", 0
	aggregate.SecurityType, aggregate.Action, aggregate.Severity = "cc", "challenge", "medium"
	aggregate.Count = 5
	appendSource(t, source, aggregate, true)
	appendSource(t, source, aggregate, true)
	plain := aggregate
	plain.Count = 0
	appendSource(t, source, plain, true)
	appendSource(t, source, plain, true)

	tailer, err := NewTailer(config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tailer.TailOnce(context.Background(), spool)
	if err != nil {
		t.Fatal(err)
	}
	if result.CompletedLines != 4 || result.AppendedEvents != 3 || result.DuplicateEvents != 1 {
		t.Fatalf("tail = %#v, want 4 lines / 3 appended / 1 duplicate", result)
	}
	if first, second := aggregateEventID("a", "n", []byte("x")), aggregateEventID("b", "n", []byte("x")); first == second {
		t.Fatal("aggregate event id ignores the source")
	}
}
