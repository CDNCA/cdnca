package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
)

func TestNodeSecurityEventsReportEmptyConnectionBans(t *testing.T) {
	const nodeID = "8b5d1c1e-3a43-4a47-9a6b-4a0bb2d1f0a1"
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	events := newNodeSecurityEvents(nodeID, func() time.Time { return at })
	client := netip.MustParseAddr("::ffff:198.51.100.7")
	events.EmptyConnectionBan(client, 12, 10*time.Minute)
	events.EmptyConnectionBan(client, 13, 10*time.Minute)
	var seqs []uint64
	for range 2 {
		report, err := autodefense.DecodeReport(<-events.Reports())
		if err != nil {
			t.Fatal(err)
		}
		event := report.NodeEvent
		if report.Kind != autodefense.ReportNodeEvent || report.NodeID != nodeID || report.SiteID != "" || event.Client != "198.51.100.7" ||
			event.Source != "ddos" || event.Kind != "empty_connection_ban" || event.DurationSeconds != 600 || event.Level != autodefense.LevelKernel {
			t.Fatalf("report = %+v %+v", report, event)
		}
		seqs = append(seqs, report.Seq)
	}
	// Same clock: seq still grows (idempotency key per node).
	if seqs[0] != uint64(at.UnixMilli()) || seqs[1] != seqs[0]+1 {
		t.Fatalf("seqs = %v", seqs)
	}
	// A full queue drops instead of blocking the detector.
	for range nodeSecurityEventQueue + 5 {
		events.EmptyConnectionBan(client, 1, time.Minute)
	}
	if events.dropped != 5 {
		t.Fatalf("dropped = %d", events.dropped)
	}
	var nilEvents *nodeSecurityEvents
	nilEvents.EmptyConnectionBan(client, 1, time.Minute) // no panic
}

func TestMergeReports(t *testing.T) {
	if mergeReports(nil, nil) != nil {
		t.Fatal("merge of nothing")
	}
	first, second := make(chan []byte, 1), make(chan []byte, 1)
	if mergeReports(first, nil) != (<-chan []byte)(first) {
		t.Fatal("single channel not passed through")
	}
	merged := mergeReports(first, second)
	first <- []byte("a")
	second <- []byte("b")
	got := map[string]bool{}
	for range 2 {
		select {
		case report := <-merged:
			got[string(report)] = true
		case <-time.After(5 * time.Second):
			t.Fatal("merged channel stalled")
		}
	}
	if !got["a"] || !got["b"] {
		t.Fatalf("got %v", got)
	}
	close(first)
	close(second)
	if _, ok := <-merged; ok {
		t.Fatal("merged channel not closed")
	}
}

// Kernel bans found by polling (DDoS rate rules, L4 guard) and the summary of
// those beyond a step's budget are valid node_event reports.
func TestNodeSecurityEventsReportKernelBans(t *testing.T) {
	const nodeID = "8b5d1c1e-3a43-4a47-9a6b-4a0bb2d1f0a1"
	events := newNodeSecurityEvents(nodeID, time.Now)
	events.KernelBan("ddos", "rate_ban", "new_connection_rate", netip.MustParseAddr("2001:db8:5::"), 1, 118*time.Second)
	events.KernelBan("l4guard", "kernel_ban", "l4_guard_rule", netip.MustParseAddr("203.0.113.9"), 1, 48*time.Hour)
	events.KernelBan("ddos", "rate_ban", "new_connection_rate", netip.Addr{}, 10, 0)
	want := []autodefense.NodeEvent{
		{Source: "ddos", Kind: "rate_ban", Client: "2001:db8:5::", Count: 1, DurationSeconds: 118, Level: autodefense.LevelKernel, Reason: "new_connection_rate"},
		{Source: "l4guard", Kind: "kernel_ban", Client: "203.0.113.9", Count: 1, DurationSeconds: autodefense.MaxMitigationSeconds, Level: autodefense.LevelKernel, Reason: "l4_guard_rule"},
		{Source: "ddos", Kind: "rate_ban", Count: 10, Level: autodefense.LevelKernel, Reason: "new_connection_rate"},
	}
	for index, expected := range want {
		select {
		case raw := <-events.Reports():
			report, err := autodefense.DecodeReport(raw)
			if err != nil || *report.NodeEvent != expected {
				t.Fatalf("event %d = %+v %v", index, report.NodeEvent, err)
			}
		default:
			t.Fatalf("event %d not reported (dropped %d)", index, events.dropped)
		}
	}
}

// Without a local runtime the receiver still exists for platform events
// (F4): every snapshot part is refused with not_supported.
func TestAutoDefenseReceiverWithoutRuntimeCarriesNodeEvents(t *testing.T) {
	const nodeID = "8b5d1c1e-3a43-4a47-9a6b-4a0bb2d1f0a1"
	if newAutoDefenseReceiver(nodeID, nil, nil, nil) != nil || newAutoDefenseReceiver("", nil, nil, newNodeSecurityEvents(nodeID, time.Now)) != nil {
		t.Fatal("receiver without runtime and events, or without identity")
	}
	events := newNodeSecurityEvents(nodeID, time.Now)
	receiver := newAutoDefenseReceiver(nodeID, nil, nil, events)
	if receiver == nil {
		t.Fatal("no receiver for platform events")
	}
	if result := receiver.ApplyAutoDefense([]byte(`{}`)); result.Applied || result.ErrorCode != autodefense.ErrorNotSupported {
		t.Fatalf("result %+v", result)
	}
	events.EmptyConnectionBan(netip.MustParseAddr("198.51.100.7"), 3, time.Minute)
	select {
	case raw := <-receiver.Reports():
		if report, err := autodefense.DecodeReport(raw); err != nil || report.Kind != autodefense.ReportNodeEvent {
			t.Fatalf("report %+v %v", report, err)
		}
	case <-time.After(time.Second):
		t.Fatal("platform event not forwarded")
	}
}

// The XDP filter's run time fallback and reattach are node
// security events (source xdp) the contract accepts.
func TestNodeSecurityEventsReportXDPTransitions(t *testing.T) {
	events := newNodeSecurityEvents("8b5d1c1e-3a43-4a47-9a6b-4a0bb2d1f0a1", time.Now)
	events.XDPFallback("verify_failed")
	events.XDPFallback("")
	events.XDPReattached("generic")
	want := []autodefense.NodeEvent{
		{Source: "xdp", Kind: "fallback", Count: 1, Level: autodefense.LevelKernel, Reason: "verify_failed"},
		{Source: "xdp", Kind: "fallback", Count: 1, Level: autodefense.LevelKernel, Reason: "unknown"},
		{Source: "xdp", Kind: "reattached", Count: 1, Level: autodefense.LevelXDP, Reason: "generic"},
	}
	for index, expected := range want {
		select {
		case raw := <-events.Reports():
			report, err := autodefense.DecodeReport(raw)
			if err != nil || *report.NodeEvent != expected {
				t.Fatalf("event %d = %+v %v", index, report.NodeEvent, err)
			}
		default:
			t.Fatalf("event %d not reported (dropped %d)", index, events.dropped)
		}
	}
}
