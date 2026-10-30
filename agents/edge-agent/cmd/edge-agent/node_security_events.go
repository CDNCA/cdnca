package main

import (
	"net/netip"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
)

// nodeSecurityEvents turns node-level security events that belong to no
// tenant or site (F4: DDoS empty connection bans) into node_event reports on
// the AUTO_DEFENSE upstream. Sending never blocks: a full queue drops (the
// agent log keeps the event). Seq is the Unix millisecond, raised past the
// previous one, so it keeps growing across restarts (ingest is idempotent
// on node + seq).
type nodeSecurityEvents struct {
	nodeID string
	now    func() time.Time
	out    chan []byte

	mu      sync.Mutex
	lastSeq uint64
	dropped uint64
}

const nodeSecurityEventQueue = 256

func newNodeSecurityEvents(nodeID string, now func() time.Time) *nodeSecurityEvents {
	return &nodeSecurityEvents{nodeID: nodeID, now: now, out: make(chan []byte, nodeSecurityEventQueue)}
}

// EmptyConnectionBan reports one DDoS empty connection ban.
func (events *nodeSecurityEvents) EmptyConnectionBan(client netip.Addr, count int, ban time.Duration) {
	events.report(autodefense.NodeEvent{Source: "ddos", Kind: "empty_connection_ban", Client: client.Unmap().String(),
		Count: int64(count), DurationSeconds: int64(ban / time.Second), Level: autodefense.LevelKernel, Reason: "empty_connections"})
}

// KernelBan reports one ban found by polling (no callback in the kernel):
// source ddos kind rate_ban (inet cdnca_ddos rate rules) or source l4guard
// kind kernel_ban (L4 guard rule bans). An invalid client is the summary of
// count bans beyond the step budget (no client, no duration).
func (events *nodeSecurityEvents) KernelBan(source, kind, reason string, client netip.Addr, count int, remaining time.Duration) {
	event := autodefense.NodeEvent{Source: source, Kind: kind, Count: int64(count), Level: autodefense.LevelKernel, Reason: reason}
	if client.IsValid() {
		event.Client = client.Unmap().String()
		event.DurationSeconds = min(max(int64(remaining/time.Second), 0), autodefense.MaxMitigationSeconds)
	}
	events.report(event)
}

// XDPFallback reports the XDP filter falling back to nftables at run time
// (source xdp kind fallback, reason the xdp Reason* code); XDPReattached its
// successful reattach (kind reattached, reason the mode). One event each per
// transition (xdpWatch).
func (events *nodeSecurityEvents) XDPFallback(reason string) {
	if reason == "" {
		reason = "unknown"
	}
	events.report(autodefense.NodeEvent{Source: "xdp", Kind: "fallback", Count: 1, Level: autodefense.LevelKernel, Reason: reason})
}

func (events *nodeSecurityEvents) XDPReattached(mode string) {
	events.report(autodefense.NodeEvent{Source: "xdp", Kind: "reattached", Count: 1, Level: autodefense.LevelXDP, Reason: mode})
}

func (events *nodeSecurityEvents) report(event autodefense.NodeEvent) {
	if events == nil {
		return
	}
	events.mu.Lock()
	defer events.mu.Unlock()
	now := events.now()
	seq := max(events.lastSeq+1, uint64(now.UnixMilli()))
	encoded, err := autodefense.EncodeReport(autodefense.Report{Schema: autodefense.ReportSchema, Kind: autodefense.ReportNodeEvent,
		NodeID: events.nodeID, Seq: seq, At: now.Unix(), NodeEvent: &event})
	if err != nil {
		events.dropped++
		return
	}
	events.lastSeq = seq
	select {
	case events.out <- encoded:
	default:
		events.dropped++
	}
}

// Reports is the queue the AUTO_DEFENSE session drains.
func (events *nodeSecurityEvents) Reports() <-chan []byte {
	if events == nil {
		return nil
	}
	return events.out
}

// mergeReports forwards both channels (either may be nil) into one; the
// forwarding goroutine lives as long as the agent.
func mergeReports(first, second <-chan []byte) <-chan []byte {
	switch {
	case first == nil:
		return second
	case second == nil:
		return first
	}
	out := make(chan []byte, nodeSecurityEventQueue)
	go func() {
		for first != nil || second != nil {
			var report []byte
			var ok bool
			select {
			case report, ok = <-first:
				if !ok {
					first = nil
					continue
				}
			case report, ok = <-second:
				if !ok {
					second = nil
					continue
				}
			}
			select {
			case out <- report:
			default: // the session is not draining: drop (display only)
			}
		}
		close(out)
	}()
	return out
}
