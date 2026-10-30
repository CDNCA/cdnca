package main

import (
	"errors"
	"log/slog"
	"sync"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
)

// autoDefenseLocalRuntime is the node's automatic defense runtime (AD-05, agents/edge-agent/internal/autodefense).
// The node decides and mitigates on its own; the control plane snapshot only carries what the node cannot learn
// itself (module switches and licence, cross node signatures, whitelist, overlay locks). Apply receives one
// verified, assembled revision that is newer than AppliedRevision and must keep the previous state on error.
// AppliedRevision survives restarts (the runtime persists what it holds). Reports yields optional upstream
// summaries (cdnca.autodefense.report/v1 JSON); it is fed without blocking and may drop.
type autoDefenseLocalRuntime interface {
	Apply(snapshot autodefense.Snapshot) error
	AppliedRevision() uint64
	Reports() <-chan []byte
}

// autoDefenseReceiver implements gatewayclient.AutoDefenseRuntime: it verifies each part with the node's artifact
// trust (edge publication key, like S5 ban lists), keeps the revision order, collects the parts of one revision
// and hands the assembled snapshot to the local runtime. The receiver holds no defense state of its own.
type autoDefenseReceiver struct {
	nodeID  string
	trusted autodefense.TrustedKeyFunc
	runtime autoDefenseLocalRuntime

	// events: platform node security events (F4) sent on the same upstream.
	events *nodeSecurityEvents
	// reports: runtime reports merged with events (built once).
	reportsOnce sync.Once
	reports     <-chan []byte

	mu sync.Mutex
	// collecting: verified parts of the revision being assembled (at most MaxParts).
	collecting []autodefense.Snapshot
	// applied counts the revision in force, for receipts of a redelivered part.
	appliedCounts gatewayclient.AutoDefenseResult
	appliedRev    uint64
}

// newAutoDefenseReceiver returns nil without a node identity, or with neither a local runtime nor platform events.
// Without a local runtime (not a dynamic routing node) the Agent still declares AUTO_DEFENSE so platform node
// security events (F4: DDoS, L4 guard) travel upstream, and refuses every snapshot part with not_supported: the
// control plane reads that receipt as "the node does not run automatic defense". events (may be nil) are sent with
// the runtime's reports.
func newAutoDefenseReceiver(nodeID string, trusted autodefense.TrustedKeyFunc, runtime autoDefenseLocalRuntime,
	events *nodeSecurityEvents) *autoDefenseReceiver {
	if nodeID == "" || runtime != nil && trusted == nil || runtime == nil && events == nil {
		return nil
	}
	return &autoDefenseReceiver{nodeID: nodeID, trusted: trusted, runtime: runtime, events: events}
}

func refusedAutoDefense(code string) gatewayclient.AutoDefenseResult {
	return gatewayclient.AutoDefenseResult{ErrorCode: code}
}

// ApplyAutoDefense implements gatewayclient.AutoDefenseRuntime.
func (receiver *autoDefenseReceiver) ApplyAutoDefense(encoded []byte) gatewayclient.AutoDefenseResult {
	if receiver.runtime == nil {
		return refusedAutoDefense(autodefense.ErrorNotSupported)
	}
	if node, _, err := autodefense.Route(encoded); err != nil {
		return refusedAutoDefense(autodefense.ErrorInvalid)
	} else if node != receiver.nodeID {
		return refusedAutoDefense(autodefense.ErrorWrongNode)
	}
	part, err := autodefense.Open(encoded, receiver.nodeID, receiver.trusted)
	switch {
	case errors.Is(err, autodefense.ErrUntrusted):
		receiver.deliveryFailed()
		return refusedAutoDefense(autodefense.ErrorUntrusted)
	case err != nil:
		receiver.deliveryFailed()
		return refusedAutoDefense(autodefense.ErrorInvalid)
	}
	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	held := max(receiver.appliedRev, receiver.runtime.AppliedRevision())
	switch {
	case part.Revision < held:
		return refusedAutoDefense(autodefense.ErrorStale)
	case part.Revision == held:
		// A redelivered part of the revision in force (control-api republishes until it sees the receipt).
		if receiver.appliedRev == held {
			return receiver.appliedCounts
		}
		return gatewayclient.AutoDefenseResult{Applied: true}
	}
	if len(receiver.collecting) > 0 {
		switch current := receiver.collecting[0]; {
		case part.Revision < current.Revision:
			return refusedAutoDefense(autodefense.ErrorStale)
		case part.Revision > current.Revision || part.Parts != current.Parts:
			// A newer revision supersedes the one being assembled.
			receiver.collecting = nil
		}
	}
	for _, collected := range receiver.collecting {
		if collected.Part == part.Part {
			if collected.Signature != part.Signature {
				return refusedAutoDefense(autodefense.ErrorInvalid)
			}
			return refusedAutoDefense(autodefense.ErrorIncomplete)
		}
	}
	receiver.collecting = append(receiver.collecting, part)
	if uint32(len(receiver.collecting)) < part.Parts {
		return refusedAutoDefense(autodefense.ErrorIncomplete)
	}
	whole, err := autodefense.Assemble(receiver.collecting)
	receiver.collecting = nil
	if err != nil {
		receiver.deliveryFailed()
		return refusedAutoDefense(autodefense.ErrorInvalid)
	}
	if err := receiver.runtime.Apply(whole); err != nil {
		slog.Warn("auto defense snapshot not applied", "revision", whole.Revision, "error", err)
		receiver.deliveryFailed()
		return refusedAutoDefense(autodefense.ErrorRuntime)
	}
	result := gatewayclient.AutoDefenseResult{Applied: true, Sites: uint32(len(whole.Sites))}
	for _, site := range whole.Sites {
		result.Signatures += uint32(len(site.Signatures))
		result.Mitigations += uint32(len(site.Mitigations))
	}
	receiver.appliedRev, receiver.appliedCounts = whole.Revision, result
	slog.Info("auto defense snapshot applied", "revision", whole.Revision, "sites", result.Sites,
		"signatures", result.Signatures, "mitigations", result.Mitigations)
	return result
}

// deliveryFailed tells the runtime a snapshot failed verification, assembly or Apply (ADR §10.2 item 5: repeated
// failures open its breakers). A stale or redelivered part is not a failure.
func (receiver *autoDefenseReceiver) deliveryFailed() {
	if counter, ok := receiver.runtime.(interface{ DeliveryFailed() }); ok {
		counter.DeliveryFailed()
	}
}

// Reports implements gatewayclient.AutoDefenseRuntime.
func (receiver *autoDefenseReceiver) Reports() <-chan []byte {
	receiver.reportsOnce.Do(func() {
		var local <-chan []byte
		if receiver.runtime != nil {
			local = receiver.runtime.Reports()
		}
		receiver.reports = mergeReports(local, receiver.events.Reports())
	})
	return receiver.reports
}
