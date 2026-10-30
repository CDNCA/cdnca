package main

import (
	"context"
	"strings"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

// ddosProtectionCheckName is the deployment check carrying the node DDoS
// protection state with every terminal deployment (E1, PJ-E03/E04).
const ddosProtectionCheckName = "edge_ddos_protection"

// Reasons the node cannot run the DDoS protection table
// (NodeDDoSProtectionV1.reason).
const (
	ddosUnsupportedOS = "unsupported_os"
	ddosNFTMissing    = "nft_missing"
	ddosNFTUnusable   = "nft_unusable"
	ddosInitFailed    = "init_failed"
)

// ddosUnavailableReason is why the node runs no DDoS protection table, ""
// when it does: not Linux, no nft binary, an nft that fails its probe (the
// firewall runtime was not selected) or a table manager that did not start.
func ddosUnavailableReason(goos string, firewallReady bool, findBinary func(string) (string, error), managerErr error) (string, string) {
	switch {
	case goos != "linux":
		return ddosUnsupportedOS, "DDoS protection needs Linux nftables"
	case !firewallReady:
		if _, err := findBinary("nft"); err != nil {
			return ddosNFTMissing, "nft command not found: install nftables"
		}
		return ddosNFTUnusable, "nft is installed but its probe failed"
	case managerErr != nil:
		return ddosInitFailed, sanitizeDDoSDetail(managerErr.Error())
	default:
		return "", ""
	}
}

type ddosStatusSource interface {
	DDoSStatus() (dynroute.DDoSStatus, bool)
}

// ddosProtectionState is the node DDoS protection state now: unavailable
// (reason), else the last table application of the dynamic routing runtime
// (pending before the first).
func ddosProtectionState(reason, detail string, source ddosStatusSource) func(context.Context) *nodemonitoring.DDoSProtectionMetrics {
	return func(context.Context) *nodemonitoring.DDoSProtectionMetrics {
		if reason != "" {
			return &nodemonitoring.DDoSProtectionMetrics{State: "unavailable", Reason: reason, Detail: sanitizeDDoSDetail(detail)}
		}
		if source == nil {
			return &nodemonitoring.DDoSProtectionMetrics{State: "pending"}
		}
		status, ok := source.DDoSStatus()
		if !ok {
			return &nodemonitoring.DDoSProtectionMetrics{State: "pending"}
		}
		metrics := &nodemonitoring.DDoSProtectionMetrics{State: status.State}
		if status.State == dynroute.DDoSFailed {
			metrics.Detail = sanitizeDDoSDetail(status.Detail)
		}
		return metrics
	}
}

// ddosProtectionChecks reports the state with every terminal deployment: a
// table that failed to apply or a node that cannot run one is a failed
// check (the release itself stands).
func ddosProtectionChecks(state func(context.Context) *nodemonitoring.DDoSProtectionMetrics) func() []*agentv1.CheckResult {
	return func() []*agentv1.CheckResult {
		current := state(context.Background())
		summary := "DDoS protection " + current.State
		switch current.State {
		case "unavailable":
			summary = "DDoS protection unavailable (" + current.Reason + "): " + current.Detail
		case dynroute.DDoSFailed:
			summary = "DDoS protection not applied, previous table kept: " + current.Detail
		}
		ok := current.State != "unavailable" && current.State != dynroute.DDoSFailed
		return []*agentv1.CheckResult{{Name: ddosProtectionCheckName, Succeeded: ok,
			Summary: summary, LatencyDuration: durationpb.New(0)}}
	}
}

// sanitizeDDoSDetail: one line of at most 256 bytes (NodeDDoSProtectionV1).
func sanitizeDDoSDetail(value string) string {
	value = strings.Join(strings.FieldsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f || r == ' ' }), " ")
	if len(value) > 256 {
		value = strings.ToValidUTF8(value[:253], "") + "..."
	}
	return value
}
