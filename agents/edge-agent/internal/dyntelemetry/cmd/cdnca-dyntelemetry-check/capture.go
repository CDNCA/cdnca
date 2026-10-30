package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/siteindex"
)

// checkCapture: a capture site (request header allowlist, GET /api) next to
// a plain site on one shared server. The capture site's lines are capture
// events with the attribution; they pass the event spool with the site
// object's capture identity.
func checkCapture(n *node) {
	ctx := context.Background()
	stopOrigin := startOrigin(originAddr, "o", nil, nil)
	defer stopOrigin()
	capture := attributionSite(1, 1)
	capture.Telemetry.Capture.Enabled = true
	capture.Telemetry.Capture.Revision = 7
	capture.Telemetry.Capture.EvidenceDigest = digest("capture-evidence")
	capture.Telemetry.Capture.Methods = []string{"GET"}
	capture.Telemetry.Capture.URIPrefixes = []string{"/api"}
	capture.Telemetry.Capture.RequestHeaderAllowlist = []string{"Authorization", "X-Trace"}
	capture.Telemetry.Capture.MaxValueBytes, capture.Telemetry.Capture.MaxBodyBytes, capture.Telemetry.Capture.MaxEventBytes = 4096, 65536, 1<<20
	plain := attributionSite(2, 1)
	// The plain site trusts 127.0.0.0/8 (the check's own address): its log
	// client_ip is the trusted chain's X-Real-IP.
	plain.Origin.TrustedProxyCIDRs = []string{"127.0.0.0/8"}
	n.versions = map[string]string{capture.ConfigurationScopeID: "0d12f000-0000-4000-8000-000000000001",
		plain.ConfigurationScopeID: "0d12f000-0000-4000-8000-000000000002"}
	if _, err := n.activator.Activate(ctx, []siteindex.Object{encode(capture), encode(plain)}); err != nil {
		check("capture-activate", false, "%v", err)
		return
	}
	headers := map[string]string{"X-Trace": "abc", "Authorization": "Bearer secret", "Traceparent": "cap-1"}
	send(portA, capture.Hosts.Primary, "GET", "/api/x", headers, "")
	headers["Traceparent"] = "cap-2"
	send(portA, capture.Hosts.Primary, "GET", "/other", headers, "")
	headers["Traceparent"] = "plain-1"
	headers["X-Real-IP"] = "203.0.113.9"
	send(portA, plain.Hosts.Primary, "GET", "/api/x", headers, "")
	// the capture site has no trusted proxy: a spoofed X-Real-IP is ignored
	headers["Traceparent"] = "cap-3"
	send(portA, capture.Hosts.Primary, "GET", "/api/y", headers, "")
	time.Sleep(300 * time.Millisecond)
	lines := n.lines("access")
	check("capture-lines", len(lines) == 4, "%d access lines", len(lines))
	sites := n.sites()
	byTrace := map[string]dyntelemetry.Result{}
	for _, line := range lines {
		result, err := dyntelemetry.Normalize(line, n.registry, sites, nodeID)
		if err != nil {
			check("capture-normalize", false, "%v\n%s", err, line)
			continue
		}
		byTrace[requestID(line)] = result
	}
	var first struct {
		RequestHeaders map[string]string `json:"request_headers"`
		Method         string            `json:"method"`
		Type           string            `json:"type"`
	}
	_ = json.Unmarshal(byTrace["cap-1"].Line, &first)
	check("capture-headers", first.Type == "access.v1" && first.RequestHeaders["X-Trace"] == "abc" &&
		first.RequestHeaders["Authorization"] == "[REDACTED]", "%s", byTrace["cap-1"].Line)
	var second struct {
		RequestHeaders map[string]string `json:"request_headers"`
	}
	_ = json.Unmarshal(byTrace["cap-2"].Line, &second)
	check("capture-outside-prefix", second.RequestHeaders == nil, "%s", byTrace["cap-2"].Line)
	identity := byTrace["cap-1"].Identity
	check("capture-identity", identity.CapturePolicyRevision == 7 && identity.CapturePolicyDigest == digest("capture-evidence") &&
		byTrace["plain-1"].Identity.CapturePolicyRevision == 0 && !byTrace["plain-1"].CapturePolicy.Enabled,
		"capture %+v plain %+v", identity, byTrace["plain-1"].Identity)
	var plainLine, spoofed struct {
		RequestHeaders map[string]string `json:"request_headers"`
		ClientIP       string            `json:"client_ip"`
	}
	_ = json.Unmarshal(byTrace["plain-1"].Line, &plainLine)
	_ = json.Unmarshal(byTrace["cap-3"].Line, &spoofed)
	check("client-ip-trusted-chain", plainLine.ClientIP == "203.0.113.9" && spoofed.ClientIP == "127.0.0.1",
		"trusted %q untrusted %q", plainLine.ClientIP, spoofed.ClientIP)
	check("capture-plain-site-untouched", plainLine.RequestHeaders == nil && strings.Contains(string(lines[2]), `"cdnca":{`), "%.200s", byTrace["plain-1"].Line)
	// fix-upstreamaddr: plain and capture lines carry the origin address
	// ($upstream_addr), the diagnostic upstream_result stays unset.
	var plainOrigin, captureOrigin struct {
		UpstreamAddr   *string `json:"upstream_addr"`
		UpstreamResult *string `json:"upstream_result"`
	}
	_ = json.Unmarshal(byTrace["plain-1"].Line, &plainOrigin)
	_ = json.Unmarshal(byTrace["cap-1"].Line, &captureOrigin)
	check("upstream-addr", plainOrigin.UpstreamAddr != nil && *plainOrigin.UpstreamAddr == originAddr &&
		captureOrigin.UpstreamAddr != nil && *captureOrigin.UpstreamAddr == originAddr &&
		plainOrigin.UpstreamResult == nil && captureOrigin.UpstreamResult == nil,
		"plain %s\n    capture %s", byTrace["plain-1"].Line, byTrace["cap-1"].Line)

	// Through the real tailer + event spool sink, as the Agent runs it.
	spool := &collect{}
	tailer, err := eventspool.NewTailer(eventspool.TailConfig{
		SourcePath: filepath.Join(n.shared, "telemetry", "dynroute", "access.jsonl"), StateDir: filepath.Join(n.prefix, "agent", "tail"),
		Identity: eventspool.TrustedIdentity{EnrollmentNodeID: nodeID}, MaxLineBytes: 1 << 20, MaxBatchEvents: 100, MaxQuarantineBytes: 1 << 20,
		Resolve: (&dyntelemetry.Resolver{Registry: n.registry, Sites: sites, NodeID: nodeID}).Resolve,
	})
	if err != nil {
		check("capture-tailer", false, "%v", err)
		return
	}
	_ = os.Chmod(filepath.Join(n.shared, "telemetry", "dynroute", "access.jsonl"), 0o600)
	result, err := tailer.TailOnce(ctx, spool)
	ok := err == nil && result.QuarantinedLines == 0 && len(spool.events) == 4
	for _, event := range spool.events {
		ok = ok && event.ConfigVersionID != "" && event.NodeID == nodeID
	}
	check("capture-event-spool", ok, "%+v %v events %d", result, err, len(spool.events))
}

type collect struct{ events []eventspool.Envelope }

func (c *collect) AppendBatch(_ context.Context, events []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	results := make([]eventspool.AppendResult, len(events))
	for index, event := range events {
		c.events = append(c.events, event)
		results[index] = eventspool.AppendResult{EventID: event.EventID, Sequence: uint64(len(c.events))}
	}
	return results, nil
}
