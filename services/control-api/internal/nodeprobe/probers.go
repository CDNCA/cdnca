package nodeprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscustomhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/marketprobe"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Target is one endpoint to probe.
type Target struct {
	Key      string // stable id of the endpoint in this round
	Address  netip.Addr
	Port     uint16
	Protocol string // tcp | http
}

// ControllerProber probes from the control plane. Only public unicast
// addresses are dialled (checked again at dial time), redirects are not
// followed and at most 1 KiB of a response is read. tcp: a completed
// connect; http: plain HTTP GET of the market probe path with any answer
// below 500 (the edge default server answers it 204, other paths 421). On 443
// an edge refuses an SNI-less handshake, so http there is probed as tcp.
// ping is probed as tcp (no raw sockets in control-api).
type ControllerProber struct {
	client  *http.Client
	dialer  *net.Dialer
	blocked func(netip.Addr) bool
}

func NewControllerProber(blocked func(netip.Addr) bool) *ControllerProber {
	if blocked == nil {
		blocked = dnscustomhttp.Blocked
	}
	prober := &ControllerProber{blocked: blocked}
	prober.dialer = &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errBlocked
		}
		parsed, err := netip.ParseAddr(host)
		if err != nil || blocked(parsed) {
			return errBlocked
		}
		return nil
	}}
	transport := &http.Transport{Proxy: nil, DialContext: prober.dialer.DialContext, DisableKeepAlives: true,
		MaxResponseHeaderBytes: 8 << 10,
		// The probe checks reachability of the edge, not its certificate for
		// a bare IP (no SNI name to verify against).
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec
	prober.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return prober
}

var errBlocked = errors.New("node probe: address not allowed")

// Probe returns ok and whether it was a vote (false when the target is not
// a public address and was not probed).
func (prober *ControllerProber) Probe(parent context.Context, target Target, timeout time.Duration) (ok, voted bool) {
	if prober.blocked(target.Address) || parent.Err() != nil {
		return false, false
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	address := netip.AddrPortFrom(target.Address, target.Port).String()
	if target.Protocol != "http" || target.Port == 443 {
		connection, err := prober.dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			// Shutting down or a refused address: not a vote.
			return false, !errors.Is(err, errBlocked) && parent.Err() == nil
		}
		_ = connection.Close()
		return true, true
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+contract.Path, nil)
	if err != nil {
		return false, false
	}
	request.Header.Set("User-Agent", "cdnca-control-api/node-probe")
	response, err := prober.client.Do(request)
	if err != nil {
		return false, !errors.Is(err, errBlocked) && parent.Err() == nil
	}
	_, _ = io.CopyN(io.Discard, response.Body, 1<<10)
	_ = response.Body.Close()
	return response.StatusCode < http.StatusInternalServerError, true
}

// PeerProber asks a peer node to probe targets (MARKET_PROBE command over
// the gateway). The Agent probes literal public addresses on ports 80/443
// only, with one GET of the market probe path (an edge answers it 204).
type PeerProber struct {
	requester marketprobe.Requester
	now       func() time.Time
}

func NewPeerProber(requester marketprobe.Requester, now func() time.Time) *PeerProber {
	if now == nil {
		now = time.Now
	}
	return &PeerProber{requester: requester, now: now}
}

// PeerProbePort is the port peers probe: the Agent's executor dials 80/443
// only, and an edge rejects an SNI-less TLS handshake on 443 (the default
// server), so the plain-HTTP default server on 80 (probe path answered 204)
// is the node's reachability signal.
const PeerProbePort = 80

// PeerAnswer is a peer's answer for one target.
type PeerAnswer struct {
	OK        bool
	LatencyMS int
}

// Probe sends one command to nodeID; the result maps each target key to the
// answer. Skipped and missing targets are absent (not votes).
func (prober *PeerProber) Probe(ctx context.Context, nodeID string, targets []Target, timeout time.Duration) map[string]PeerAnswer {
	if prober == nil || prober.requester == nil || len(targets) == 0 {
		return nil
	}
	if len(targets) > contract.MaxTargets {
		targets = targets[:contract.MaxTargets]
	}
	timeoutMillis := max(contract.MinTimeoutMillis, min(contract.MaxTimeoutMillis, int(timeout.Milliseconds())))
	expires := prober.now().Add(time.Duration(timeoutMillis)*time.Millisecond + 5*time.Second)
	commandTargets := make([]*agentv1.MarketProbeTarget, len(targets))
	for index, target := range targets {
		commandTargets[index] = &agentv1.MarketProbeTarget{TaskId: "np-" + strconv.Itoa(index),
			Ip: target.Address.String(), Port: uint32(target.Port)}
	}
	command := &agentv1.MarketProbeCommand{
		Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(),
			OccurredTime: timestamppb.New(prober.now())},
		NodeId: nodeID, Targets: commandTargets, TimeoutMillis: uint32(timeoutMillis), ExpireTime: timestamppb.New(expires),
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	reply, err := prober.requester.Request(ctx, nodeID, payload)
	if err != nil || len(reply) == 0 {
		return nil
	}
	var result agentv1.MarketProbeResult
	if proto.Unmarshal(reply, &result) != nil || result.NodeId != nodeID ||
		result.CommandEventId != command.Event.EventId || len(result.Results) != len(targets) {
		return nil
	}
	out := make(map[string]PeerAnswer, len(targets))
	for index, item := range result.Results {
		if item.GetTaskId() != commandTargets[index].TaskId {
			return nil
		}
		switch item.Outcome {
		case agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK:
			out[targets[index].Key] = PeerAnswer{OK: true, LatencyMS: int(item.GetLatencyMillis())}
		case agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED:
			out[targets[index].Key] = PeerAnswer{}
		}
	}
	return out
}
