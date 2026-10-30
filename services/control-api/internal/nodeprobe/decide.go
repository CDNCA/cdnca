// Package nodeprobe probes node line endpoints from outside the node:
// from the controller itself and from
// peer nodes in other carrier/region monitoring groups. The Agent only
// probes 127.0.0.1, which misses a black-holed public IP, an upstream link
// failure or a firewall dropping outside traffic.
//
// Every round each endpoint gets one verdict (the
// mirror of the dnspup rule): it is unreachable only when the controller's
// probe fails and at least failure_ratio percent of the peer nodes that
// answered failed too. With two nodes that is the controller plus the one
// peer; without peer votes the controller decides alone, without a
// controller vote the peers do. Monitoring groups pick which peers are asked
// first (internal/nodeprobe.assignPeers), they do not split the vote. The
// verdict is recorded with nodescheduler.RecordProbe (consecutive thresholds
// and debounce of the line group's health policy), so line-group endpoint
// health and /decisions carry real data. A node whose every published
// endpoint is unhealthy gets the external_probe serving hold unless a fresh
// dnspup verdict exists (dnspup is authoritative then; the peer log stays as
// reference); the serving view already removes a node held by any source and
// fails open when nothing would be left. Every round with a failure, and one
// all-good round per LogEvery, lands in node_peer_probe_results (the
// availability log, source=peer).
package nodeprobe

import "github.com/cdnca/cdnca/services/control-api/internal/marketprobe"

// Monitoring groups (systemconfig monitor_groups).
const (
	GroupDomestic = "domestic"
	GroupTelecom  = "telecom"
	GroupUnicom   = "unicom"
	GroupMobile   = "mobile"
	GroupOverseas = "overseas"
)

// ControllerProberID is the controller's own vote; it stands for the domestic
// group (the controller runs in the operator's mainland network).
const ControllerProberID = "controller"

// ProberGroups are the monitoring groups a peer node votes in, from the
// region/carrier of its own published endpoint: mainland nodes are domestic
// plus their carrier (BGP: domestic only), nodes outside the mainland vote
// overseas.
func ProberGroups(region, carrier string) []string {
	regionCode, regionKnown := marketprobe.Region(region)
	if regionKnown && regionCode != "cn" {
		return []string{GroupOverseas}
	}
	groups := []string{GroupDomestic}
	if code, ok := marketprobe.Carrier(carrier); ok && code != "bgp" {
		groups = append(groups, code)
	}
	if !regionKnown && len(groups) == 1 {
		// No region and no carrier: nothing says where the node is.
		return nil
	}
	return groups
}

// Vote is one prober's result for one endpoint. Skipped probes (the prober
// refused or could not run it) are not votes.
type Vote struct {
	Prober string
	// Name and Address identify a peer in the log (empty for the controller).
	Name, Address string
	Groups        []string
	OK            bool
	LatencyMS     int
}

// Verdict of one endpoint in one round.
type Verdict struct {
	// Decided is false when nobody voted: the probe path is down (or nobody
	// could probe), which says nothing about the endpoint.
	Decided bool
	Healthy bool
	// Controller is the controller's vote (nil: not probed).
	Controller *bool
	// PeerFailed / PeerTotal count the peer votes.
	PeerFailed, PeerTotal int
}

// Failed / Total count every vote (controller included), for the log.
func (verdict Verdict) Failed() int {
	if verdict.Controller != nil && !*verdict.Controller {
		return verdict.PeerFailed + 1
	}
	return verdict.PeerFailed
}

func (verdict Verdict) Total() int {
	if verdict.Controller != nil {
		return verdict.PeerTotal + 1
	}
	return verdict.PeerTotal
}

// Decide applies the monitoring policy to one endpoint's votes: unhealthy
// when the controller failed (or did not vote) and at least failureRatio
// percent of the peers failed (or none voted); undecided without any vote.
// failureRatio is 1..100 (0: 50, the console default).
func Decide(votes []Vote, failureRatio int) Verdict {
	if failureRatio <= 0 || failureRatio > 100 {
		failureRatio = 50
	}
	var verdict Verdict
	for _, vote := range votes {
		if vote.Prober == ControllerProberID {
			ok := vote.OK
			verdict.Controller = &ok
			continue
		}
		verdict.PeerTotal++
		if !vote.OK {
			verdict.PeerFailed++
		}
	}
	verdict.Decided = verdict.Controller != nil || verdict.PeerTotal > 0
	controllerFailed := verdict.Controller == nil || !*verdict.Controller
	peersFailed := verdict.PeerTotal == 0 || verdict.PeerFailed*100 >= failureRatio*verdict.PeerTotal
	verdict.Healthy = verdict.Decided && !(controllerFailed && peersFailed)
	return verdict
}
