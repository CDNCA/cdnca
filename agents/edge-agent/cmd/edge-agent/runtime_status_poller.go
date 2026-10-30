package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
)

// runtimeStatusInterval matches the OpenResty engines' one-second windows.
const (
	runtimeStatusInterval = time.Second
	runtimeStatusMaxBytes = 4 << 20
)

// Runtime status endpoints of the node skeleton's loopback health server
// (edgeskeleton writeHealthServer), under the configured health URL:
const (
	// ccAutoSwitchStatusSuffix: every CC site's auto switch state (FX65).
	ccAutoSwitchStatusSuffix = "/cc-auto-switch"
	// ccKernelBansSuffix drains the CC engine's client bans:
	// one "<tenant scope>|<site>|<client>|<until epoch>" per line.
	ccKernelBansSuffix = "/cc-kernel-bans"
	// ccStatsSuffix drains the CC engine's rule statistics frames:
	// one JSON frame per line, then {"dropped":n} if any.
	ccStatsSuffix = "/cc-stats"
	// securityBansSuffix: POST applies the ban list library's snapshot, GET
	// drains the WAF kernel ban queue (cdnca_banlist).
	securityBansSuffix = "/security-bans"
)

var errRuntimeStatusAbsent = errors.New("runtime status endpoint is absent")

type ccAutoSwitchNotifier interface {
	NotifyCCAutoSwitch(context.Context, gatewayclient.CCAutoSwitchEvent) error
}

// runtimeStatusPoller reads the node skeleton's loopback status endpoints
// once a second: every CC auto switch engagement is reported once to the
// control plane for its notification (FX65), CC and WAF bans are raised to
// the kernel, the CC rule statistics are summed and the firewall action
// escalation is mirrored into nftables (FX45).
type runtimeStatusPoller struct {
	healthURL string
	client    *http.Client
	notifier  ccAutoSwitchNotifier
	nodeID    string
	// engaged is each engaged site's engage second already reported.
	engaged map[string]int64
	// ccBans raises CC temporary bans to the kernel (nil: off).
	ccBans *ccKernelBans
	// ccStats sums the CC rule statistics for the upstream (nil: off).
	ccStats *ccStats
	// siteTenant maps a site to its running tenant scope (WAF kernel bans).
	siteTenant   func(siteID string) string
	securityBans *securityBanRuntime
	// firewallActions mirrors the FX45 escalation into nftables (nil: off).
	firewallActions *firewallActionMirror
	// siteDrop lifts expired level D sites and follows site changes (nil: off).
	siteDrop *siteDropRuntime
	// ready reports whether the node runtime was applied once (nil: always);
	// before that OpenResty is not running by design and nothing is polled.
	ready func() bool
	wait  func(context.Context, time.Duration) error
}

// withReady polls only once ready reports the runtime applied (first Apply).
func (poller *runtimeStatusPoller) withReady(ready func() bool) *runtimeStatusPoller {
	if poller != nil {
		poller.ready = ready
	}
	return poller
}

// withSiteDrop refreshes the site drop plan every poll (esc-node §2).
func (poller *runtimeStatusPoller) withSiteDrop(siteDrop *siteDropRuntime) *runtimeStatusPoller {
	if poller != nil {
		poller.siteDrop = siteDrop
	}
	return poller
}

func newRuntimeStatusPoller(healthURL string, timeout time.Duration) *runtimeStatusPoller {
	if healthURL == "" {
		return nil
	}
	return &runtimeStatusPoller{
		healthURL: healthURL, wait: waitFirewallExpiryInterval, engaged: map[string]int64{},
		client: &http.Client{
			Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout}).DialContext, ResponseHeaderTimeout: timeout},
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (poller *runtimeStatusPoller) Run(ctx context.Context) error {
	for {
		poller.pollOnce(ctx)
		if err := poller.wait(ctx, runtimeStatusInterval); err != nil {
			return err
		}
	}
}

// withCCAutoSwitchNotifier reports this node's CC auto switch engagements
// through notifier (the node monitoring carrier).
func (poller *runtimeStatusPoller) withCCAutoSwitchNotifier(nodeID string, notifier ccAutoSwitchNotifier) *runtimeStatusPoller {
	if poller != nil && notifier != nil && nodeID != "" {
		poller.nodeID, poller.notifier = nodeID, notifier
	}
	return poller
}

func (poller *runtimeStatusPoller) pollOnce(ctx context.Context) {
	if poller.ready != nil && !poller.ready() {
		return
	}
	poller.pollCCAutoSwitch(ctx)
	poller.pollCCKernelBans(ctx)
	poller.pollCCStats(ctx)
	poller.securityBans.reapply(ctx)
	poller.pollFirewallActions(ctx)
	poller.siteDrop.refresh(ctx)
}

const ccAutoSwitchStatusSchema = "cdnca.edge.cc-auto-switch/v1"

type ccAutoSwitchSiteStatus struct {
	TenantScopeID  string `json:"tenant_scope_id"`
	SiteID         string `json:"site_id"`
	PolicyID       string `json:"policy_id"`
	PolicyVersion  uint64 `json:"policy_version"`
	Active         bool   `json:"active"`
	Since          int64  `json:"since"`
	TriggerQPS     uint64 `json:"trigger_qps"`
	Trigger5xx     uint64 `json:"trigger_5xx"`
	QPSTotal       uint64 `json:"qps_total"`
	QPS5xx         uint64 `json:"qps_5xx"`
	RecoverSeconds uint64 `json:"recover_seconds"`
}

// pollCCAutoSwitch reports each engagement once: an engaged site whose engage
// second (since) was not reported yet. A site that recovered or left the
// runtime is forgotten, so its next engagement is reported again.
func (poller *runtimeStatusPoller) pollCCAutoSwitch(ctx context.Context) {
	if poller.notifier == nil {
		return
	}
	body, err := poller.get(ctx, ccAutoSwitchStatusSuffix)
	if errors.Is(err, errRuntimeStatusAbsent) {
		clear(poller.engaged)
		return
	}
	if err != nil {
		slog.Warn("CC auto switch status unavailable", "error", err)
		return
	}
	var status struct {
		SchemaVersion string          `json:"schema_version"`
		Sites         json.RawMessage `json:"sites"`
	}
	var sites []ccAutoSwitchSiteStatus
	if json.Unmarshal(body, &status) != nil || status.SchemaVersion != ccAutoSwitchStatusSchema ||
		string(status.Sites) != "{}" && json.Unmarshal(status.Sites, &sites) != nil {
		slog.Warn("CC auto switch status is invalid")
		return
	}
	engaged := make(map[string]int64, len(sites))
	for _, site := range sites {
		if !site.Active || site.Since <= 0 {
			continue
		}
		key := site.TenantScopeID + "/" + site.SiteID
		engaged[key] = site.Since
		if poller.engaged[key] == site.Since {
			continue
		}
		err := poller.notifier.NotifyCCAutoSwitch(ctx, gatewayclient.CCAutoSwitchEvent{
			NodeID: poller.nodeID, TenantScopeID: site.TenantScopeID, SiteID: site.SiteID,
			PolicyID: site.PolicyID, PolicyVersion: site.PolicyVersion, EngagedAt: time.Unix(site.Since, 0),
			TriggerQPS: site.TriggerQPS, Trigger5xx: site.Trigger5xx,
			QPSTotal: site.QPSTotal, QPS5xx: site.QPS5xx, RecoverSeconds: site.RecoverSeconds,
		})
		if err != nil {
			// Retried on the next poll.
			delete(engaged, key)
			slog.Warn("CC auto switch event not queued", "site_id", site.SiteID, "error", err)
		}
	}
	poller.engaged = engaged
}

// get reads one status endpoint; 404 means the current runtime renders none
// (no site of that kind on this node).
func (poller *runtimeStatusPoller) get(ctx context.Context, suffix string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, poller.healthURL+suffix, nil)
	if err != nil {
		return nil, err
	}
	response, err := poller.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, errRuntimeStatusAbsent
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("runtime status answered " + response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, runtimeStatusMaxBytes+1))
	if err != nil || len(body) > runtimeStatusMaxBytes {
		return nil, errors.New("runtime status response is invalid")
	}
	return body, nil
}
