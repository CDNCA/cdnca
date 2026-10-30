package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// FX45 firewall action escalation under dynamic routing: the OpenResty
// engine counts each site's blocked requests per second and decides engage
// and recovery; once a second the agent posts the running sites' policy
// objects to <health>/firewall-action (cdnca_security.firewall_action_status)
// and mirrors the answered state into nftables, one engine per site.
const (
	firewallActionStatusSuffix = "/firewall-action"
	firewallActionStatusSchema = "cdnca.edge.firewall-action-status/v1"
)

type firewallActionSite struct {
	SiteID string `json:"site_id"`
	SHA256 string `json:"sha256"`
}

type firewallActionSiteStatus struct {
	TenantID      string `json:"tenant_id"`
	SiteID        string `json:"site_id"`
	PolicyID      string `json:"policy_id"`
	PolicyVersion uint64 `json:"policy_version"`
	Active        bool   `json:"active"`
}

type firewallActionMirror struct {
	fw firewall.ScopedFirewall
	// owned reports whether a tenant owns the node; nil: every tenant does
	// (tests). Elsewhere the escalation stays in OpenResty (A08): its
	// nftables block is a host-wide ANY deny.
	owned   func(string) bool
	sites   func() []edgesite.Site
	object  func(digest string) ([]byte, error)
	engines map[string]*firewallActionEngine // site ID ->
}

type firewallActionEngine struct {
	digest string
	engine *firewall.ActionEngine
}

func newFirewallActionMirror(fw firewall.ScopedFirewall, sites func() []edgesite.Site, object func(string) ([]byte, error)) *firewallActionMirror {
	if fw == nil || sites == nil || object == nil {
		return nil
	}
	return &firewallActionMirror{fw: fw, sites: sites, object: object, engines: map[string]*firewallActionEngine{}}
}

// withFirewallActions mirrors the firewall action escalation (nil: off).
func (poller *runtimeStatusPoller) withFirewallActions(mirror *firewallActionMirror) *runtimeStatusPoller {
	if poller != nil && mirror != nil {
		poller.firewallActions = mirror
	}
	return poller
}

// sync makes the engines follow the running sites: a site with a new policy
// object gets a new engine (its scope version and engaged state read back
// from nftables), a site that left the runtime or lost its policy has its
// engagement withdrawn. It returns what to post.
func (mirror *firewallActionMirror) sync(ctx context.Context) []firewallActionSite {
	running := map[string]string{}
	for _, site := range mirror.sites() {
		if mirror.owned != nil && !mirror.owned(site.ConfigurationScopeID) {
			continue
		}
		if ref := site.Security.FirewallAction; ref != nil && ref.SHA256 != "" {
			running[site.SiteID] = ref.SHA256
		}
	}
	for siteID, current := range mirror.engines {
		if running[siteID] == current.digest {
			continue
		}
		if _, err := current.engine.Withdraw(ctx); err != nil {
			slog.Warn("firewall action withdraw failed", "site_id", siteID, "error", err)
			continue // retried on the next poll
		}
		delete(mirror.engines, siteID)
	}
	posted := make([]firewallActionSite, 0, len(running))
	for siteID, digest := range running {
		if _, ok := mirror.engines[siteID]; !ok {
			content, err := mirror.object(digest)
			if err != nil {
				slog.Warn("firewall action policy object unavailable", "site_id", siteID, "error", err)
				continue
			}
			engine, err := firewall.NewRuntimeActionEngine(ctx, mirror.fw, content)
			if err != nil {
				slog.Warn("firewall action policy rejected", "site_id", siteID, "error", err)
				continue
			}
			mirror.engines[siteID] = &firewallActionEngine{digest: digest, engine: engine}
		}
		posted = append(posted, firewallActionSite{SiteID: siteID, SHA256: digest})
	}
	sort.Slice(posted, func(i, j int) bool { return posted[i].SiteID < posted[j].SiteID })
	return posted
}

// apply mirrors each reported site's state; a site the runtime left out (its
// object did not load) keeps its nftables state.
func (mirror *firewallActionMirror) apply(ctx context.Context, sites []firewallActionSiteStatus) {
	for _, site := range sites {
		current := mirror.engines[site.SiteID]
		if current == nil {
			continue
		}
		changed, err := current.engine.Mirror(ctx, firewall.ActionRuntimeState{TenantID: site.TenantID, SiteID: site.SiteID,
			PolicyID: site.PolicyID, PolicyVersion: site.PolicyVersion, Active: site.Active})
		if err != nil {
			slog.Warn("firewall action nftables mirror failed", "site_id", site.SiteID, "error", err)
		} else if changed {
			slog.Info("firewall action nftables mirrored", "site_id", site.SiteID, "active", site.Active)
		}
	}
}

func (poller *runtimeStatusPoller) pollFirewallActions(ctx context.Context) {
	mirror := poller.firewallActions
	if mirror == nil {
		return
	}
	posted := mirror.sync(ctx)
	if len(posted) == 0 {
		return
	}
	body, err := poller.post(ctx, firewallActionStatusSuffix, posted)
	if err != nil {
		if !errors.Is(err, errRuntimeStatusAbsent) {
			slog.Warn("firewall action status unavailable", "error", err)
		}
		return
	}
	var status struct {
		SchemaVersion string          `json:"schema_version"`
		ObservedAt    int64           `json:"observed_at"`
		Sites         json.RawMessage `json:"sites"`
	}
	var sites []firewallActionSiteStatus
	if json.Unmarshal(body, &status) != nil || status.SchemaVersion != firewallActionStatusSchema || status.ObservedAt <= 0 ||
		string(bytes.TrimSpace(status.Sites)) != "{}" && json.Unmarshal(status.Sites, &sites) != nil {
		slog.Warn("firewall action status is invalid")
		return
	}
	mirror.apply(ctx, sites)
}

// post sends a JSON body to one status endpoint (404: the runtime renders
// none).
func (poller *runtimeStatusPoller) post(ctx context.Context, suffix string, value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, poller.healthURL+suffix, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
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
