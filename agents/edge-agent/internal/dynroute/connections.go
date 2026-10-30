package dynroute

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dyntelemetry"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgeskeleton"
)

// SiteConnection is one site and public port's requests in flight on the
// shared servers (cdnca_limits.site, D13-b2): the independent connections
// metric v7 read from a port's listener when only that site used it.
type SiteConnection struct {
	SiteID      string
	Port        uint16
	Connections uint64
}

// SiteConnections reads the counters over the control socket; Evidence is
// the digest of the answer as read (what the reading was based on).
func (runtime *Runtime) SiteConnections(ctx context.Context) ([]SiteConnection, [32]byte, error) {
	raw, err := runtime.controlGet(ctx, edgeskeleton.ConnectionsLocation)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("site connections: %w", err)
	}
	return parseSiteConnections(raw)
}

// controlGet reads a location of the workers' control socket.
func (runtime *Runtime) controlGet(ctx context.Context, location string) ([]byte, error) {
	socket := filepath.Join(runtime.config.StateRoot, edgeskeleton.ControlSocket)
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		}}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://cdnca"+location, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d %v", response.StatusCode, err)
	}
	return raw, nil
}

func parseSiteConnections(raw []byte) ([]SiteConnection, [32]byte, error) {
	var counts map[string]uint64
	if err := json.Unmarshal(raw, &counts); err != nil {
		// cjson encodes an empty table as {} and never as []
		return nil, [32]byte{}, fmt.Errorf("site connections: %w", err)
	}
	result := make([]SiteConnection, 0, len(counts))
	for key, count := range counts {
		siteID, portText, ok := strings.Cut(key, "|")
		port, err := strconv.ParseUint(portText, 10, 16)
		if !ok || err != nil || port == 0 || siteID == "" {
			return nil, [32]byte{}, fmt.Errorf("site connections: key %q", key)
		}
		result = append(result, SiteConnection{SiteID: siteID, Port: uint16(port), Connections: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].SiteID < result[j].SiteID || result[i].SiteID == result[j].SiteID && result[i].Port < result[j].Port
	})
	return result, sha256.Sum256(raw), nil
}

func scopeIdentities(input Input) map[string]scopeIdentity {
	if len(input.ScopeVersions) == 0 {
		return nil
	}
	result := make(map[string]scopeIdentity, len(input.ScopeVersions))
	for scope, version := range input.ScopeVersions {
		result[scope] = scopeIdentity{ConfigVersionID: version, InstallationID: input.Installations[scope]}
	}
	return result
}

// MetricSite is one active site listener the node reports independent
// connections metrics for: identity from the site object, the config
// version and installation of its scope.
type MetricSite struct {
	TenantID, SiteID, Domain, PackageSubscriptionID string
	ConfigVersionID, InstallationID                 string
	Port                                            uint16
}

// MetricSites are the active sites' listeners whose scope has a telemetry
// installation, ordered by (site, port).
func (runtime *Runtime) MetricSites() []MetricSite {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	var result []MetricSite
	for _, site := range runtime.sites {
		scope, ok := runtime.state.Scopes[site.ConfigurationScopeID]
		if !ok || scope.InstallationID == "" {
			continue
		}
		subscription := ""
		if site.Telemetry != nil {
			subscription = site.Telemetry.PackageSubscriptionID
		}
		seen := map[int]bool{}
		for _, listener := range site.Listeners {
			if seen[listener.Port] {
				continue
			}
			seen[listener.Port] = true
			result = append(result, MetricSite{TenantID: site.TenantID, SiteID: site.SiteID, Domain: site.Hosts.Primary,
				PackageSubscriptionID: subscription, ConfigVersionID: scope.ConfigVersionID, InstallationID: scope.InstallationID,
				Port: uint16(listener.Port)})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].SiteID < result[j].SiteID || result[i].SiteID == result[j].SiteID && result[i].Port < result[j].Port
	})
	return result
}

// SubscriptionMinuteSites are the sites the minutes can be bound to
// (MetricSites without the port).
func (runtime *Runtime) SubscriptionMinuteSites() []dyntelemetry.MinuteSite {
	var result []dyntelemetry.MinuteSite
	for _, site := range runtime.MetricSites() {
		result = append(result, dyntelemetry.MinuteSite{TenantID: site.TenantID, SiteID: site.SiteID,
			PackageSubscriptionID: site.PackageSubscriptionID, ConfigVersionID: site.ConfigVersionID, InstallationID: site.InstallationID})
	}
	return result
}

// SubscriptionMinutes takes the finished minutes over the control socket.
// Each minute is answered once: the workers delete what they hand out.
func (runtime *Runtime) SubscriptionMinutes(ctx context.Context) ([]dyntelemetry.NodeMinute, error) {
	raw, err := runtime.controlGet(ctx, edgeskeleton.SubscriptionMinutesLocation)
	if err != nil {
		return nil, fmt.Errorf("subscription minutes: %w", err)
	}
	return ParseSubscriptionMinutes(raw)
}

// ParseSubscriptionMinutes decodes GET /subscription-minutes.
func ParseSubscriptionMinutes(raw []byte) ([]dyntelemetry.NodeMinute, error) {
	var answer struct {
		Minutes []struct {
			Schema         string `json:"schema"`
			Minute         int64  `json:"minute"`
			SubscriptionID string `json:"subscription_id"`
			edgeconfig.SubscriptionMinuteCounters
		} `json:"minutes"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("subscription minutes: %w", err)
	}
	result := make([]dyntelemetry.NodeMinute, 0, len(answer.Minutes))
	for _, item := range answer.Minutes {
		if item.Schema != edgeconfig.SubscriptionMinuteNodeSchema || item.Minute <= 0 || item.Minute%60 != 0 ||
			item.SubscriptionID == "" || !item.SubscriptionMinuteCounters.Valid() {
			return nil, fmt.Errorf("subscription minutes: invalid record %q at %d", item.SubscriptionID, item.Minute)
		}
		result = append(result, dyntelemetry.NodeMinute{SubscriptionID: item.SubscriptionID, Minute: time.Unix(item.Minute, 0).UTC(),
			SubscriptionMinuteCounters: item.SubscriptionMinuteCounters})
	}
	return result, nil
}
