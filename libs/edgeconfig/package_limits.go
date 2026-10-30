package edgeconfig

import (
	"fmt"
	"sort"
	"strings"
)

// PackageConnectionLimit shares the budgets of one subscription across every
// listener and domain it has on an edge node. It is never keyed by client IP.
// Connections is the concurrent request budget (并发请求数: requests in
// flight, HTTP/2 and HTTP/3 streams each count; -1 unlimited, 0 refuses).
type PackageConnectionLimit struct {
	SubscriptionID string `json:"subscription_id"`
	Connections    int64  `json:"connections"`
	// BandwidthBPS caps the subscription's outbound bandwidth on this node
	// (bit/s; 0 or absent: unlimited). The node splits it evenly between the
	// subscription's responses in flight (PackageBandwidthDirective).
	BandwidthBPS int64 `json:"bandwidth_bps,omitempty"`
	// ADR 0012 §6.2 market supply limits, this node's share (0 or absent:
	// unlimited); any of them requires SUBSCRIPTION_LIMITS v1
	// (SubscriptionLimitsUsed). MaxConnections: concurrent client TCP
	// connections (HTTP/3 has none); NewPerSecond: new TCP connections per
	// second; QPS: requests per second; Stopped: every request 503.
	MaxConnections int64 `json:"max_connections,omitempty"`
	NewPerSecond   int64 `json:"new_per_second,omitempty"`
	QPS            int64 `json:"qps,omitempty"`
	Stopped        bool  `json:"stopped,omitempty"`
}

// MaxPackageBandwidthBPS is the package catalog's largest bandwidth limit.
const MaxPackageBandwidthBPS = int64(1_000_000_000_000_000)

// Bounds of the market supply limits on one node (libs/marketproto/spec
// caps: connections and QPS 10^9, new connections 10^8).
const (
	MaxSubscriptionConnections  = int64(1_000_000_000)
	MaxSubscriptionNewPerSecond = int64(100_000_000)
	MaxSubscriptionQPS          = int64(1_000_000_000)
)

// SubscriptionLimitsCapability / SubscriptionLimitsAPIVersion: the site
// runtime document capability of CAPABILITY_NAME_SUBSCRIPTION_LIMITS.
const (
	SubscriptionLimitsCapability        = "subscription_limits"
	SubscriptionLimitsAPIVersion uint32 = 1
)

func (limit PackageConnectionLimit) Validate() error {
	if !uuidPattern.MatchString(limit.SubscriptionID) || limit.Connections < -1 || limit.Connections > 65535 ||
		limit.BandwidthBPS < 0 || limit.BandwidthBPS > MaxPackageBandwidthBPS ||
		limit.MaxConnections < 0 || limit.MaxConnections > MaxSubscriptionConnections ||
		limit.NewPerSecond < 0 || limit.NewPerSecond > MaxSubscriptionNewPerSecond ||
		limit.QPS < 0 || limit.QPS > MaxSubscriptionQPS {
		return ErrInvalidConfig
	}
	return nil
}

// SubscriptionLimitsUsed: the limit carries a market supply limit (ADR 0012)
// only SUBSCRIPTION_LIMITS v1 nodes enforce.
func (limit PackageConnectionLimit) SubscriptionLimitsUsed() bool {
	return limit.MaxConnections > 0 || limit.NewPerSecond > 0 || limit.QPS > 0 || limit.Stopped
}

// L4SubscriptionLimitsV2 is a layer 4 stream's market supply limits (ADR
// 0012 §6.2), this node's share, shared by every stream of the subscription
// on the node; 0 unlimited. MaxConnections: concurrent sessions;
// NewPerSecond: new sessions per second; BandwidthBPS: download rate split
// between the subscription's sessions; Stopped: every session closed.
// Requires SUBSCRIPTION_LIMITS v1.
type L4SubscriptionLimitsV2 struct {
	SubscriptionID string `json:"subscription_id"`
	MaxConnections int64  `json:"max_connections,omitempty"`
	NewPerSecond   int64  `json:"new_per_second,omitempty"`
	BandwidthBPS   int64  `json:"bandwidth_bps,omitempty"`
	Stopped        bool   `json:"stopped,omitempty"`
}

// ValidL4SubscriptionLimits accepts an unset limit or one within bounds that
// limits something.
func ValidL4SubscriptionLimits(value *L4SubscriptionLimitsV2) bool {
	return value == nil || uuidPattern.MatchString(value.SubscriptionID) &&
		value.MaxConnections >= 0 && value.MaxConnections <= MaxSubscriptionConnections &&
		value.NewPerSecond >= 0 && value.NewPerSecond <= MaxSubscriptionNewPerSecond &&
		value.BandwidthBPS >= 0 && value.BandwidthBPS <= MaxPackageBandwidthBPS &&
		(value.MaxConnections > 0 || value.NewPerSecond > 0 || value.BandwidthBPS > 0 || value.Stopped)
}

// PackageBandwidthDict is the shared dictionary holding, per subscription,
// the number of its responses in flight on the node.
const PackageBandwidthDict = "cdnca_package_bandwidth"

// PackageBandwidthHTTP is the http{} level part of package bandwidth limits:
// the in-flight counter dictionary, when any limit has a bandwidth.
func PackageBandwidthHTTP(limits []PackageConnectionLimit) string {
	for _, limit := range limits {
		if limit.BandwidthBPS > 0 {
			return "  lua_shared_dict " + PackageBandwidthDict + " 1m;\n"
		}
	}
	return ""
}

// PackageBandwidthDirective is the server{} part of a subscription's
// bandwidth limit: the server rewrite phase counts the request as in flight
// and sets its send rate to the budget divided by the subscription's
// responses in flight (rounded down, at least 1 byte/s); the log phase
// (PackageBandwidthLogLua) uncounts it. A response keeps the rate it started
// with, so the node total can exceed the budget briefly while new responses
// start; it converges as responses finish. The counter key expires an hour
// after it is created, so a count a crashed worker never released heals.
// An internal redirect re-runs the server rewrite phase but keeps the
// request's variables: a request whose $cdnca_package_rate is set already
// counts once.
func PackageBandwidthDirective(limit PackageConnectionLimit) (string, error) {
	if err := limit.Validate(); err != nil {
		return "", err
	}
	if limit.BandwidthBPS == 0 {
		return "", nil
	}
	bytesPerSecond := max(limit.BandwidthBPS/8, 1)
	return fmt.Sprintf(`    set_by_lua_block $cdnca_package_rate {
      local dict, key = ngx.shared[%[1]q], %[2]q
      local counted = ngx.var.cdnca_package_rate
      if counted ~= nil and counted ~= "" then return counted end
      local active = dict:incr(key, 1, 0, 3600) or 1
      return math.max(math.floor(%[3]d / math.max(active, 1)), 1)
    }
    limit_rate $cdnca_package_rate;
`, PackageBandwidthDict, limit.SubscriptionID, bytesPerSecond), nil
}

// PackageBandwidthLogLua uncounts the request (PackageBandwidthDirective) in
// the server's log phase; "" without a bandwidth limit.
func PackageBandwidthLogLua(limit PackageConnectionLimit) string {
	if limit.BandwidthBPS == 0 || limit.Validate() != nil {
		return ""
	}
	return fmt.Sprintf(`if (ngx.var.cdnca_package_rate or "") ~= "" then
        local dict, key = ngx.shared[%q], %q
        local active = dict:incr(key, -1)
        if active and active < 0 then dict:set(key, 0, 3600) end
      end
`, PackageBandwidthDict, limit.SubscriptionID)
}

func PackageConnectionZones(limits []PackageConnectionLimit) (string, error) {
	byID := make(map[string]int64, len(limits))
	for _, limit := range limits {
		if err := limit.Validate(); err != nil {
			return "", err
		}
		if previous, exists := byID[limit.SubscriptionID]; exists && previous != limit.Connections {
			return "", ErrInvalidConfig
		}
		byID[limit.SubscriptionID] = limit.Connections
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var output strings.Builder
	for _, id := range ids {
		if byID[id] > 0 {
			fmt.Fprintf(&output, "  limit_conn_zone %q zone=%s:64k;\n", id, packageConnectionZone(id))
		}
	}
	return output.String(), nil
}

func PackageConnectionDirective(limit PackageConnectionLimit) (string, error) {
	if err := limit.Validate(); err != nil {
		return "", err
	}
	if limit.Connections == -1 {
		return "", nil
	}
	if limit.Connections == 0 {
		return "    return 503;\n", nil
	}
	return fmt.Sprintf("    limit_conn %s %d;\n    limit_conn_status 503;\n", packageConnectionZone(limit.SubscriptionID), limit.Connections), nil
}

func packageConnectionZone(subscriptionID string) string {
	return "cdnca_pkg_" + strings.ReplaceAll(subscriptionID, "-", "")
}

func sitePackageConnections(sites []Site) []PackageConnectionLimit {
	var limits []PackageConnectionLimit
	for _, site := range sites {
		if site.PackageConnections != nil {
			limits = append(limits, PackageConnectionLimit{SubscriptionID: site.PackageSubscriptionID, Connections: *site.PackageConnections})
		}
	}
	return limits
}
