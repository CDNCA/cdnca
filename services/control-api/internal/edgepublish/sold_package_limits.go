package edgepublish

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type soldPackageLimits struct {
	subscriptionID uuid.UUID
	Connections    *int64 `json:"connections"`
	// BandwidthBPS is enforced on every node (ge-analytics): the node splits
	// it between the subscription's responses in flight. -1 / 0 / absent:
	// unlimited.
	BandwidthBPS *int64 `json:"bandwidth_bps"`
	WebSocket    *bool  `json:"websocket"`
	HTTP3        *bool  `json:"http3"`
	CustomCC     *bool  `json:"custom_cc"`
	WAF          *bool  `json:"waf"`
	// market is the node share of a market supply subscription (ADR 0012
	// §6.2, market_supply_limits); it replaces connections and bandwidth.
	market *edgeconfig.PackageConnectionLimit
}

func loadSoldPackageLimits(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (map[uuid.UUID]soldPackageLimits, error) {
	rows, err := tx.Query(ctx, `SELECT site.id,subscription.id,subscription.product_snapshot#>'{spec,limits}',
			market.node_requests,market.node_bandwidth_bps,market.node_connections,market.node_new_per_second,
			market.node_qps,market.node_stopped
		FROM sites site JOIN package_subscriptions subscription
		ON subscription.id=site.package_subscription_id AND subscription.tenant_scope_id=site.scope_id
		LEFT JOIN market_supply_limits market ON market.package_subscription_id=subscription.id
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL ORDER BY site.id`, scopeID)
	if err != nil {
		return nil, fmt.Errorf("%w: load sold package limits", ErrPersistence)
	}
	defer rows.Close()
	result := make(map[uuid.UUID]soldPackageLimits)
	for rows.Next() {
		var siteID, subscriptionID uuid.UUID
		var raw []byte
		var requests, bandwidth, connections, newPerSecond, qps *int64
		var stopped *bool
		if err := rows.Scan(&siteID, &subscriptionID, &raw, &requests, &bandwidth, &connections, &newPerSecond,
			&qps, &stopped); err != nil {
			return nil, fmt.Errorf("%w: scan sold package limits", ErrPersistence)
		}
		limits, err := decodeSoldPackageLimits(raw)
		if err != nil {
			return nil, err
		}
		limits.subscriptionID = subscriptionID
		if requests != nil {
			limits.market = &edgeconfig.PackageConnectionLimit{SubscriptionID: subscriptionID.String(),
				Connections: *requests, BandwidthBPS: *bandwidth, MaxConnections: *connections,
				NewPerSecond: *newPerSecond, QPS: *qps, Stopped: *stopped}
			if limits.market.Validate() != nil {
				return nil, ErrInvalidInput
			}
		}
		result[siteID] = limits
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("%w: iterate sold package limits", ErrPersistence)
	}
	return result, nil
}

func decodeSoldPackageLimits(raw []byte) (soldPackageLimits, error) {
	var limits soldPackageLimits
	if len(raw) == 0 {
		return limits, nil
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || keys == nil {
		return limits, ErrInvalidInput
	}
	for _, key := range []string{"connections", "bandwidth_bps", "websocket", "http3", "custom_cc", "waf"} {
		if value, exists := keys[key]; exists && string(value) == "null" {
			return limits, ErrInvalidInput
		}
	}
	if json.Unmarshal(raw, &limits) != nil || limits.Connections != nil && (*limits.Connections < -1 || *limits.Connections > 65535) ||
		limits.BandwidthBPS != nil && (*limits.BandwidthBPS < -1 || *limits.BandwidthBPS > edgeconfig.MaxPackageBandwidthBPS) {
		return soldPackageLimits{}, ErrInvalidInput
	}
	return limits, nil
}

func soldPackageSecurityBindings(bindings []securityBindingFact, limits soldPackageLimits) []securityBindingFact {
	return slices.DeleteFunc(slices.Clone(bindings), func(binding securityBindingFact) bool {
		return binding.policy.Kind == securitypolicy.KindWAF && limits.WAF != nil && !*limits.WAF ||
			binding.policy.Kind == securitypolicy.KindCC && limits.CustomCC != nil && !*limits.CustomCC
	})
}

func applySoldPackageRuntimeV2Limits(document *siteRuntimeV2Document, limits map[uuid.UUID]soldPackageLimits) {
	for index := range document.Sites {
		site := &document.Sites[index]
		value := limits[uuid.MustParse(site.ID)]
		if value.WebSocket != nil {
			enabled := *value.WebSocket
			site.WebSocket = &enabled
		}
		if value.HTTP3 != nil && !*value.HTTP3 {
			for index := range site.Listeners {
				site.Listeners[index].Protocols = slices.DeleteFunc(slices.Clone(site.Listeners[index].Protocols), func(protocol string) bool { return protocol == "http3" })
			}
		}
		connections, bandwidth := int64(-1), int64(0)
		if value.Connections != nil && *value.Connections >= 0 {
			connections = *value.Connections
		}
		if value.BandwidthBPS != nil && *value.BandwidthBPS > 0 {
			bandwidth = *value.BandwidthBPS
		}
		if value.market != nil {
			if value.market.Connections >= 0 || value.market.BandwidthBPS > 0 || value.market.SubscriptionLimitsUsed() {
				market := *value.market
				site.PackageLimits = &market
			}
		} else if connections >= 0 || bandwidth > 0 {
			site.PackageLimits = &edgeconfig.PackageConnectionLimit{
				SubscriptionID: value.subscriptionID.String(), Connections: connections, BandwidthBPS: bandwidth,
			}
		}
	}
	// Recompute only the gated capabilities; preserve unrelated policy requirements.
	required := make(map[string]uint32)
	for _, capability := range document.RequiredCapabilities {
		if capability.Name != "websocket" && capability.Name != "http3" && capability.Name != edgeconfig.SubscriptionLimitsCapability {
			required[capability.Name] = capability.APIVersion
		}
	}
	for _, site := range document.Sites {
		if *site.WebSocket {
			required["websocket"] = 1
		}
		if site.PackageLimits != nil && site.PackageLimits.SubscriptionLimitsUsed() {
			required[edgeconfig.SubscriptionLimitsCapability] = edgeconfig.SubscriptionLimitsAPIVersion
		}
		if site.PackageLimits != nil {
		}
		for _, listener := range site.Listeners {
			if slices.Contains(listener.Protocols, "http3") {
				required["http3"] = 1
			}
		}
	}
	document.RequiredCapabilities = nil
	for name, version := range required {
		document.RequiredCapabilities = append(document.RequiredCapabilities, siteRuntimeV2Capability{Name: name, APIVersion: version})
	}
	sort.Slice(document.RequiredCapabilities, func(i, j int) bool {
		return document.RequiredCapabilities[i].Name < document.RequiredCapabilities[j].Name
	})
}

// bindSoldPackageRuntimeSecurity binds each listener's security as the
// legacy renderer binds the site's (siteRuntimeV2ListenerSecurity): the
// package-permitted policies, the managed WAF and the JS challenge
// (facts[].challenge; tenantID is the challenge's tenants.id). override, when
// set, is a security activation candidate's binding: it replaces the site's
// binding of its kind (replaceSecurityBinding).
func bindSoldPackageRuntimeSecurity(ctx context.Context, tx pgx.Tx, scopeID, tenantID uuid.UUID, facts []siteFact, limits map[uuid.UUID]soldPackageLimits, document *siteRuntimeV2Document, override *securityBindingFact) error {
	bindings, err := loadSecurityBindingFacts(ctx, tx, scopeID)
	if err != nil {
		return err
	}
	if override != nil {
		replaceSecurityBinding(bindings, *override)
	}
	// Each site's own quick block over its WAF library (a candidate's
	// binding included).
	quickBlocks, err := loadSiteQuickBlockOverrides(ctx, tx, scopeID)
	if err != nil {
		return err
	}
	applySiteQuickBlockOverrides(bindings, quickBlocks)
	if err := attachSiteTrustedCrawlers(ctx, tx, bindings); err != nil {
		return err
	}
	if err := attachSiteCRS(ctx, tx, scopeID, bindings); err != nil {
		return err
	}
	if err := attachSiteIPLists(ctx, tx, scopeID, bindings); err != nil {
		return err
	}
	byID := make(map[uuid.UUID]siteFact, len(facts))
	for _, fact := range facts {
		byID[fact.id] = fact
	}
	for i := range document.Sites {
		site := &document.Sites[i]
		id := uuid.MustParse(site.ID)
		filtered := soldPackageSecurityBindings(bindings[id], limits[id])
		for j := range site.Listeners {
			listener := &site.Listeners[j]
			security, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, byID[id], uint16(listener.Port), filtered)
			if err != nil {
				return err
			}
			listener.Security = security
		}
	}
	setSiteRuntimeV2SecurityCapabilities(document)
	return nil
}

// setSiteRuntimeV2SecurityCapabilities raises the document's required
// capabilities to what its listeners' security needs.
func setSiteRuntimeV2SecurityCapabilities(document *siteRuntimeV2Document) {
	required := make(map[string]uint32)
	for _, capability := range document.RequiredCapabilities {
		required[capability.Name] = capability.APIVersion
	}
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			if listener.Security != nil {
				if listener.Security.CC != nil {
					required["cc"] = max(required["cc"], listenerCCAPIVersion(listener.Security))
				}
				if version := edgeconfig.ListenerSecurityWAFAPIVersion(listener.Security); version > 0 {
					required["waf"] = max(required["waf"], version)
				}
				if edgeconfig.ListenerSecurityUsesJA4(listener.Security) {
					required["ja4"] = ja4APIVersion
				}
				if edgeconfig.ListenerSecurityUsesCCMatchKeys(listener.Security) {
					required[edgeconfig.CCMatchKeysCapability] = edgeconfig.CCMatchKeysAPIVersion
				}
				if edgeconfig.ListenerSecurityUsesJA4Negation(listener.Security) {
					required[edgeconfig.WAFJA4NegationCapability] = edgeconfig.JA4NegationAPIVersion
				}
				if edgeconfig.SecurityPoliciesUseIPIntel(listener.Security.Policies) {
					required["ip_intel"] = edgeconfig.IPIntelCapabilityVersion
				}
			}
		}
	}
	document.RequiredCapabilities = nil
	for name, version := range required {
		document.RequiredCapabilities = append(document.RequiredCapabilities, siteRuntimeV2Capability{Name: name, APIVersion: version})
	}
	sort.Slice(document.RequiredCapabilities, func(i, j int) bool {
		return document.RequiredCapabilities[i].Name < document.RequiredCapabilities[j].Name
	})
}
