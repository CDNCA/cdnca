package edgepublish

import (
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"slices"
	"sort"
)

// l4StreamCapabilityVersion is the tcp/udp API version an agent needs for a
// v2 stream: 12 for every stream since it belongs to no website (migration
// 492: the spec and its geo carry no site_id, which agents before v12
// require). v12 agents implement every earlier feature (additional
// listeners, passthrough and shared ports, drain limit, new connection rate,
// session log, toa, port ranges, guard rules, origin lists; 1.0.35 baseline).
const l4StreamCapabilityVersion uint32 = 12

func bindSiteRuntimeV2Streams(document *siteRuntimeV2Document, tenantID uuid.UUID, streams []snapshotStream, lifecycle []l4ProtocolCapability) {
	if len(streams) == 0 && len(lifecycle) == 0 {
		return
	}
	runtime := &edgeconfig.StreamRuntime{TenantID: tenantID.String()}
	required := map[string]uint32{}
	for _, stream := range streams {
		value := *stream.RuntimeV2
		value.TenantID = tenantID.String()
		value.Geo.TenantID = tenantID.String()
		runtime.StreamsV2 = append(runtime.StreamsV2, value)
		version := l4StreamCapabilityVersion
		required[value.Listener.Protocol] = max(required[value.Listener.Protocol], version)
		for _, listener := range value.AdditionalListeners {
			required[listener.Protocol] = max(required[listener.Protocol], version)
		}
		if value.ProxyProtocolInbound || value.ProxyProtocolOutbound {
			required["proxy_protocol"] = 1
		}
		if value.TOA {
			required["l4_toa"] = 1
		}
		if value.SubscriptionLimits != nil {
			required[edgeconfig.SubscriptionLimitsCapability] = edgeconfig.SubscriptionLimitsAPIVersion
		}
		if value.PackageSubscriptionID != "" {
			// The node stamps the package on the forward's session facts.
			required[edgeconfig.L4PackageAttributionCapability] = edgeconfig.L4PackageAttributionAPIVersion
		}
		if edgeconfig.L4GuardRulesUseIPIntel(value.GuardRules) {
			// The node looks the rules' geo conditions up in its library.
			required["ip_intel"] = edgeconfig.IPIntelCapabilityVersion
		}
	}
	for _, item := range lifecycle {
		required[item.protocol] = max(required[item.protocol], item.version)
	}
	for _, capability := range document.RequiredCapabilities {
		required[capability.Name] = max(required[capability.Name], capability.APIVersion)
	}
	document.RequiredCapabilities = nil
	for name, version := range required {
		document.RequiredCapabilities = append(document.RequiredCapabilities, siteRuntimeV2Capability{Name: name, APIVersion: version})
	}
	sort.Slice(document.RequiredCapabilities, func(i, j int) bool {
		return document.RequiredCapabilities[i].Name < document.RequiredCapabilities[j].Name
	})
	document.Streams = runtime
}

func siteRuntimeStreamFragment(document siteRuntimeV2Document, healthPort uint16) (string, map[string][]byte, error) {
	if document.Streams == nil {
		return "", nil, nil
	}
	// Every stream requires tcp/udp v12 (bindSiteRuntimeV2Streams), which
	// serves shared sockets.
	var claims []edgeconfig.PortClaim
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			claims = append(claims, edgeconfig.SiteListenerPortClaims("", site.ID, uint16(listener.Port),
				listener.TLS != nil, slices.Contains(listener.Protocols, "http3"), site.Domains)...)
		}
	}
	return edgeconfig.RenderSharedStreamFragment(document.ConfigVersionID, uint64(document.SourceRevision), *document.Streams,
		healthPort, claims)
}
