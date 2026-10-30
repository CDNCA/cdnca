// Package siteruntimecap is the single table of site runtime v2 document
// capability names (required_capabilities[].name) and the Agent capability
// each one stands for. The publisher (edgepublish) and the rollout
// validator (edgedeployment) both read it, so a name the publisher may write
// is always one the validator accepts.
//
// Adding a capability: add the proto enum value, then one line to
// siteobject.RuntimeCapabilityNames (libs/edgeconfig).
// TestEveryCapabilityIsClassified fails until each enum value is either
// there or in nodeOnlyCapabilities.
package siteruntimecap

import (
	"sort"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// documentNames is built from siteobject.RuntimeCapabilityNames, the table
// the edge agent also reads (fix-l4cap), so a name written here is always one
// the agent accepts.
var documentNames = buildDocumentNames()

func buildDocumentNames() map[string]agentv1.CapabilityName {
	result := make(map[string]agentv1.CapabilityName, len(siteobject.RuntimeCapabilityNames))
	for enum, document := range siteobject.RuntimeCapabilityNames {
		value, ok := agentv1.CapabilityName_value[enum]
		if !ok {
			panic("siteruntimecap: " + enum + " is not an agent.v1 CapabilityName")
		}
		if _, duplicate := result[document]; duplicate {
			panic("siteruntimecap: document capability " + document + " is mapped twice")
		}
		result[document] = agentv1.CapabilityName(value)
	}
	return result
}

// nodeOnlyCapabilities are Agent capabilities that never appear in a site
// runtime v2 document (node, gateway or command level features).
var nodeOnlyCapabilities = map[agentv1.CapabilityName]bool{
	agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED: true,
	// HTTP_3 is only the standalone HTTP/3 runtime; the document's "http3"
	// is SITE_QUIC.
	agentv1.CapabilityName_CAPABILITY_NAME_HTTP_3:                          true,
	agentv1.CapabilityName_CAPABILITY_NAME_NFTABLES:                        true,
	agentv1.CapabilityName_CAPABILITY_NAME_IPSET:                           true,
	agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE:                  true,
	agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK:                 true,
	agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL:                   true,
	agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY:             true,
	agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY:          true,
	agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT:   true,
	agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE:                    true,
	agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK:      true,
	agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT: true,
	agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE:   true,
	agentv1.CapabilityName_CAPABILITY_NAME_FIREWALL_CONTROL:                true,
	agentv1.CapabilityName_CAPABILITY_NAME_DRAIN_CONTROL:                   true,
	agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING:                 true,
	agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION:         true,
	agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE:                    true,
	agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE:                  true,
	agentv1.CapabilityName_CAPABILITY_NAME_MULTI_TENANT_RUNTIME:            true,
	agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK:                true,
	agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS:             true,
	agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST:               true,
	agentv1.CapabilityName_CAPABILITY_NAME_ARTIFACT_SET:                    true,
	agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE:                    true,
	agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER:                      true,
	agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET:         true,
	agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION:      true,
	agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP:                       true,
	// L4_TRAFFIC_STOP is declared per node; the per-node site object key
	// document names the forwards to cut, never required_capabilities.
	agentv1.CapabilityName_CAPABILITY_NAME_L4_TRAFFIC_STOP: true,
	// WAF_REPEAT_SITE is declared per node; autodefense sends a site's grey
	// zone repeat setting only to a node that declares it (defer-small2).
	agentv1.CapabilityName_CAPABILITY_NAME_WAF_REPEAT_SITE: true,
	// CACHE_WILDCARD_PURGE is checked per node by cachecontrol before a
	// "*.<suffix>" purge is sent (fp-site2), never required_capabilities.
	agentv1.CapabilityName_CAPABILITY_NAME_CACHE_WILDCARD_PURGE: true,
	// L4_STREAM_SELECTION is declared per node; the per-node site object key
	// document names the forwards it withholds (per-node-dist).
	agentv1.CapabilityName_CAPABILITY_NAME_L4_STREAM_SELECTION: true,
	// CACHE_CONTROL_CANCEL is checked per node by cachecontrol Cancel before
	// a cancel is sent to the node (fz-x3, CACHE-ADD-07).
	agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL: true,
	// NODE_TELEMETRY_DETAIL is node telemetry content (mounts, port group
	// override receipts, fz-x11); the console reads it per node.
	agentv1.CapabilityName_CAPABILITY_NAME_NODE_TELEMETRY_DETAIL: true,
	// NODE_REGION is declared per node; the per-node site object key
	// document carries the node's region code (fz-x12).
	agentv1.CapabilityName_CAPABILITY_NAME_NODE_REGION: true,
	// NODE_STORAGE is declared per node; the per-node site object key
	// document carries the node's cache and log directories (fix-nodesettings).
	agentv1.CapabilityName_CAPABILITY_NAME_NODE_STORAGE: true,
	// BAN_CIDR gates network bans in the security ban list (fix-cidrban),
	// not a site runtime document.
	agentv1.CapabilityName_CAPABILITY_NAME_BAN_CIDR: true,
	// AGGREGATED_EDGE_PROBE gates the probe method and headers of aggregated
	// edge host targets (fix-aephase1), a probe command feature.
	agentv1.CapabilityName_CAPABILITY_NAME_AGGREGATED_EDGE_PROBE: true,
	// GATEWAY_ADDRESS_CHANGE gates the signed Gateway address change command
	// (fix-nodegw), a node command feature.
	agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE: true,
}

// Name maps a document capability name to its Agent capability.
func Name(value string) (agentv1.CapabilityName, bool) {
	name, ok := documentNames[value]
	if !ok {
		return agentv1.CapabilityName_CAPABILITY_NAME_UNSPECIFIED, false
	}
	return name, true
}

// Names lists every document capability name, sorted.
func Names() []string {
	result := make([]string, 0, len(documentNames))
	for name := range documentNames {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
