package siteobject

import "github.com/cdnca/cdnca/libs/edgeconfig"

// RuntimeCapabilityNames is the single table of site runtime v2 document
// capability names (required_capabilities[].name), keyed by the agent.v1
// CapabilityName enum value name. The control plane's publisher/validator
// (siteruntimecap) and the edge agent's site object check both read it, so
// a name the control plane writes is always one the agent accepts
// (fix-l4cap: the agent had missed L4_TOA, L4_PACKAGE_ATTRIBUTION and
// SUBSCRIPTION_LIMITS and refused every L4 forward).
//
// Keys are enum names rather than proto values so this package does not
// depend on the generated proto module; both readers check every key is a
// real enum value.
var RuntimeCapabilityNames = map[string]string{
	"CAPABILITY_NAME_HTTP_1_1": "http1",
	"CAPABILITY_NAME_HTTP_2":   "http2",
	// The listener protocol http3 (QUIC on an HTTPS listener) needs the
	// QUIC-capable OpenResty build, not the standalone HTTP/3 runtime
	// (CAPABILITY_NAME_HTTP_3, which is node only).
	"CAPABILITY_NAME_SITE_QUIC":      "http3",
	"CAPABILITY_NAME_WEBSOCKET":      "websocket",
	"CAPABILITY_NAME_IPV4":           "ipv4",
	"CAPABILITY_NAME_IPV6":           "ipv6",
	"CAPABILITY_NAME_TCP_PROXY":      "tcp",
	"CAPABILITY_NAME_UDP_PROXY":      "udp",
	"CAPABILITY_NAME_PROXY_PROTOCOL": "proxy_protocol",
	"CAPABILITY_NAME_CC":             "cc",
	"CAPABILITY_NAME_WAF":            "waf",
	"CAPABILITY_NAME_SITE_RUNTIME":   "site_runtime",
	"CAPABILITY_NAME_JA4":            "ja4",
	// fix-ja4rule: WAF "JA4 not in list" (72) and CC v7 count keys / JA4 match (73).
	"CAPABILITY_NAME_WAF_JA4_NEGATION":        edgeconfig.WAFJA4NegationCapability,
	"CAPABILITY_NAME_CC_MATCH_KEYS":           edgeconfig.CCMatchKeysCapability,
	"CAPABILITY_NAME_IP_INTEL":                "ip_intel",
	"CAPABILITY_NAME_L4_TOA":                  "l4_toa",
	"CAPABILITY_NAME_SCHED302":                "sched302",
	"CAPABILITY_NAME_SUBSCRIPTION_LIMITS":     edgeconfig.SubscriptionLimitsCapability,
	"CAPABILITY_NAME_EDGE_BROTLI":             "edge_brotli",
	"CAPABILITY_NAME_EDGE_WEBP":               "edge_webp",
	"CAPABILITY_NAME_EDGE_RESPONSE_RULES":     edgeconfig.EdgeResponseRulesCapability,
	"CAPABILITY_NAME_CACHE_RULE_MATCH":        edgeconfig.CacheRuleMatchCapability,
	"CAPABILITY_NAME_ORIGIN_FOLLOW_REDIRECT":  edgeconfig.OriginFollowRedirectCapability,
	"CAPABILITY_NAME_ORIGIN_TLS_NO_VERIFY":    edgeconfig.OriginTLSNoVerifyCapability,
	"CAPABILITY_NAME_SITE_EDGE_OPTIONS":       edgeconfig.SiteEdgeOptionsCapability,
	"CAPABILITY_NAME_L2_ROUTING":              edgeconfig.L2RoutingCapability,
	"CAPABILITY_NAME_ERROR_PAGE_SLOTS":        ErrorPageSlotsCapability,
	"CAPABILITY_NAME_SITE_TLS_OPTIONS":        edgeconfig.SiteTLSOptionsCapability,
	"CAPABILITY_NAME_SITE_TLS_CUSTOM_CIPHERS": edgeconfig.SiteTLSCustomCiphersCapability,
	"CAPABILITY_NAME_L4_PACKAGE_ATTRIBUTION":  edgeconfig.L4PackageAttributionCapability,
}
