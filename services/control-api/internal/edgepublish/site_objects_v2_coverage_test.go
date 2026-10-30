package edgepublish

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// siteObjectV2Coverage is every field of the site model a v8 publication
// carries per site (the v2 document site entry, its origin-route document,
// telemetry entry, HTTP policy entry) and where cdnca.edge.site/v2 puts it.
// "->" maps a field; "derived" is recomputed; "dropped" has no meaning once
// a site is data (with why); "pending" is not expressed yet (with the task).
// docs/edge/site-object-v2.md mirrors this table.
var siteObjectV2Coverage = map[string]string{
	"id":                                                           "-> site_id",
	"revision":                                                     "-> revision",
	"domains[]":                                                    "-> hosts.primary (first), hosts.aliases (sorted)",
	"listeners[].id":                                               "dropped: public-<port>; the port is the listener identity",
	"listeners[].position":                                         "dropped: listeners are ordered by port",
	"listeners[].address_family":                                   "-> listeners[].address_family",
	"listeners[].port":                                             "-> listeners[].port",
	"listeners[].protocols[]":                                      "-> listeners[].http2/http3 (http1 always)",
	"listeners[].tls.certificate_version_id":                       "-> listeners[].tls.certificate_version_id",
	"listeners[].tls.protocols[]":                                  "-> listeners[].tls.protocols (absent: TLSv1.2+TLSv1.3)",
	"listeners[].tls.cipher_preset":                                "-> listeners[].tls.cipher_preset",
	"listeners[].tls.cipher_suites[]":                              "-> listeners[].tls.cipher_suites[]",
	"listeners[].tls.ocsp_stapling":                                "-> listeners[].tls.ocsp_stapling",
	"listeners[].tls.client_auth":                                  "-> listeners[].tls.client_auth",
	"listeners[].tls.prefer_server_ciphers":                        "-> listeners[].tls.prefer_server_ciphers",
	"listeners[].tls.client_ca_ref":                                "-> listeners[].tls.client_ca (ref client_ca, the bundle as an object)",
	"listeners[].security.policies[]":                              "-> security.rules.policies (merged across listeners; rules pinned by port when they differ)",
	"listeners[].security.cc.SourceSHA256":                         "-> security.cc[].source_sha256",
	"listeners[].security.cc.CompiledSHA256":                       "-> security.cc[].policy.sha256",
	"listeners[].security.cc.Policy":                               "-> referenced cc_policy object (canonical CCV2Policy)",
	"listeners[].security.managed_waf.policy_id":                   "-> security.managed_waf.policy_id",
	"listeners[].security.managed_waf.policy_version":              "-> security.managed_waf.policy_version",
	"listeners[].security.managed_waf.request_body_limit":          "-> security.managed_waf.profile",
	"listeners[].security.managed_waf.request_body_no_files_limit": "-> security.managed_waf.profile",
	"listeners[].security.managed_waf.request_body_limit_action":   "-> security.managed_waf.profile",
	"listeners[].security.managed_waf.arguments_limit":             "-> security.managed_waf.profile",
	"listeners[].security.managed_waf.json_depth_limit":            "-> security.managed_waf.profile",
	"listeners[].security.managed_waf.pcre_match_limit":            "-> security.managed_waf.profile",
	"listeners[].security.managed_waf.inspection_limit_action":     "-> security.managed_waf.profile, security.rules.header_overflow",
	"listeners[].security.managed_waf.profile":                     "-> security.managed_waf.crs_profile",
	"listeners[].security.managed_waf.exclusions[]":                "-> security.managed_waf.exclusions",
	"listeners[].security.managed_waf.allow_cidrs[]":               "-> security.managed_waf.allow_cidrs",
	"listeners[].security.managed_waf.apps[].pack_id":              "-> security.managed_waf.apps",
	"listeners[].security.managed_waf.apps[].version":              "-> security.managed_waf.apps",
	"listeners[].security.managed_waf.apps[].sha256":               "-> security.managed_waf.apps",
	"listeners[].security.challenge.tenant_id":                     "-> tenant_id",
	"listeners[].security.challenge.policy_id":                     "-> security.challenge.id",
	"listeners[].security.challenge.policy_version":                "-> security.challenge.revision",
	"origin_pools[].id":                                            "-> origin.pools[].id",
	"origin_pools[].position":                                      "dropped: pools are ordered by id",
	"origin_pools[].kind":                                          "-> origin.pools[].kind",
	"origin_pools[].algorithm":                                     "-> origin.pools[].algorithm (origin route balance_method wins)",
	"origin_pools[].origins[].id":                                  "-> origin.pools[].endpoints[].id",
	"origin_pools[].origins[].position":                            "dropped: endpoints keep their order",
	"origin_pools[].origins[].tier":                                "derived: the pool kind",
	"origin_pools[].origins[].scheme":                              "-> origin.pools[].endpoints[].scheme",
	"origin_pools[].origins[].host":                                "-> origin.pools[].endpoints[].host",
	"origin_pools[].origins[].port":                                "-> origin.pools[].endpoints[].port",
	"origin_pools[].origins[].weight":                              "-> origin.pools[].endpoints[].weight",
	"origin_pools[].origins[].node_id":                             "-> origin.pools[].endpoints[].node_id",
	"origin_pools[].origins[].sni":                                 "-> origin.pools[].endpoints[].sni + sni_mode custom; absent: sni_mode visitor_host / origin_host / custom (request_host custom value without port), v7 poolTLSName",
	"origin_pools[].origins[].trust_ref":                           "-> origin.pools[].endpoints[].trust_anchor (the CA set: a referenced object, its digest)",
	"origin_pools[].retry.methods[]":                               "-> origin.pools[].retry.methods",
	"origin_pools[].retry.bodyless_only":                           "dropped: always true (fixed by the format)",
	"origin_pools[].retry.response_not_started":                    "dropped: always true (fixed by the format)",
	"origin_pools[].retry.retry_on[]":                              "dropped: always the six failures (fixed by the format)",
	"origin_pools[].retry.max_attempts":                            "-> origin.pools[].retry.max_attempts",
	"origin_pools[].retry.connect_timeout_ms":                      "-> origin.pools[].retry.connect_timeout_ms",
	"origin_pools[].retry.read_timeout_ms":                         "-> origin.pools[].retry.read_timeout_ms",
	"origin_pools[].retry.total_budget_ms":                         "-> origin.pools[].retry.total_budget_ms",
	"origin_pools[].keepalive_idle_timeout_ms":                     "-> origin.pools[].keepalive_idle_timeout_ms",
	// ge-origin (G3) origin forwarding (dynamic routing D5a).
	"origin_pools[].hash_key":                 "-> origin.pools[].hash_key (algorithm hash)",
	"origin_pools[].sticky.source":            "-> origin.pools[].sticky.source (algorithm sticky)",
	"origin_pools[].sticky.name":              "-> origin.pools[].sticky.name",
	"origin_pools[].request_host.mode":        "-> origin.pools[].request_host.mode (absent: the visitor host)",
	"origin_pools[].request_host.value":       "-> origin.pools[].request_host.value",
	"origin_pools[].follow_port":              "-> origin.pools[].follow_port",
	"origin_pools[].active_level":             "-> origin.pools[].active_level",
	"origin_pools[].origins[].level":          "-> origin.pools[].endpoints[].level",
	"origin_pools[].origins[].max_conns":      "-> origin.pools[].endpoints[].max_conns",
	"forwarding.trusted_proxy_cidrs[]":        "-> origin.trusted_proxy_cidrs",
	"forwarding.websocket_origins[]":          "-> websocket_origins",
	"forwarding.https_pool_id":                "-> origin.https_pool_id",
	"forwarding.follow_redirect.max_hops":     "-> origin.follow_redirect.max_hops (ge36, ORIGIN_FOLLOW_REDIRECT)",
	"forwarding.follow_redirect.cross_origin": "-> origin.follow_redirect.cross_origin",
	"forwarding.search_engine_pool_id":        "-> origin.search_engine.pool_id (site-backend6, SITE_EDGE_OPTIONS)",
	"forwarding.acme_passthrough":             "-> origin.acme_passthrough (site-backend6)",
	"forwarding.unbuffered[]":                 "-> origin.unbuffered[] (site-backend6)",
	"forwarding.default_site":                 "-> default (site-backend6)",
	"origin_route.routes[].hosts[]":           "-> origin.routes[].hosts",
	"default_pool_id":                         "-> origin.default_pool_id (origin route wins)",
	"websocket":                               "-> websocket",
	"range":                                   "-> range",
	"l2.enabled":                              "-> origin.l2 present",
	"l2.direct_fallback_pool_id":              "-> origin.l2.direct_fallback_pool_id",
	"l2.probe_interval_ms":                    "-> origin.l2.probe_interval_ms",
	"l2.failure_threshold":                    "-> origin.l2.failure_threshold",
	"l2.recovery_threshold":                   "-> origin.l2.recovery_threshold",
	"l2.single_half_open_probe":               "dropped: always true (fixed by the format)",
	"l2.max_hops":                             "dropped: always 1 (fixed by the format)",
	"l2.cache_only":                           "-> origin.l2.cache_only",
	"l2.passthrough":                          "-> origin.l2.passthrough",
	"l2.conditions[].id":                      "-> origin.l2.conditions[].id",
	"l2.conditions[].rules[].field":           "-> origin.l2.conditions[].rules[].field",
	"l2.conditions[].rules[].operator":        "-> origin.l2.conditions[].rules[].operator",
	"l2.conditions[].rules[].value":           "-> origin.l2.conditions[].rules[].value",
	"l2.conditions[].node_ids[]":              "-> origin.l2.conditions[].node_ids",
	"l2.conditions[].endpoint_ids[]":          "-> origin.l2.conditions[].endpoint_ids",
	"http_policy.policy_id":                   "-> http_policy.id",
	"http_policy.policy_revision":             "-> http_policy.revision",
	"http_policy.artifact_sha256":             "dropped: digest of the whole scope file; http_policy.sha256 addresses the site's own entry",
	"firewall_action.policy_id":               "-> security.firewall_action.id",
	"firewall_action.policy_revision":         "-> security.firewall_action.revision",
	"firewall_action.document_sha256":         "-> security.firewall_action.sha256 (the file object)",
	"firewall_action.artifact_path":           "dropped: a path in the release; the object is addressed by digest",
	"force_https.redirect_port":               "-> force_https.redirect_port",
	"cache.tenant_id":                         "-> tenant_id",
	"cache.domain":                            "-> cache.domain",
	// The policy document is carried whole (cache.policy); each field is
	// listed so a new policy field must say how the node uses it.
	"cache.policy.schema_version":                    "-> cache.policy.schema_version (in cache.generation)",
	"cache.policy.revision":                          "-> cache.policy.revision (not in cache.generation)",
	"cache.policy.mode":                              "-> cache.policy.mode (in cache.generation)",
	"cache.policy.rules[].order":                     "-> cache.policy.rules[].order",
	"cache.policy.rules[].extensions[]":              "-> cache.policy.rules[].extensions",
	"cache.policy.rules[].path_prefix":               "-> cache.policy.rules[].path_prefix",
	"cache.policy.rules[].status_codes[]":            "-> cache.policy.rules[].status_codes",
	"cache.policy.rules[].action":                    "-> cache.policy.rules[].action (no_cache: BYPASS no_cache_rule)",
	"cache.policy.rules[].ttl_seconds":               "-> cache.policy.rules[].ttl_seconds",
	"cache.policy.rules[].browser_ttl_seconds":       "-> cache.policy.rules[].browser_ttl_seconds",
	"cache.policy.rules[].path_regex":                "-> cache.policy.rules[].path_regex (ge36, CACHE_RULE_MATCH, in the generation)",
	"cache.policy.rules[].content_types[]":           "-> cache.policy.rules[].content_types (ge36, CACHE_RULE_MATCH, header filter, in the generation)",
	"cache.policy.rules[].path_exact":                "-> cache.policy.rules[].path_exact (单个路径, CACHE_RULE_MATCH v2, in the generation)",
	"cache.policy.rules[].ignore_query":              "-> cache.policy.rules[].ignore_query (按规则忽略 URL 参数, CACHE_RULE_MATCH v2, in the generation)",
	"cache.policy.rules[].slice_bytes":               "-> cache.policy.rules[].slice_bytes (按规则分片回源, CACHE_RULE_MATCH v2, in the generation)",
	"cache.policy.rules[].force_cache":               "-> cache.policy.rules[].force_cache (强制 CDN 缓存, CACHE_RULE_MATCH v2, in the generation)",
	"cache.policy.rules[].ignore_vary":               "-> cache.policy.rules[].ignore_vary (忽略 Vary, CACHE_RULE_MATCH v2, in the generation)",
	"cache.policy.rules[].no_cache[].source":         "-> cache.policy.rules[].no_cache[].source (不缓存条件, CACHE_RULE_MATCH v2, in the generation)",
	"cache.policy.rules[].no_cache[].name":           "-> cache.policy.rules[].no_cache[].name (不缓存条件请求头名)",
	"cache.policy.rules[].no_cache[].pattern":        "-> cache.policy.rules[].no_cache[].pattern (不缓存条件正则)",
	"cache.policy.query_mode":                        "-> cache.policy.query_mode (in cache.generation)",
	"cache.policy.query_names[]":                     "-> cache.policy.query_names (in cache.generation)",
	"cache.policy.vary_headers[]":                    "-> cache.policy.vary_headers (in cache.generation)",
	"cache.policy.disk_quota_bytes":                  "-> cache.policy.disk_quota_bytes (soft quota, not in cache.generation)",
	"cache.policy.stale_if_error":                    "-> cache.policy.stale_if_error (use_stale error/timeout/updating/5xx; not in cache.generation)",
	"cache.policy.background_update":                 "-> cache.policy.background_update (needs stale_if_error; not in cache.generation)",
	"cache.policy.min_object_bytes":                  "-> cache.policy.min_object_bytes (BYPASS object_size; not in cache.generation)",
	"cache.policy.max_object_bytes":                  "-> cache.policy.max_object_bytes (BYPASS object_size; not in cache.generation)",
	"cache.policy.slice_bytes":                       "-> cache.policy.slice_bytes (slice variant; in cache.generation)",
	"cache.shared_across_domains":                    "-> cache.key_by_host (inverted)",
	"package_limits.subscription_id":                 "-> limits.connections.subscription_id",
	"package_limits.connections":                     "-> limits.connections.max",
	"package_limits.bandwidth_bps":                   "-> limits.connections.bandwidth_bps",
	"package_limits.max_connections":                 "-> limits.connections.max_connections",
	"package_limits.new_per_second":                  "-> limits.connections.new_per_second",
	"package_limits.qps":                             "-> limits.connections.qps",
	"package_limits.stopped":                         "-> limits.connections.stopped",
	"traffic_limit.exceeded":                         "-> traffic_limit (present only while exceeded)",
	"traffic_limit.period":                           "-> traffic_limit.period",
	"traffic_limit.notice_html":                      "-> traffic_limit.notice_html",
	"package_expired":                                "-> package_expired (errpage-3)",
	"schedule302.target":                             "-> schedule302.target",
	"schedule302.keep_path":                          "-> schedule302.keep_path",
	"schedule302.keep_query":                         "-> schedule302.keep_query",
	"schedule302.signature_ttl_seconds":              "-> schedule302.signature_ttl_seconds",
	"schedule302.https_to_http":                      "-> schedule302.https_to_http",
	"schedule302.extensions[]":                       "-> schedule302.extensions",
	"schedule302.path_prefixes[]":                    "-> schedule302.path_prefixes",
	"schedule302.min_size_bytes":                     "-> schedule302.min_size_bytes",
	"force_https.status":                             "-> force_https.status",
	"force_https.exclude_hosts[]":                    "-> force_https.exclude_hosts",
	"access.host_redirects[].source_host":            "-> access.host_redirects.source_host",
	"access.host_redirects[].target_host":            "-> access.host_redirects.target_host",
	"access.host_redirects[].target_scheme":          "-> access.host_redirects.target_scheme",
	"access.host_redirects[].target_port":            "-> access.host_redirects.target_port",
	"access.host_redirects[].status":                 "-> access.host_redirects.status",
	"access.host_redirects[].preserve_uri":           "-> access.host_redirects.preserve_uri",
	"access.hsts.max_age_seconds":                    "-> hsts.max_age_seconds (site object field, D9)",
	"access.hsts.include_subdomains":                 "-> hsts.include_subdomains (site object field, D9)",
	"access.hsts.preload":                            "-> hsts.preload (site object field, D9)",
	"access.compression.enabled":                     "-> access.compression.enabled",
	"access.compression.types[]":                     "-> access.compression.types",
	"access.compression.min_length_bytes":            "-> access.compression.min_length_bytes",
	"access.compression.encodings[]":                 "-> access.compression.encodings",
	"access.compression.gzip_level":                  "-> access.compression.gzip_level",
	"access.compression.brotli_level":                "-> access.compression.brotli_level",
	"access.webp.enabled":                            "-> access.webp.enabled",
	"access.webp.quality":                            "-> access.webp.quality",
	"access.response_rules[].id":                     "-> access.response_rules.id",
	"access.response_rules[].statuses[].from":        "-> access.response_rules.statuses.from",
	"access.response_rules[].statuses[].to":          "-> access.response_rules.statuses.to",
	"access.response_rules[].headers[].name":         "-> access.response_rules.headers.name",
	"access.response_rules[].headers[].op":           "-> access.response_rules.headers.op",
	"access.response_rules[].headers[].value":        "-> access.response_rules.headers.value",
	"access.response_rules[].action":                 "-> access.response_rules.action",
	"access.response_rules[].header_actions[].kind":  "-> access.response_rules.header_actions.kind",
	"access.response_rules[].header_actions[].name":  "-> access.response_rules.header_actions.name",
	"access.response_rules[].header_actions[].value": "-> access.response_rules.header_actions.value",
	"access.response_rules[].status":                 "-> access.response_rules.status",
	"access.limits.connections_per_ip":               "-> access.limits.connections_per_ip",
	"access.limits.rate_bytes_per_second":            "-> access.limits.rate_bytes_per_second",
	"access.limits.rate_after_bytes":                 "-> access.limits.rate_after_bytes",
	"access.basic_auth.realm":                        "-> access.basic_auth.realm",
	"access.basic_auth.users[].username":             "-> access.basic_auth.users.username",
	"access.basic_auth.users[].salt":                 "-> access.basic_auth.users.salt",
	"access.basic_auth.users[].sha256":               "-> access.basic_auth.users.sha256",
	"access.basic_auth.exclude_path_prefixes[]":      "-> access.basic_auth.exclude_path_prefixes",
	"access.maintenance.status":                      "-> access.maintenance.status",
	"access.maintenance.content_type":                "-> access.maintenance.content_type",
	"access.maintenance.body":                        "-> access.maintenance.body",
	"access.maintenance.retry_after_seconds":         "-> access.maintenance.retry_after_seconds",
	"access.maintenance.allowed_cidrs[]":             "-> access.maintenance.allowed_cidrs",

	"origin_route.schema":                                   "dropped: the route document's own schema",
	"origin_route.ingress_source_enabled":                   "-> origin.ingress_source",
	"origin_route.pools[].id":                               "-> origin.pools[].id",
	"origin_route.pools[].kind":                             "-> origin.pools[].kind",
	"origin_route.pools[].balance_method":                   "-> origin.pools[].algorithm",
	"origin_route.pools[].endpoints[].id":                   "-> origin.pools[].endpoints[].id",
	"origin_route.pools[].endpoints[].tier":                 "derived: the pool kind",
	"origin_route.pools[].endpoints[].node_id":              "-> origin.pools[].endpoints[].node_id",
	"origin_route.pools[].endpoints[].topology_revision":    "-> origin.pools[].endpoints[].topology_revision",
	"origin_route.pools[].endpoints[].mtls_identity_sha256": "-> origin.pools[].endpoints[].mtls_identity_sha256",
	"origin_route.pools[].endpoints[].host":                 "-> origin.pools[].endpoints[].host",
	"origin_route.pools[].endpoints[].port":                 "-> origin.pools[].endpoints[].port",
	"origin_route.pools[].endpoints[].weight":               "-> origin.pools[].endpoints[].weight",
	"origin_route.default_pool_id":                          "-> origin.default_pool_id",
	"origin_route.default_fallback_pool_id":                 "-> origin.default_fallback_pool_id",
	"origin_route.routes[].id":                              "-> origin.routes[].id",
	"origin_route.routes[].priority":                        "-> origin.routes[].priority",
	"origin_route.routes[].path_prefix":                     "-> origin.routes[].path_prefix",
	"origin_route.routes[].node_regions[]":                  "-> origin.routes[].node_regions (the node evaluates its own region)",
	"origin_route.routes[].client_cidrs[]":                  "-> origin.routes[].client_cidrs",
	"origin_route.routes[].pool_id":                         "-> origin.routes[].pool_id",
	"origin_route.routes[].fallback_pool_id":                "-> origin.routes[].fallback_pool_id",
	"origin_route.retry.methods[]":                          "-> origin.pools[].retry.methods",
	"origin_route.retry.max_attempts":                       "-> origin.pools[].retry.max_attempts (pools the route names)",
	"origin_route.retry.connect_timeout_ms":                 "-> origin.pools[].retry.connect_timeout_ms",
	"origin_route.retry.read_timeout_ms":                    "-> origin.pools[].retry.read_timeout_ms",
	"origin_route.retry.total_budget_ms":                    "-> origin.pools[].retry.total_budget_ms",

	"telemetry.package_subscription_id": "-> telemetry.package_subscription_id",
	"telemetry.capture":                 "-> telemetry.capture",
	"http_policy.edge":                  "-> referenced http_policy object (the site's entry, raw); max_upload_bytes -> limits.max_body_bytes",
}

// Not in the v8 site model at all (facts the caller passes, or not built yet).
var siteObjectV2Outside = map[string]string{
	"error_pages":                    "fact: the scope's errorpagecontrol production snapshot -> siteErrorPageFacts (ErrorPagesFor: global + site, theme style_hash); bodies are referenced error_page_asset objects; node pages (no_host, unknown_site) stay out",
	"origin.auth":                    "fact: originauthcontrol bindings (separate release); credentials are the node-sealed snapshot's per-rule secret objects (originauth secret_objects.go), secret ref = (rule id, publication revision)",
	"listeners[].tls key pair":       "pending: certificate secret objects (dynamic certificate task)",
	"challenge secret":               "unchanged: the challenge secret rollout installs <policy_id>/versions/<n> on the node",
	"limits.max_body_bytes (system)": "0 = the node-level system limit (document system.nginx.client_max_body_bytes stays a node skeleton setting)",
	"security.mounts (rule packs)":   "-> security.mounts, security.resolved_sha256 (site_security_mounts, loadSiteRuleMounts; packs travel as node artifact set items)",
	"placement":                      "pending: site_runtime 10 (ADR 0009 §8.1)",
	"SNI != Host":                    "pending: product decision (ADR 0009 PoC §7)",
}

var siteObjectV2Terminals = map[reflect.Type]bool{
	reflect.TypeFor[edgeconfig.CCV2Policy]():       true,
	reflect.TypeFor[edgeconfig.SecurityPolicy]():   true,
	reflect.TypeFor[edgeconfig.CRSProfileRef]():    true,
	reflect.TypeFor[siteobject.TelemetryCapture](): true,
}

func siteObjectV2FieldPaths(prefix string, value reflect.Type, paths map[string]bool) {
	for value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() == reflect.Slice {
		siteObjectV2FieldPaths(prefix+"[]", value.Elem(), paths)
		return
	}
	if value.Kind() != reflect.Struct || siteObjectV2Terminals[value] {
		paths[prefix] = true
		return
	}
	for index := range value.NumField() {
		field := value.Field(index)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" && field.Anonymous {
			siteObjectV2FieldPaths(prefix, field.Type, paths) // JSON flattens it
			continue
		}
		if name == "" {
			name = field.Name
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		siteObjectV2FieldPaths(path, field.Type, paths)
	}
}

// A field added to the site model fails this test until the table says
// where it goes in cdnca.edge.site/v2; a stale entry fails it too.
func TestSiteObjectsV2FieldCoverage(t *testing.T) {
	paths := map[string]bool{}
	siteObjectV2FieldPaths("", reflect.TypeFor[siteRuntimeV2Site](), paths)
	siteObjectV2FieldPaths("origin_route", reflect.TypeFor[siteOriginRouteDocument](), paths)
	siteObjectV2FieldPaths("telemetry", reflect.TypeFor[siteobject.SiteTelemetry](), paths)
	paths["http_policy.edge"] = true
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		if siteObjectV2Coverage[path] == "" {
			t.Errorf("site model field %s has no cdnca.edge.site/v2 mapping", path)
		}
	}
	for _, path := range slices.Sorted(maps.Keys(siteObjectV2Coverage)) {
		if !paths[path] {
			t.Errorf("coverage entry %s names no site model field", path)
		}
	}
	pending := 0
	for _, note := range siteObjectV2Outside {
		if strings.HasPrefix(note, "pending") {
			pending++
		}
	}
	t.Logf("%d site model fields mapped; %d items outside the v8 model, %d pending", len(paths), len(siteObjectV2Outside), pending)
}
