package edgeconfig

import (
	"fmt"
	"strings"
)

// This file holds the per-site telemetry and ACME HTTP-01 directives shared
// by the legacy renderer and the site runtime v2 renderer (agents/edge-agent
// siteruntimev2), so both produce byte-identical log formats, variables and
// log paths and the control plane never distinguishes the two.

// renderURLAuthTelemetryDefaults defines the URL auth log variables that
// cdnca_url_auth_json references, for a renderer without URL auth.
func renderURLAuthTelemetryDefaults(output *strings.Builder) {
	output.WriteString("  map $request_id $cdnca_urlauth_trace_id { default \"\"; }\n")
	output.WriteString("  map $request_id $cdnca_urlauth_action { default \"\"; }\n")
	output.WriteString("  map $request_id $cdnca_urlauth_reason { default \"\"; }\n")
	output.WriteString("  map $request_id $cdnca_urlauth_status { default 0; }\n")
	output.WriteString("  map $request_id $cdnca_urlauth_policy_version { default 0; }\n")
	output.WriteString("  map $request_id $cdnca_urlauth_policy_event { default \"\"; }\n")
}

// renderTelemetryServer writes one site server's telemetry identity variables
// and its access and security log directives.
func renderTelemetryServer(output *strings.Builder, tenantID, siteID, packageSubscriptionID, configVersionID, accessLog, securityLog string, capture bool) {
	fmt.Fprintf(output, "    set $cdnca_tenant_id %s;\n", nginxTelemetryQuote(tenantID))
	fmt.Fprintf(output, "    set $cdnca_site_id %s;\n", nginxTelemetryQuote(siteID))
	fmt.Fprintf(output, "    set $cdnca_package_subscription_id %s;\n", nginxTelemetryQuote(packageSubscriptionID))
	fmt.Fprintf(output, "    set $cdnca_config_version_id %s;\n", nginxTelemetryQuote(configVersionID))
	output.WriteString("    set $cdnca_node_id \"\";\n")
	renderTelemetryJA4(output)
	output.WriteString("    set $cdnca_security_emit 0;\n    set $cdnca_security_type \"\";\n    set $cdnca_security_action \"\";\n    set $cdnca_security_severity \"\";\n    set $cdnca_security_rule_id \"\";\n")
	// Attack evidence (ge-waf S4): the deciding policy, detector, matched
	// fragment and request body excerpt (SecurityEvidenceLua fills them in the
	// log phase).
	output.WriteString("    set $cdnca_security_policy_id \"\";\n    set $cdnca_security_detector \"\";\n    set $cdnca_security_matched \"\";\n    set $cdnca_security_body \"\";\n")
	fmt.Fprintf(output, "    set $%s 0;\n", BlockPageVariable)
	output.WriteString("    set $cdnca_access_telemetry_json '{\"schema_version\":0}';\n")
	output.WriteString("    set $cdnca_security_telemetry_json '{\"schema_version\":0}';\n")
	if capture {
		fmt.Fprintf(output, "    access_log %s cdnca_access_capture_json;\n", nginxTelemetryQuote(accessLog))
		fmt.Fprintf(output, "    access_log %s cdnca_security_capture_json if=$cdnca_security_emit;\n", nginxTelemetryQuote(securityLog))
	} else {
		fmt.Fprintf(output, "    access_log %s cdnca_access_json;\n", nginxTelemetryQuote(accessLog))
		fmt.Fprintf(output, "    access_log %s cdnca_security_json if=$cdnca_security_emit;\n", nginxTelemetryQuote(securityLog))
	}
}

// renderACMEHTTP01Location writes the ACME HTTP-01 overlay marker and the
// challenge location the acmehttp01 overlay manager serves from.
func renderACMEHTTP01Location(output *strings.Builder, stateRoot string) {
	fmt.Fprintf(output, "    %s\n", ACMEHTTP01RouteMarker)
	output.WriteString("    location ~ \"^/\\.well-known/acme-challenge/(?<cdnca_acme_token>[A-Za-z0-9_-]{22,256})$\" {\n")
	output.WriteString("      default_type text/plain;\n")
	output.WriteString("      add_header Cache-Control \"no-store\" always;\n")
	fmt.Fprintf(output, "      root %s;\n", ACMEHTTP01OverlayRoot(stateRoot))
	output.WriteString("      try_files /$host/$cdnca_acme_token =404;\n")
	output.WriteString("    }\n")
}

// RenderTelemetryHTTP is the http{} level telemetry of a renderer without URL
// auth: the URL auth defaults, the maps and every log_format.
func RenderTelemetryHTTP() string {
	var output strings.Builder
	renderURLAuthTelemetryDefaults(&output)
	renderTelemetryFormats(&output)
	return output.String()
}

// TelemetryServer is one site listener's signed telemetry identity
// (telemetry/identity-v1.json) as a site server renders it.
type TelemetryServer struct {
	TenantID              string
	SiteID                string
	PackageSubscriptionID string
	ConfigVersionID       string
	AccessLogPath         string
	SecurityLogPath       string
	Capture               TelemetryCapturePolicy
}

// RenderTelemetryServer is the server{} level telemetry of one site listener,
// the same directives the legacy renderer writes.
func RenderTelemetryServer(server TelemetryServer) string {
	var output strings.Builder
	renderTelemetryServer(&output, server.TenantID, server.SiteID, server.PackageSubscriptionID, server.ConfigVersionID,
		server.AccessLogPath, server.SecurityLogPath, server.Capture.Enabled)
	return output.String()
}

// RenderTelemetryCaptureHooks is the capture of a site whose capture policy
// is enabled ("", "" otherwise): bodyFilter is a server level
// body_filter_by_lua_block ("" without response body fields) and logLua the
// statements the server's one log_by_lua_block runs. Both sit at server
// level (site runtime v2), so a request refused before any location (CC v2
// server_rewrite) is captured too and no location hook replaces the server's
// other log statements (CC v2 SEC-11 / auto switch).
func RenderTelemetryCaptureHooks(policy TelemetryCapturePolicy) (bodyFilter, logLua string) {
	if !policy.Enabled {
		return "", ""
	}
	var filter, log strings.Builder
	if len(policy.ResponseBodyFieldAllowlist) > 0 {
		filter.WriteString("    body_filter_by_lua_block {\n")
		renderTelemetryCaptureBodyFilterLua(&filter, policy)
		filter.WriteString("    }\n")
	}
	renderTelemetryCaptureLogLua(&log, policy)
	return filter.String(), log.String()
}

// RenderACMEHTTP01Location is the ACME HTTP-01 overlay marker and challenge
// location of one site server; stateRoot is the deployment root.
func RenderACMEHTTP01Location(stateRoot string) string {
	var output strings.Builder
	renderACMEHTTP01Location(&output, stateRoot)
	return output.String()
}

// TelemetryCapturePolicyFromManifest is a signed manifest capture policy in
// the form the renderer takes, normalized as the legacy renderer normalizes it.
func TelemetryCapturePolicyFromManifest(policy TelemetrySiteCapturePolicy) (TelemetryCapturePolicy, error) {
	if !validManifestCapturePolicy(policy) {
		return TelemetryCapturePolicy{}, ErrInvalidConfig
	}
	return normalizeTelemetryCapturePolicy(TelemetryCapturePolicy{
		SchemaVersion: telemetryCaptureSchemaVersion, Revision: policy.Revision,
		EvidenceDigest: policy.EvidenceDigest, Enabled: policy.Enabled,
		Methods: policy.Methods, URIPrefixes: policy.URIPrefixes,
		RequestHeaderAllowlist: policy.RequestHeaderAllowlist, ResponseHeaderAllowlist: policy.ResponseHeaderAllowlist,
		RequestBodyFieldAllowlist: policy.RequestBodyFieldAllowlist, ResponseBodyFieldAllowlist: policy.ResponseBodyFieldAllowlist,
		MaxValueBytes: policy.MaxValueBytes, MaxBodyBytes: policy.MaxBodyBytes, MaxEventBytes: policy.MaxEventBytes,
	})
}
