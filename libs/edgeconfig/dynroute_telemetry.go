package edgeconfig

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Dynamic routing telemetry (ADR 0009 D12, docs/edge/dynroute-telemetry.md):
// every shared server writes one node-level access log and one security log.
// A line is the v7 line (telemetryAccessJSON / telemetrySecurityJSON, the
// same field list) plus an attribution object "cdnca" naming the site the
// request selected (generation, scope, site object digest, public port). The
// Agent turns it back into the v7 line of that site (config_version_id from
// its attribution registry, "cdnca" removed) before the event spool, so the
// control plane sees one format from both runtimes.

const (
	// DynamicRoutingTelemetryDir is the node-level log directory under the
	// shared root (<deployment root>/shared, the skeleton's Paths.SharedRoot).
	DynamicRoutingTelemetryDir = "telemetry/dynroute"
	// DynamicRoutingAttribution is the key of the attribution object.
	DynamicRoutingAttribution = "cdnca"
)

// DynamicRoutingTelemetryVariables are the variables the log phase
// (cdnca_telemetry.lua) writes; the skeleton declares them in its never
// executed variables location. $cdnca_* are the v7 names the shared log line
// reads; $cdnca_telemetry is "plain" or "capture" for a request that is
// logged, unset otherwise (unknown Host, index not ready).
var DynamicRoutingTelemetryVariables = []string{
	"cdnca_telemetry", "cdnca_telemetry_client_ip",
	"cdnca_tenant_id", "cdnca_config_version_id", "cdnca_node_id", "cdnca_ja4_log",
	"cdnca_access_telemetry_json", "cdnca_security_telemetry_json",
	"cdnca_security_emit", "cdnca_security_type", "cdnca_security_action", "cdnca_security_severity",
	"cdnca_security_rule_id", BlockPageVariable,
	// Attack evidence (ge-waf S4), read by the security line.
	"cdnca_security_policy_id", "cdnca_security_detector", "cdnca_security_matched", "cdnca_security_body",
	// Aggregated decisions (sec-log-agg): set by CC, counted by the log
	// phase; the flush server's line marker.
	"cdnca_security_aggregate", "cdnca_security_flush",
	// The security line's path: $uri plus the redacted query (P14,
	// cdnca_telemetry.security_path).
	"cdnca_security_path",
	// "1" for an L1's hop this node serves as its L2 (fix-l2trust, written
	// by cdnca_dynroute; the skeleton declares it with its module
	// variables, a duplicate name is declared once)
	"cdnca_l2_trusted",
}

// dynamicRoutingSecurityPath is the security line's path on a shared server:
// the request path plus its query, sensitive values masked and the query cut
// to 512 bytes by the log phase (cdnca_telemetry.security_path), so a WAF
// event shows what was requested without logging secrets. The access line
// keeps $uri.
const dynamicRoutingSecurityPath = `"path":"$cdnca_security_path"`

// DynamicRoutingSecurityFlushPath is the flush server's location
// (cdnca_telemetry.AGGREGATE_FLUSH_PATH).
const DynamicRoutingSecurityFlushPath = "/__cdnca_security_flush"

// dynamicRoutingAttributionJSON is appended to a plain line. Every variable
// is written by site selection (contract §1) for a logged request.
// "l2" is true for an L1's hop this node served as its L2 (fix-l2trust,
// $cdnca_l2_trusted): the Agent skips the line, the L1 logged the visitor's
// request.
const dynamicRoutingAttributionJSON = `,"cdnca":{"generation":$cdnca_site_generation,"scope":"$cdnca_site_scope","digest":"$cdnca_site_digest","port":$cdnca_site_port,"l2":$cdnca_telemetry_l2}}`

// dynamicRoutingLine is a v7 line with the attribution object. On a shared
// server $server_port is the socket port (empty on a mux socket), so the
// security line's listen_port is the selected public port instead.
//
// client_ip is the visitor by the site's trusted proxy chain
// ($cdnca_telemetry_client_ip, cdnca_origin.client_ip(): a trusted peer's
// X-Real-IP, else the peer), the address the origin is told about; v7 logs
// $remote_addr (the peer) even for a trusted proxy.
func dynamicRoutingLine(v7 string) string {
	line := strings.Replace(v7, `"listen_port":$server_port`, `"listen_port":$cdnca_site_port`, 1)
	line = strings.Replace(line, `"client_ip":"$remote_addr"`, `"client_ip":"$cdnca_telemetry_client_ip"`, 1)
	return strings.TrimSuffix(line, "}") + dynamicRoutingAttributionJSON
}

// RenderDynamicRoutingTelemetryHTTP is the http{} level telemetry of the
// node skeleton: the v7 maps, the log formats and the maps choosing which
// format logs a request.
func RenderDynamicRoutingTelemetryHTTP() string {
	var output strings.Builder
	renderTelemetryMaps(&output, false)
	output.WriteString("  map $cdnca_l2_trusted $cdnca_telemetry_l2 { \"1\" true; default false; }\n")
	output.WriteString("  map $cdnca_telemetry $cdnca_telemetry_plain { plain 1; default 0; }\n")
	output.WriteString("  map $cdnca_telemetry $cdnca_telemetry_capture { capture 1; default 0; }\n")
	output.WriteString("  map \"$cdnca_telemetry:$cdnca_security_emit\" $cdnca_telemetry_security_plain { plain:1 1; default 0; }\n")
	output.WriteString("  map \"$cdnca_telemetry:$cdnca_security_emit\" $cdnca_telemetry_security_capture { capture:1 1; default 0; }\n")
	output.WriteString("  log_format cdnca_access_json escape=json '" + dynamicRoutingLine(telemetryAccessJSON) + "';\n")
	security := strings.Replace(dynamicRoutingLine(telemetrySecurityJSON), `"path":"$uri"`, dynamicRoutingSecurityPath, 1)
	output.WriteString("  log_format cdnca_security_json escape=json '" + security + "';\n")
	output.WriteString("  log_format cdnca_access_capture_json escape=none '$cdnca_access_telemetry_json';\n")
	output.WriteString("  log_format cdnca_security_capture_json escape=none '$cdnca_security_telemetry_json';\n")
	return output.String()
}

// DynamicRoutingTelemetryPaths are the node-level access and security logs
// under sharedRoot.
func DynamicRoutingTelemetryPaths(sharedRoot string) (access, security string) {
	directory := filepath.Join(sharedRoot, filepath.FromSlash(DynamicRoutingTelemetryDir))
	return filepath.Join(directory, "access.jsonl"), filepath.Join(directory, "security.jsonl")
}

// RenderDynamicRoutingTelemetryServer is the access_log directives of one
// shared server (sharedRoot absolute and clean). A request is logged once,
// in the plain or the capture format of its site.
func RenderDynamicRoutingTelemetryServer(sharedRoot string) (string, error) {
	if !safeAbsolutePath(sharedRoot) {
		return "", ErrInvalidConfig
	}
	access, security := DynamicRoutingTelemetryPaths(sharedRoot)
	var output strings.Builder
	fmt.Fprintf(&output, "    access_log %s cdnca_access_json if=$cdnca_telemetry_plain;\n", nginxTelemetryQuote(access))
	fmt.Fprintf(&output, "    access_log %s cdnca_access_capture_json if=$cdnca_telemetry_capture;\n", nginxTelemetryQuote(access))
	fmt.Fprintf(&output, "    access_log %s cdnca_security_json if=$cdnca_telemetry_security_plain;\n", nginxTelemetryQuote(security))
	fmt.Fprintf(&output, "    access_log %s cdnca_security_capture_json if=$cdnca_telemetry_security_capture;\n", nginxTelemetryQuote(security))
	return output.String(), nil
}

// DynamicRoutingCaptureLogBody is the v7 capture log Lua the dynamic routing
// log phase runs (cdnca_telemetry.lua embeds it between markers;
// TestDynamicRoutingCaptureLuaIsV7 keeps the two identical), with two changes
// as in the plain line: the security event's listen_port is the selected
// public port ($server_port is the socket's, empty on a mux socket), and
// client_ip the trusted-proxy-chain client.
func DynamicRoutingCaptureLogBody() string {
	body := strings.Replace(telemetryCaptureLogBody, "security.listen_port=tonumber(ngx.var.server_port)",
		"security.listen_port=tonumber(ngx.var.cdnca_site_port)", 1)
	body = strings.Replace(body, "client_ip=ngx.var.remote_addr", "client_ip=ngx.var.cdnca_telemetry_client_ip", 1)
	return strings.Replace(body, "security.request_class=ngx.var.cdnca_security_request_class",
		"security.request_class=ngx.var.cdnca_security_request_class; security.path=ngx.var.cdnca_security_path", 1)
}

// Capture policy defaults (normalizeTelemetryCapturePolicy) for a site object
// capture whose limits are 0.
const (
	DefaultCaptureValueBytes = defaultCaptureValueBytes
	DefaultCaptureBodyBytes  = defaultCaptureBodyBytes
	DefaultCaptureEventBytes = defaultCaptureEventBytes
)
