package edgeconfig

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The embedded v7 capture Lua of cdnca_telemetry.lua is exactly the shared
// body (with the dynamic routing listen_port), so the two runtimes build the
// same capture events.
func TestDynamicRoutingCaptureLuaIsV7(t *testing.T) {
	raw, err := os.ReadFile("../../edge/openresty/dynroute/cdnca_telemetry.lua")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	begin := strings.Index(text, "-- cdnca:capture-begin")
	end := strings.Index(text, "-- cdnca:capture-end")
	if begin < 0 || end < begin {
		t.Fatal("capture markers missing")
	}
	embedded := text[strings.Index(text[begin:], "\n")+begin+1 : end]
	if embedded != DynamicRoutingCaptureLogBody() {
		t.Fatal("cdnca_telemetry.lua capture body differs from edgeconfig.DynamicRoutingCaptureLogBody (regenerate it)")
	}
	if strings.Contains(DynamicRoutingCaptureLogBody(), "ngx.var.server_port") || strings.Contains(DynamicRoutingCaptureLogBody(), "ngx.var.remote_addr") ||
		!strings.Contains(DynamicRoutingCaptureLogBody(), "security.listen_port=tonumber(ngx.var.cdnca_site_port)") {
		t.Fatal("dynamic routing capture must log the selected public port")
	}
	if !strings.Contains(telemetryCaptureLogBody, "security.listen_port=tonumber(ngx.var.server_port)") {
		t.Fatal("v7 capture body changed")
	}
}

var logFormatPattern = regexp.MustCompile(`log_format (\S+) escape=json '([^']*)';`)

func logFormats(t *testing.T, text string) map[string]string {
	t.Helper()
	formats := map[string]string{}
	for _, match := range logFormatPattern.FindAllStringSubmatch(text, -1) {
		formats[match[1]] = match[2]
	}
	return formats
}

// lineFields decodes a log_format template as JSON after replacing each
// $variable by a placeholder, returning the top-level fields in order.
func lineFields(t *testing.T, template string) ([]string, map[string]any) {
	t.Helper()
	filled := regexp.MustCompile(`\$[a-z_0-9]+`).ReplaceAllString(template, "0")
	var fields map[string]any
	if err := json.Unmarshal([]byte(filled), &fields); err != nil {
		t.Fatalf("template is not JSON: %v\n%s", err, filled)
	}
	var order []string
	for _, match := range regexp.MustCompile(`[{,]"([a-z_0-9]+)":`).FindAllStringSubmatch(template, -1) {
		order = append(order, match[1])
	}
	return order, fields
}

// A dynamic routing line carries every v7 field, in the v7 order, from the
// same variables (except the security line's listen_port), plus only the
// attribution object.
func TestDynamicRoutingLinesAreV7Lines(t *testing.T) {
	v7 := logFormats(t, RenderTelemetryHTTP())
	dynamic := logFormats(t, RenderDynamicRoutingTelemetryHTTP())
	for _, pair := range [][2]string{{"cdnca_access_json", "cdnca_access_json"}, {"cdnca_security_json", "cdnca_security_json"}} {
		old, current := v7[pair[0]], dynamic[pair[1]]
		if old == "" || current == "" {
			t.Fatalf("missing format %v", pair)
		}
		oldOrder, _ := lineFields(t, old)
		order, fields := lineFields(t, current)
		attribution, ok := fields[DynamicRoutingAttribution].(map[string]any)
		// generation, scope, digest, port and l2 (fix-l2trust)
		if !ok || len(attribution) != 5 {
			t.Fatalf("%s: attribution %v", pair[1], fields[DynamicRoutingAttribution])
		}
		order = slices.DeleteFunc(order, func(name string) bool {
			return name == DynamicRoutingAttribution || name == "generation" || name == "scope" || name == "digest" || name == "port" || name == "l2"
		})
		if !slices.Equal(order, oldOrder) {
			t.Fatalf("%s fields\n%v\nv7\n%v", pair[1], order, oldOrder)
		}
		expected := strings.TrimSuffix(old, "}")
		if pair[1] == "cdnca_security_json" {
			expected = strings.Replace(expected, `"listen_port":$server_port`, `"listen_port":$cdnca_site_port`, 1)
			expected = strings.Replace(expected, `"path":"$uri"`, dynamicRoutingSecurityPath, 1)
		}
		expected = strings.Replace(expected, `"client_ip":"$remote_addr"`, `"client_ip":"$cdnca_telemetry_client_ip"`, 1)
		if !strings.HasPrefix(current, expected+`,"cdnca":{`) {
			t.Fatalf("%s is not the v7 line plus attribution:\n%s", pair[1], current)
		}
	}
	http := RenderDynamicRoutingTelemetryHTTP()
	// the L1 hop mark is JSON true/false whatever the variable holds
	if !strings.Contains(http, `map $cdnca_l2_trusted $cdnca_telemetry_l2 { "1" true; default false; }`) {
		t.Fatal("missing the L2 hop map")
	}
	if strings.Contains(http, "map $host $cdnca_ja4_log") {
		t.Fatal("$cdnca_ja4_log must be a variable the log phase writes, not a map")
	}
	for _, name := range []string{"$cdnca_telemetry_cache_status", "$cdnca_security_request_class", "$cdnca_origin_connect_us", "$cdnca_security_block_page_log"} {
		if !strings.Contains(http, "map ") || !strings.Contains(http, name+" ") && !strings.Contains(http, name+" {") {
			t.Fatalf("missing map %s", name)
		}
	}
}

func TestDynamicRoutingTelemetryServer(t *testing.T) {
	text, err := RenderDynamicRoutingTelemetryServer("/var/lib/cdnca-edge/shared")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`access_log "/var/lib/cdnca-edge/shared/telemetry/dynroute/access.jsonl" cdnca_access_json if=$cdnca_telemetry_plain;`,
		`access_log "/var/lib/cdnca-edge/shared/telemetry/dynroute/access.jsonl" cdnca_access_capture_json if=$cdnca_telemetry_capture;`,
		`access_log "/var/lib/cdnca-edge/shared/telemetry/dynroute/security.jsonl" cdnca_security_json if=$cdnca_telemetry_security_plain;`,
		`access_log "/var/lib/cdnca-edge/shared/telemetry/dynroute/security.jsonl" cdnca_security_capture_json if=$cdnca_telemetry_security_capture;`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %s in\n%s", want, text)
		}
	}
	for _, bad := range []string{"", "relative", "/a/../b", "/a b", `/a"b`} {
		if _, err := RenderDynamicRoutingTelemetryServer(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	for _, name := range DynamicRoutingTelemetryVariables {
		if strings.HasPrefix(name, "cdnca_site_") {
			t.Fatalf("%s: cdnca_site_* belongs to site selection (contract §1)", name)
		}
	}
}

// sec-log-fix: the security log condition and line read the variables every
// Lua module writes. They drifted apart once ($cdnca_security_* written,
// $cdnca_security_emit read), so no security event reached security.jsonl.
func TestSecurityLogReadsTheVariablesTheModulesWrite(t *testing.T) {
	http := RenderDynamicRoutingTelemetryHTTP()
	for _, want := range []string{
		`map "$cdnca_telemetry:$cdnca_security_emit" $cdnca_telemetry_security_plain`,
		`map "$cdnca_telemetry:$cdnca_security_emit" $cdnca_telemetry_security_capture`,
		`log_format cdnca_security_capture_json escape=none '$cdnca_security_telemetry_json'`,
		`"security_type":"$cdnca_security_type","action":"$cdnca_security_action","severity":"$cdnca_security_severity","rule_id":"$cdnca_security_rule_id"`,
		`map $cdnca_security_block_page $cdnca_security_block_page_log`,
	} {
		if !strings.Contains(http, want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, name := range []string{"cdnca_security_emit", "cdnca_security_type", "cdnca_security_action",
		"cdnca_security_severity", "cdnca_security_rule_id", BlockPageVariable, "cdnca_security_telemetry_json"} {
		if !slices.Contains(DynamicRoutingTelemetryVariables, name) {
			t.Fatalf("%s not declared by the skeleton", name)
		}
	}
	if BlockPageVariable != "cdnca_security_block_page" {
		t.Fatalf("block page variable %s", BlockPageVariable)
	}
	// Writers: default variable names of each module, and no old names.
	writers := map[string]string{
		"../../edge/openresty/ccv2/engine.lua":              `emit = "cdnca_security_emit"`,
		"../../edge/openresty/lua/cdnca_waf.lua":            `emit = "cdnca_security_emit"`,
		"../../edge/openresty/lua/cdnca_rule_interp.lua":    `ngx_var.cdnca_security_emit = "1"`,
		"../../edge/openresty/dynroute/cdnca_security.lua":  `ngx_var.cdnca_security_emit = "1"`,
		"../../edge/openresty/dynroute/cdnca_telemetry.lua": `cdnca_security_emit = "0"`,
		"../../edge/openresty/dynroute/cdnca_limits.lua":    `ngx_var.cdnca_security_block_page = "1"`,
		"../../edge/openresty/lua/cdnca_banlist.lua":        `"cdnca_security_block_page"`,
	}
	old := regexp.MustCompile(`cdnfly_security_(emit|type|action|severity|rule_id|request_class|telemetry_json)\b|cdnfly_block_page`)
	for path, want := range writers {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%s: missing %s", path, want)
		}
		if found := old.FindString(string(raw)); found != "" {
			t.Fatalf("%s still uses %s", path, found)
		}
	}
}

// P14: the security line logs the path with its redacted query
// ($cdnca_security_path, written by the log phase before the line), the
// access line keeps $uri; the plain, aggregated and capture security events
// all read the same variable.
func TestDynamicRoutingSecurityLineLogsRedactedQuery(t *testing.T) {
	formats := logFormats(t, RenderDynamicRoutingTelemetryHTTP())
	if !strings.Contains(formats["cdnca_security_json"], `"path":"$cdnca_security_path"`) ||
		strings.Contains(formats["cdnca_security_json"], `"path":"$uri"`) {
		t.Fatalf("security line path: %s", formats["cdnca_security_json"])
	}
	if !strings.Contains(formats["cdnca_access_json"], `"path":"$uri"`) {
		t.Fatal("access line must keep $uri")
	}
	if !slices.Contains(DynamicRoutingTelemetryVariables, "cdnca_security_path") {
		t.Fatal("cdnca_security_path not declared by the skeleton")
	}
	if !strings.Contains(DynamicRoutingCaptureLogBody(), "security.path=ngx.var.cdnca_security_path") ||
		strings.Contains(telemetryCaptureLogBody, "cdnca_security_path") {
		t.Fatal("dynamic routing capture security event must use the redacted path (v7 unchanged)")
	}
	raw, err := os.ReadFile("../../edge/openresty/dynroute/cdnca_telemetry.lua")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		`',"path":' .. json_string(v.cdnca_security_path)`,
		`ngx_var.cdnca_security_path = security_path(ngx_var.uri, ngx_var.args)`,
		`local SECURITY_QUERY_BYTES = 512`,
		`password = true, passwd = true, pwd = true, token = true, access_token = true, secret = true,`,
		`key = true, sign = true, signature = true, auth = true, session = true, cookie = true, code = true,`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("cdnca_telemetry.lua missing %s", want)
		}
	}
	// the variable is written before the capture and aggregate paths read it
	if strings.Index(text, "ngx_var.cdnca_security_path = security_path(") > strings.Index(text, "pcall(count_aggregate") {
		t.Fatal("cdnca_security_path must be set before the aggregate line is built")
	}
}
