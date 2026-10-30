package edgeconfig

import (
	"regexp"
	"strings"
	"testing"
)

// fix-upstreamaddr：访问日志带回源地址 upstream_addr（$upstream_addr 截到 64 字节），
// 与诊断码 upstream_result 分开；只在访问行，安全行没有。
func TestTelemetryAccessLineCarriesUpstreamAddr(t *testing.T) {
	for name, text := range map[string]string{"v7": RenderTelemetryHTTP(), "dynroute": RenderDynamicRoutingTelemetryHTTP()} {
		formats := logFormats(t, text)
		if !strings.Contains(formats["cdnca_access_json"], `"upstream_addr":"$cdnca_upstream_addr_log"`) {
			t.Fatalf("%s: access line lacks upstream_addr: %s", name, formats["cdnca_access_json"])
		}
		if strings.Contains(formats["cdnca_access_json"], `"upstream_result"`) {
			t.Fatalf("%s: access line must not write upstream_result (diagnostic code)", name)
		}
		if strings.Contains(formats["cdnca_security_json"], "upstream_addr") {
			t.Fatalf("%s: security line carries upstream_addr", name)
		}
		if !strings.Contains(text, `map $upstream_addr $cdnca_upstream_addr_log {`) {
			t.Fatalf("%s: $cdnca_upstream_addr_log map missing", name)
		}
	}
}

// map 的正则：≤64 字节、不以空格/逗号结尾（agent validBounded 要求无首尾空白）。
func TestUpstreamAddrMapBound(t *testing.T) {
	match := regexp.MustCompile(`map \$upstream_addr \$cdnca_upstream_addr_log \{ "~\^\(\?<cdnca_upaddr>([^"]*)\)" \$cdnca_upaddr; default ""; \}`).
		FindStringSubmatch(RenderTelemetryHTTP())
	if match == nil {
		t.Fatal("map shape changed")
	}
	pattern := regexp.MustCompile("^(" + match[1] + ")")
	for input, want := range map[string]string{
		"127.0.0.1:8080":                          "127.0.0.1:8080",
		"10.0.0.1:80, 10.0.0.2:80":                "10.0.0.1:80, 10.0.0.2:80",
		"10.0.0.1:80 : 10.0.0.2:80":               "10.0.0.1:80 : 10.0.0.2:80",
		"[2001:db8::1]:443":                       "[2001:db8::1]:443",
		strings.Repeat("a", 70):                   strings.Repeat("a", 64),
		strings.Repeat("a", 63) + ", 10.0.0.2:80": strings.Repeat("a", 63),
		"": "",
	} {
		got := pattern.FindString(input)
		if got != want || len(got) > 64 || strings.TrimSpace(got) != got {
			t.Fatalf("%q -> %q, want %q", input, got, want)
		}
	}
}

// capture 模式（Lua）：变量存在就写 upstream_addr（未回源为 ""，与 plain 行一致）；旧 agent
// 渲染的配置没有该变量，ngx.var 读出 nil，不写键，旧 agent 不会隔离日志行。
func TestTelemetryCaptureLuaUpstreamAddrOptional(t *testing.T) {
	for name, body := range map[string]string{"v7": telemetryCaptureLogBody, "dynroute": DynamicRoutingCaptureLogBody()} {
		if !strings.Contains(body, "local upstream_addr = ngx.var.cdnca_upstream_addr_log") ||
			!strings.Contains(body, `if upstream_addr ~= nil then access.upstream_addr = upstream_addr end`) {
			t.Fatalf("%s: capture Lua lacks optional upstream_addr", name)
		}
		if strings.Contains(body, "security.upstream_addr") || strings.Contains(body, "common.upstream_addr") ||
			strings.Contains(body, "upstream_addr=upstream_addr") {
			t.Fatalf("%s: upstream_addr must be on the access event only", name)
		}
	}
}
