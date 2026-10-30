package edgeconfig

import (
	"regexp"
	"strings"
	"testing"
)

// ge-analytics: the access log carries the transfer time ($request_time in
// microseconds) so bandwidth peak/95th can spread a response over it.
func TestAccessLogCarriesTransferDuration(t *testing.T) {
	var capture strings.Builder
	renderTelemetryCaptureLogLua(&capture, TelemetryCapturePolicy{})
	config := RenderTelemetryHTTP() + capture.String()
	for _, value := range []string{
		"map $request_time $cdnca_duration_us {",
		`"response_bytes":$bytes_sent,"duration_us":$cdnca_duration_us,`,
		"access.duration_us=tonumber(ngx.var.cdnca_duration_us) or 0",
	} {
		if !strings.Contains(config, value) {
			t.Errorf("generated config is missing %q", value)
		}
	}
}

// The map must turn every $request_time nginx writes (%T.%03d) into whole
// microseconds and never emit an invalid JSON number.
func TestTransferDurationMapConvertsRequestTime(t *testing.T) {
	var output strings.Builder
	renderTelemetryDurationMap(&output)
	type entry struct {
		pattern *regexp.Regexp
		value   string
	}
	var entries []entry
	fallback := ""
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "default ") {
			fallback = strings.TrimSuffix(strings.TrimPrefix(line, "default "), ";")
			continue
		}
		if !strings.HasPrefix(line, "~") && !strings.HasPrefix(line, `"~`) {
			continue
		}
		index := strings.LastIndex(line, " ")
		pattern := strings.Trim(line[:index], `"`)[1:]
		entries = append(entries, entry{regexp.MustCompile(pattern), strings.TrimSuffix(line[index+1:], ";")})
	}
	resolve := func(input string) string {
		for _, item := range entries {
			if match := item.pattern.FindStringSubmatchIndex(input); match != nil {
				return string(item.pattern.ExpandString(nil, strings.NewReplacer("${", "${").Replace(item.value), input, match))
			}
		}
		return fallback
	}
	for input, want := range map[string]string{
		"0.000": "0", "0.004": "4000", "0.040": "40000", "0.400": "400000", "1.000": "1000000",
		"100.250": "100250000", "86400.000": "86400000000", "-": "0", "": "0", "1.5": "0",
	} {
		if got := resolve(input); got != want {
			t.Errorf("$request_time %q -> %q, want %q", input, got, want)
		}
	}
}
