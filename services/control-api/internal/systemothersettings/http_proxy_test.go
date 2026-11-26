package systemothersettings

import (
	"strings"
	"testing"
)

// The http代理 password never appears in a read; legacy free text reads as direct.
func TestHTTPProxyRedactedAndLegacyTextDirect(t *testing.T) {
	value := DefaultSettings()
	value.HTTPProxy = "http://ops:s3cret@proxy.example:3128"
	if err := settingsFieldError(value); err != nil {
		t.Fatalf("valid proxy refused: %v", err)
	}
	shown := redacted(value)
	if strings.Contains(shown.HTTPProxy, "s3cret") || shown.HTTPProxy != "http://ops:********@proxy.example:3128" {
		t.Fatalf("redacted proxy = %q", shown.HTTPProxy)
	}
	if value.HTTPProxy != "http://ops:s3cret@proxy.example:3128" {
		t.Fatalf("redacted changed the saved value: %q", value.HTTPProxy)
	}
	for _, raw := range []string{"proxy.example:3128", "127.0.0.1"} {
		decoded, err := decodeSettings([]byte(`{"http_proxy":"` + raw + `"}`))
		if err != nil || decoded.HTTPProxy != "" || !validSettings(decoded) {
			t.Fatalf("legacy %q decoded=(%q,%v), want direct", raw, decoded.HTTPProxy, err)
		}
	}
}
