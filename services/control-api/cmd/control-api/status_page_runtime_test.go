package main

import "testing"

func TestConsoleProbeURL(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"override wins", map[string]string{"CDNCA_STATUS_CONSOLE_PROBE_URL": " https://x.example/ ", "PAYMENT_CHANNELS_NOTIFY_BASE": "https://c.example"}, "https://x.example/"},
		{"public origin", map[string]string{"PAYMENT_CHANNELS_NOTIFY_BASE": "https://c.example:8443/"}, "https://c.example:8443/dashboard/"},
		{"loopback fallback", map[string]string{}, "https://127.0.0.1/dashboard/"},
		{"non-https origin ignored", map[string]string{"PAYMENT_CHANNELS_NOTIFY_BASE": "http://c.example"}, "https://127.0.0.1/dashboard/"},
	} {
		if got := consoleProbeURL(func(key string) string { return tc.env[key] }); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
