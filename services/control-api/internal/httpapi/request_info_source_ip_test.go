package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The native installer places control-api behind the local nginx on loopback.
// Session source IPs must come from the proxy-supplied client address when the
// peer is trusted, and must never be taken from forwarding headers otherwise.
func TestRequestInfoSourceIPHonoursTrustedLoopbackProxy(t *testing.T) {
	trusted := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), APIKeyTrustedProxyCIDRs: []string{"127.0.0.1/32", "::1/128"}})
	if trusted.initializationErr != nil {
		t.Fatal(trusted.initializationErr)
	}
	untrusted := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)})
	if untrusted.initializationErr != nil {
		t.Fatal(untrusted.initializationErr)
	}
	for _, test := range []struct {
		name   string
		server *Server
		remote string
		xff    []string
		want   string
	}{
		{name: "trusted proxy forwards client", server: trusted, remote: "127.0.0.1:51234", xff: []string{"203.0.113.61"}, want: "203.0.113.61"},
		{name: "trusted ipv6 loopback proxy", server: trusted, remote: "[::1]:51234", xff: []string{"2001:db8::7"}, want: "2001:db8::7"},
		{name: "client spoof is ignored behind trusted proxy", server: trusted, remote: "127.0.0.1:51234", xff: []string{"198.51.100.9, 203.0.113.61"}, want: "203.0.113.61"},
		{name: "trusted proxy without forwarding header", server: trusted, remote: "127.0.0.1:51234", want: ""},
		{name: "direct untrusted client", server: trusted, remote: "203.0.113.4:443", want: "203.0.113.4"},
		{name: "untrusted peer with forwarding header", server: trusted, remote: "203.0.113.4:443", xff: []string{"203.0.113.61"}, want: ""},
		{name: "no trusted proxies keeps the current drop behaviour", server: untrusted, remote: "127.0.0.1:51234", xff: []string{"203.0.113.61"}, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
			request.RemoteAddr = test.remote
			for _, value := range test.xff {
				request.Header.Add("X-Forwarded-For", value)
			}
			if got := test.server.requestInfo(request).SourceIP; got != test.want {
				t.Fatalf("SourceIP = %q, want %q", got, test.want)
			}
		})
	}
}
