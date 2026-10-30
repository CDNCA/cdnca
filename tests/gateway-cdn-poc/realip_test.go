package main

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	ranges, err := parseTrusted("127.0.0.1/32=X-Forwarded-For,173.245.48.0/20=CF-Connecting-IP")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote string
		header       http.Header
		ip, source   string
	}{
		{"untrusted peer ignores every header", "[::1]:5000",
			http.Header{"X-Forwarded-For": {"203.0.113.9"}, "Cf-Connecting-Ip": {"203.0.113.9"}}, "::1", "tcp"},
		{"trusted generic CDN: rightmost untrusted XFF hop", "127.0.0.1:5000",
			http.Header{"X-Forwarded-For": {"203.0.113.9, 198.51.100.7"}}, "198.51.100.7", "trusted_proxy"},
		{"trusted hops on the right are skipped", "127.0.0.1:5000",
			http.Header{"X-Forwarded-For": {"198.51.100.7, 127.0.0.1"}}, "198.51.100.7", "trusted_proxy"},
		{"header not bound to the range is ignored", "127.0.0.1:5000",
			http.Header{"Cf-Connecting-Ip": {"203.0.113.9"}}, "127.0.0.1", "tcp"},
		{"cloudflare range uses CF-Connecting-IP only", "173.245.48.1:443",
			http.Header{"Cf-Connecting-Ip": {"198.51.100.7"}, "X-Forwarded-For": {"203.0.113.9"}}, "198.51.100.7", "trusted_proxy"},
		{"malformed hop stops the walk", "127.0.0.1:5000",
			http.Header{"X-Forwarded-For": {"198.51.100.7, bogus"}}, "127.0.0.1", "tcp"},
		{"trusted peer without header keeps the peer", "127.0.0.1:5000", http.Header{}, "127.0.0.1", "tcp"},
	}
	for _, c := range cases {
		ip, source := clientIP(c.remote, c.header, ranges)
		if ip != c.ip || source != c.source {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, ip, source, c.ip, c.source)
		}
	}
}
