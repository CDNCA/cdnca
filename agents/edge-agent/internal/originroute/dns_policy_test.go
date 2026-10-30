package originroute

import (
	"errors"
	"strings"
	"testing"
)

func TestOriginDNSHostnameIsCanonicalAndDefaultsAreBounded(t *testing.T) {
	policy := testPolicy()
	policy.Pools[1].Endpoints[0].Host = "Origin.Example.COM."

	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, pool := range normalized.Pools {
		if pool.ID == "origin-b" {
			got = pool.Endpoints[0].Host
		}
	}
	if got != "origin.example.com" {
		t.Fatalf("normalized hostname = %q", got)
	}
	if normalized.DNS == nil {
		t.Fatal("hostname policy did not materialize bounded DNS defaults")
	}
	if normalized.DNS.Resolver != "" ||
		normalized.DNS.QueryTimeoutMS != DefaultDNSQueryTimeoutMS ||
		normalized.DNS.MinTTLSeconds != DefaultDNSMinTTLSeconds ||
		normalized.DNS.MaxTTLSeconds != DefaultDNSMaxTTLSeconds ||
		normalized.DNS.StaleTTLSeconds != DefaultDNSStaleTTLSeconds {
		t.Fatalf("unexpected DNS defaults: %+v", normalized.DNS)
	}

	shuffled := policy
	shuffled.Pools = append([]Pool(nil), policy.Pools...)
	shuffled.Pools[1].Endpoints = append([]Endpoint(nil), policy.Pools[1].Endpoints...)
	shuffled.Pools[1].Endpoints[0].Host = "origin.example.com"
	left, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Canonical(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("hostname spelling changed canonical policy:\n%s\n%s", left, right)
	}
}

func TestOriginDNSHostnameValidationRejectsAmbiguousAndReverseNames(t *testing.T) {
	invalidHosts := []string{
		"localhost",
		"2.0.192.in-addr.arpa",
		"b.a.9.8.7.6.5.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
		"bad..example",
		"-bad.example",
		"bad-.example",
		"1.2.3.999",
		strings.Repeat("a", 64) + ".example",
		"origin.ex\u00e4mple",
	}
	for _, host := range invalidHosts {
		t.Run(host, func(t *testing.T) {
			policy := testPolicy()
			policy.Pools[1].Endpoints[0].Host = host
			if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Normalize(%q) error = %v", host, err)
			}
		})
	}

	policy := testPolicy()
	policy.Pools[2].Endpoints[0].Host = "l2.example.com"
	if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("L2 DNS endpoint error = %v", err)
	}
}

func TestOriginDNSExpertPolicyIsExplicitAndStrict(t *testing.T) {
	policy := testPolicy()
	policy.Pools[1].Endpoints[0].Host = "origin.example.com"
	policy.DNS = &DNSPolicy{
		Resolver: "2001:4860:4860::8888", QueryTimeoutMS: 750,
		MinTTLSeconds: 2, MaxTTLSeconds: 600, StaleTTLSeconds: 1200,
	}
	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	if *normalized.DNS != *policy.DNS {
		t.Fatalf("normalized DNS policy = %+v", normalized.DNS)
	}

	tests := []struct {
		name   string
		mutate func(*DNSPolicy)
	}{
		{"resolver must be an IP", func(value *DNSPolicy) { value.Resolver = "dns.example.com" }},
		{"timeout too low", func(value *DNSPolicy) { value.QueryTimeoutMS = 99 }},
		{"timeout too high", func(value *DNSPolicy) { value.QueryTimeoutMS = 5001 }},
		{"minimum zero", func(value *DNSPolicy) { value.MinTTLSeconds = 0 }},
		{"maximum below minimum", func(value *DNSPolicy) { value.MaxTTLSeconds = 1 }},
		{"maximum too high", func(value *DNSPolicy) { value.MaxTTLSeconds = 86401 }},
		{"stale zero", func(value *DNSPolicy) { value.StaleTTLSeconds = 0 }},
		{"stale too high", func(value *DNSPolicy) { value.StaleTTLSeconds = 86401 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := testPolicy()
			candidate.Pools[1].Endpoints[0].Host = "origin.example.com"
			value := *policy.DNS
			test.mutate(&value)
			candidate.DNS = &value
			if _, err := Normalize(candidate); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Normalize() error = %v", err)
			}
		})
	}
}

func TestOriginDNSIngressBindingRequiresBothAddressFamilies(t *testing.T) {
	policy := testPolicy()
	policy.Pools[1].Endpoints[0].Host = "origin.example.com"
	policy.Listeners[0].IngressSourceIPv4 = "127.0.0.1"
	if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("single-family source binding error = %v", err)
	}
	policy.Listeners[0].IngressSourceIPv6 = "::1"
	if _, err := Normalize(policy); err != nil {
		t.Fatalf("dual-stack source binding rejected: %v", err)
	}
}
