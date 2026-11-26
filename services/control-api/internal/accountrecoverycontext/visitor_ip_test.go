package accountrecoverycontext

import (
	"net/netip"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/clientip"
)

// the visitor address the 源IP请求头 setting gave
// (clientip.WithVisitor, httpapi WithClientSourceIP) is the source IP of the
// login, CAPTCHA, API key and billing bridge limits; without it the
// trusted-proxy rules decide as before.
func TestSourceIPResolverPrefersTheVisitorAddress(t *testing.T) {
	resolver, err := NewSourceIPResolver([]string{"127.0.0.1/32"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := newRequest("console.example.com", "127.0.0.1:41000")
	request.Header.Set("X-Forwarded-For", "198.51.100.200")
	if got, err := resolver.ResolveSourceIP(request); err != nil || got != netip.MustParseAddr("198.51.100.200") {
		t.Fatalf("without visitor: %s %v", got, err)
	}
	visitor := netip.MustParseAddr("203.0.113.9")
	withVisitor := request.WithContext(clientip.WithVisitor(request.Context(), visitor))
	if got, err := resolver.ResolveSourceIP(withVisitor); err != nil || got != visitor {
		t.Fatalf("with visitor: %s %v", got, err)
	}
	// A direct untrusted peer with forwarding headers is refused only without a visitor address.
	spoofed := newRequest("console.example.com", "192.0.2.7:41000")
	spoofed.Header.Set("X-Forwarded-For", "198.51.100.200")
	if _, err := resolver.ResolveSourceIP(spoofed); err != ErrSourceIPSpoofed {
		t.Fatalf("spoofed without visitor: %v", err)
	}
	if got, err := resolver.ResolveSourceIP(spoofed.WithContext(clientip.WithVisitor(spoofed.Context(), visitor))); err != nil || got != visitor {
		t.Fatalf("spoofed with visitor: %s %v", got, err)
	}
}

func TestRecoveryResolverPrefersTheVisitorAddress(t *testing.T) {
	database := singleBindingDatabase("recovery.example.com", testTenantA, testScopeA)
	resolver := newTestResolver(t, database, Config{TrustedProxyCIDRs: []string{"10.0.0.0/8"}})
	request := newRequest("recovery.example.com", "10.1.0.9:443")
	request.Header.Set("X-Forwarded-For", "198.51.100.40")
	trusted, err := resolver.Resolve(request.WithContext(clientip.WithVisitor(request.Context(), netip.MustParseAddr("203.0.113.9"))))
	if err != nil || trusted.SourceIP != "203.0.113.9" {
		t.Fatalf("visitor: %+v %v", trusted, err)
	}
	// A private visitor address (not allowed here) keeps the proxy chain's source.
	trusted, err = resolver.Resolve(request.WithContext(clientip.WithVisitor(request.Context(), netip.MustParseAddr("10.9.9.9"))))
	if err != nil || trusted.SourceIP != "198.51.100.40" {
		t.Fatalf("private visitor: %+v %v", trusted, err)
	}
	trusted, err = resolver.Resolve(request)
	if err != nil || trusted.SourceIP != "198.51.100.40" {
		t.Fatalf("no visitor: %+v %v", trusted, err)
	}
}
