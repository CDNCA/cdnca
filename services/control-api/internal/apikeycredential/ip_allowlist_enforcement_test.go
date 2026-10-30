package apikeycredential

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
)

func TestSourceIPResolverTrustedProxyContract(t *testing.T) {
	direct, err := accountrecoverycontext.NewSourceIPResolver(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "https://control.example.test/v1/sites", nil)
	request.RemoteAddr = "[::ffff:192.0.2.8]:443"
	address, err := direct.ResolveSourceIP(request)
	if err != nil || address.String() != "192.0.2.8" {
		t.Fatalf("mapped direct peer = (%s, %v), want canonical IPv4", address, err)
	}
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	if _, err := direct.ResolveSourceIP(request); !errors.Is(err, accountrecoverycontext.ErrSourceIPSpoofed) {
		t.Fatalf("untrusted forwarding header error = %v, want spoofed", err)
	}

	trusted, err := accountrecoverycontext.NewSourceIPResolver([]string{"10.0.0.0/8"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest("GET", "https://control.example.test/v1/sites", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.3")
	address, err = trusted.ResolveSourceIP(request)
	if err != nil || address.String() != "203.0.113.9" {
		t.Fatalf("trusted proxy chain = (%s, %v), want 203.0.113.9", address, err)
	}
	request.Header.Set("Forwarded", "for=203.0.113.9")
	if _, err := trusted.ResolveSourceIP(request); !errors.Is(err, accountrecoverycontext.ErrSourceIPInvalid) {
		t.Fatalf("ambiguous proxy chain error = %v, want invalid", err)
	}
	request.Header.Del("Forwarded")
	request.Header.Del("X-Forwarded-For")
	if _, err := trusted.ResolveSourceIP(request); !errors.Is(err, accountrecoverycontext.ErrSourceIPMissing) {
		t.Fatalf("missing trusted proxy chain error = %v, want missing", err)
	}
}

func TestEnforceIPAllowlistContextAndReasonContract(t *testing.T) {
	if address, reason := enforceIPAllowlist(context.Background(), nil); reason != "" || address.IsValid() {
		t.Fatalf("unrestricted enforcement = (%s, %q)", address, reason)
	}
	allowlist := []string{"192.0.2.0/24", "2001:db8::/32"}
	if _, reason := enforceIPAllowlist(context.Background(), allowlist); reason != ReasonClientIPMissing {
		t.Fatalf("missing context reason = %q", reason)
	}

	ctx := WithClientIP(context.Background(), netip.MustParseAddr("::ffff:192.0.2.9"), "request-42b")
	address, reason := enforceIPAllowlist(ctx, allowlist)
	if reason != "" || address.String() != "192.0.2.9" {
		t.Fatalf("mapped allowed address = (%s, %q)", address, reason)
	}
	ctx = WithClientIP(context.Background(), netip.MustParseAddr("198.51.100.9"), "request-42b")
	if _, reason := enforceIPAllowlist(ctx, allowlist); reason != ReasonClientIPNotAllowed {
		t.Fatalf("outside CIDR reason = %q", reason)
	}
	ctx = WithClientIPFailure(context.Background(), "request-42b", ReasonClientIPSpoofed)
	if _, reason := enforceIPAllowlist(ctx, allowlist); reason != ReasonClientIPSpoofed {
		t.Fatalf("spoofed context reason = %q", reason)
	}
	if _, reason := enforceIPAllowlist(WithClientIP(context.Background(), netip.MustParseAddr("192.0.2.9"), "request-42b"),
		[]string{"192.0.2.1/24"}); reason != ReasonIPAllowlistInvalid {
		t.Fatalf("noncanonical persisted CIDR reason = %q", reason)
	}

	fact, ok := clientIPFactFromContext(ctx)
	if !ok || fact.reasonCode != ReasonClientIPSpoofed || fact.requestID != "request-42b" {
		t.Fatalf("sealed client IP fact = %#v, %v", fact, ok)
	}
	if fields := reflect.VisibleFields(reflect.TypeFor[Denial]()); containsField(fields, "Secret") || containsField(fields, "RawCredential") {
		t.Fatalf("denial contract contains secret-bearing field: %#v", fields)
	}
}

func containsField(fields []reflect.StructField, name string) bool {
	for _, field := range fields {
		if field.Name == name {
			return true
		}
	}
	return false
}
