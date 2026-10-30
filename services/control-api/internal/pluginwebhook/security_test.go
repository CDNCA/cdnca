package pluginwebhook

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type staticResolver struct {
	addresses []netip.Addr
	err       error
}

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, r.err
}

func TestResolveTargetPinsOnlyPublicDNSAnswers(t *testing.T) {
	t.Parallel()
	target, err := resolveTarget(context.Background(), "https://hooks.example.com:443/events", staticResolver{
		addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700:4700::1111")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if target.Hostname != "hooks.example.com" || target.Port != "443" || target.URL.String() != "https://hooks.example.com/events" || len(target.Addresses) != 2 {
		t.Fatalf("resolved target = %#v", target)
	}

	blocked := []string{
		"0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1",
		"192.0.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1",
		"192.175.48.1", "198.18.0.1", "198.51.100.1",
		"203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "::808:808", "::ffff:808:808",
		"::ffff:0:808:808", "64:ff9b::808:808", "64:ff9b:1::808:808", "100::1", "2001::1",
		"2001:db8::1", "2002:808:808::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff00::1",
	}
	for _, address := range blocked {
		t.Run(address, func(t *testing.T) {
			_, err := resolveTarget(context.Background(), "https://hooks.example.com/events", staticResolver{
				addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(address)},
			})
			if !errors.Is(err, ErrTargetForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestResolveTargetRequiresCanonicalHTTPSDNSAndPath(t *testing.T) {
	t.Parallel()
	public := staticResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	for _, target := range []string{
		"http://hooks.example.com/events",
		"HTTPS://hooks.example.com/events",
		"https://Hooks.example.com/events",
		"https://xn--bcher-kva.example/events",
		"https://8.8.8.8/events",
		"https://[2001:4860:4860::8888]/events",
		"https://hooks.example.com:8443/events",
		"https://hooks.example.com",
		"https://hooks.example.com/a/../b",
		"https://hooks.example.com/a%2Fb",
		"https://hooks.example.com/a%5Cb",
		"https://hooks.example.com/a%41",
		"https://hooks.example.com/a%20b ",
		"https://hooks.example.com/a\\b",
		"https://hooks.example.com/%00",
	} {
		if _, err := resolveTarget(context.Background(), target, public); !errors.Is(err, ErrTargetForbidden) {
			t.Errorf("target %q error = %v", target, err)
		}
	}
	canonical, err := resolveTarget(context.Background(), "https://hooks.example.com/a%20b", public)
	if err != nil || canonical.URL.String() != "https://hooks.example.com/a%20b" {
		t.Fatalf("canonical escaped path = %#v, error = %v", canonical, err)
	}
	maxPath := "https://hooks.example.com/" + strings.Repeat("a", 511)
	if _, err := resolveTarget(context.Background(), maxPath, public); err != nil {
		t.Fatalf("512-byte path rejected: %v", err)
	}
	if _, err := resolveTarget(context.Background(), maxPath+"a", public); !errors.Is(err, ErrTargetForbidden) {
		t.Fatalf("513-byte path error = %v", err)
	}
}

func TestResolveTargetRejectsSSRFURLFormsAndDNSFailures(t *testing.T) {
	t.Parallel()
	public := staticResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	for _, target := range []string{
		"http://hooks.example.com/events",
		"https://localhost/events",
		"https://worker.localhost/events",
		"https://user:secret@hooks.example.com/events",
		"https://hooks.example.com/events?token=secret",
		"https://hooks.example.com/events#fragment",
		"https://hooks.example.com:0/events",
	} {
		if _, err := resolveTarget(context.Background(), target, public); !errors.Is(err, ErrTargetForbidden) {
			t.Fatalf("target %q error = %v", target, err)
		}
	}
	if _, err := resolveTarget(context.Background(), "https://hooks.example.com/events", staticResolver{}); !errors.Is(err, ErrTargetResolution) {
		t.Fatalf("empty DNS error = %v", err)
	}
}
