package cdnranges

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// The list equals the one agent-gateway ships (single source of the CF ranges).
func TestCloudflareMatchesTheGatewayList(t *testing.T) {
	raw, err := os.ReadFile("../../../agent-gateway/trusted_proxies_cloudflare.txt")
	if err != nil {
		t.Fatal(err)
	}
	var shipped []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			cidr, _, _ := strings.Cut(line, "=")
			shipped = append(shipped, cidr)
		}
	}
	if strings.Join(shipped, ",") != strings.Join(Cloudflare, ",") {
		t.Fatalf("Cloudflare = %v, gateway ships %v", Cloudflare, shipped)
	}
}

func TestContains(t *testing.T) {
	for address, want := range map[string]bool{
		"162.158.193.46": true, "162.159.38.177": true, "104.16.1.1": true, "[2606:4700::1]": true,
		"::ffff:162.158.193.46": true, "11.0.0.73": false, "8.8.8.8": false, "not-an-ip": false, "": false,
	} {
		if got := Contains(address); got != want {
			t.Errorf("Contains(%q) = %v, want %v", address, got, want)
		}
	}
}

func TestHostBehindCDN(t *testing.T) {
	answers := map[string][]string{
		"proxied.example.com": {"104.16.1.1", "2606:4700::1"},
		"mixed.example.com":   {"104.16.1.1", "11.0.0.73"},
		"direct.example.com":  {"11.0.0.73"},
	}
	lookup := func(_ context.Context, host string) ([]string, error) {
		if values, ok := answers[host]; ok {
			return values, nil
		}
		return nil, errors.New("no such host")
	}
	for host, want := range map[string]bool{
		"proxied.example.com": true, "mixed.example.com": false, "direct.example.com": false,
		"missing.example.com": false, "172.64.1.1": true, "11.0.0.73": false, "": false,
	} {
		if got := HostBehindCDN(context.Background(), lookup, host); got != want {
			t.Errorf("HostBehindCDN(%q) = %v, want %v", host, got, want)
		}
	}
}
