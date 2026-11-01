package nativebackup

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

const gatewayHostEnv = "CDNCA_GATEWAY_ENROLLMENT_ADDR=0.0.0.0:19443\nCDNCA_GATEWAY_AGENT_ADDR=0.0.0.0:19444\n" +
	"CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=203.0.113.10:19444\nCDNCA_GATEWAY_INSTANCE_ID=x\n"

func TestRetargetGatewayHostMovesTheGatewayToTheNewIP(t *testing.T) {
	host := newBindHost(t)
	host.fixture.write(gatewayEnvFile, gatewayHostEnv, 0o600)
	keyBefore := host.fixture.read(PKIDirectory + "/gateway-server-key.pem")
	result, err := RetargetGatewayHost(host.fixture.layout, "198.51.100.7", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Previous != "203.0.113.10" || result.Current != "198.51.100.7" {
		t.Fatalf("result %+v", result)
	}
	block, _ := pem.Decode([]byte(host.fixture.read(PKIDirectory + "/gateway-server.pem")))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Both addresses, same root (nodes verify with the migrated Gateway CA), same key.
	for _, ip := range []string{"198.51.100.7", "203.0.113.10", "127.0.0.1"} {
		if !slices.ContainsFunc(certificate.IPAddresses, net.ParseIP(ip).Equal) {
			t.Fatalf("SAN misses %s: %v", ip, certificate.IPAddresses)
		}
	}
	if err := certificate.CheckSignatureFrom(host.pki.root); err != nil {
		t.Fatal(err)
	}
	if host.fixture.read(PKIDirectory+"/gateway-server-key.pem") != keyBefore {
		t.Fatal("the Gateway key changed")
	}
	if got := host.fixture.read(gatewayEnvFile); !strings.Contains(got, "CDNCA_GATEWAY_AGENT_PUBLIC_ENDPOINT=198.51.100.7:19444\n") ||
		!strings.Contains(got, "CDNCA_GATEWAY_INSTANCE_ID=x") {
		t.Fatalf("gateway.env %q", got)
	}
	control := host.fixture.read(ConfigDirectory + "/control.env")
	for _, line := range []string{"CDNCA_GATEWAY_LOCAL_ADDRESS=198.51.100.7:19444", "CDNCA_GATEWAY_LOCAL_SERVER_NAME=198.51.100.7",
		"CDNCA_GATEWAY_LOCAL_ENROLLMENT_ADDRESS=198.51.100.7:19443"} {
		if !strings.Contains(control, line+"\n") {
			t.Fatalf("control.env misses %s:\n%s", line, control)
		}
	}
	if got := host.fixture.read(NodeInstallDefaultsFile); !strings.Contains(got, "gateway_address=198.51.100.7:19444\n") ||
		!strings.Contains(got, "gateway_enrollment_address=198.51.100.7:19443\n") || !strings.Contains(got, "gateway_server_name=198.51.100.7\n") ||
		!strings.Contains(got, "upgrade_trust_sha256=") {
		t.Fatalf("node-install-defaults %q", got)
	}
	if got := host.fixture.read(WebRuntimeConfigFile); !strings.Contains(got, `window.__CDNCA_GATEWAY_ADDRESS__ = "198.51.100.7:19444";`) ||
		!strings.Contains(got, `window.__CDNCA_GATEWAY_SERVER_NAME__ = "198.51.100.7";`) {
		t.Fatalf("runtime-config.js %q", got)
	}
	// Running it again changes nothing.
	again, err := RetargetGatewayHost(host.fixture.layout, "198.51.100.7", time.Now())
	if err != nil || again.Changed {
		t.Fatalf("second run %+v %v", again, err)
	}
}

func TestRetargetGatewayHostToDomainAndInvalidInput(t *testing.T) {
	host := newBindHost(t)
	host.fixture.write(gatewayEnvFile, gatewayHostEnv, 0o600)
	if _, err := RetargetGatewayHost(host.fixture.layout, "gw.example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(host.fixture.read(PKIDirectory + "/gateway-server.pem")))
	certificate, _ := x509.ParseCertificate(block.Bytes)
	if !slices.Contains(certificate.DNSNames, "gw.example.com") {
		t.Fatalf("DNS SAN %v", certificate.DNSNames)
	}
	for _, bad := range []string{"", "a b", "1.2.3.4:5", "https://x"} {
		if _, err := RetargetGatewayHost(host.fixture.layout, bad, time.Now()); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestMigrationGatewayHostOnlyMovesIPGateways(t *testing.T) {
	host := newBindHost(t)
	layout := host.fixture.layout
	if got := migrationGatewayHost(layout, MigrationTarget{Host: "198.51.100.7"}); got != "" {
		t.Fatalf("no gateway.env: %q", got)
	}
	host.fixture.write(gatewayEnvFile, gatewayHostEnv, 0o600)
	for _, tc := range []struct {
		target MigrationTarget
		want   string
	}{
		{MigrationTarget{Host: "198.51.100.7"}, "198.51.100.7"},
		{MigrationTarget{Host: "203.0.113.10"}, ""},                                             // floating IP kept
		{MigrationTarget{Host: "new.example.com"}, ""},                                          // SSH by name: no guess
		{MigrationTarget{Host: "new.example.com", GatewayHost: "198.51.100.9"}, "198.51.100.9"}, // explicit
	} {
		if got := migrationGatewayHost(layout, tc.target); got != tc.want {
			t.Fatalf("%+v: %q want %q", tc.target, got, tc.want)
		}
	}
	host.fixture.write(gatewayEnvFile, strings.Replace(gatewayHostEnv, "203.0.113.10", "gw.example.com", 1), 0o600)
	if got := migrationGatewayHost(layout, MigrationTarget{Host: "198.51.100.7"}); got != "" {
		t.Fatalf("domain Gateway follows DNS, got %q", got)
	}
}
