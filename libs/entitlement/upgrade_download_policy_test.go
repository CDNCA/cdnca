package entitlement

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testDownloadRootPEM = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"

func TestUpgradeDownloadPolicyValidate(t *testing.T) {
	good := UpgradeDownloadPolicy{Host: "cdnca.com", Port: 19445, Addresses: []string{"203.0.113.9", "2001:db8::9"}, RootCA: testDownloadRootPEM}
	if err := good.Validate("https://cdnca.com:19445/downloads/edge-agent/upgrades/sha256/ab"); err != nil {
		t.Fatalf("valid policy: %v", err)
	}
	system := UpgradeDownloadPolicy{Host: "cdnca.com", Port: 443, Addresses: []string{"203.0.113.9"}, RootCA: UpgradeDownloadSystemRoot}
	if err := system.Validate("https://cdnca.com/downloads/edge-agent/upgrades/sha256/ab"); err != nil {
		t.Fatalf("default port 443: %v", err)
	}
	literal := UpgradeDownloadPolicy{Host: "203.0.113.9", Port: 443, Addresses: []string{"203.0.113.9"}, RootCA: testDownloadRootPEM}
	if err := literal.Validate("https://203.0.113.9/x"); err != nil {
		t.Fatalf("IP literal: %v", err)
	}
	for name, mutate := range map[string]func(*UpgradeDownloadPolicy) string{
		"port differs from URL": func(p *UpgradeDownloadPolicy) string { return "https://cdnca.com:443/x" },
		"host differs from URL": func(p *UpgradeDownloadPolicy) string { return "https://www.cdnca.com:19445/x" },
		"no addresses":          func(p *UpgradeDownloadPolicy) string { p.Addresses = nil; return "" },
		"duplicate address": func(p *UpgradeDownloadPolicy) string {
			p.Addresses = []string{"203.0.113.9", "::ffff:203.0.113.9"}
			return ""
		},
		"non-canonical address": func(p *UpgradeDownloadPolicy) string { p.Addresses = []string{"2001:DB8::9"}; return "" },
		"unspecified address":   func(p *UpgradeDownloadPolicy) string { p.Addresses = []string{"0.0.0.0"}; return "" },
		"too many addresses": func(p *UpgradeDownloadPolicy) string {
			p.Addresses = nil
			for i := 1; i <= 17; i++ {
				p.Addresses = append(p.Addresses, fmt.Sprintf("203.0.113.%d", i))
			}
			return ""
		},
		"upper-case host":   func(p *UpgradeDownloadPolicy) string { p.Host = "CDNCA.com"; return "https://cdnca.com:19445/x" },
		"single-label host": func(p *UpgradeDownloadPolicy) string { p.Host = "cdnca"; return "https://cdnca:19445/x" },
		"zero port":         func(p *UpgradeDownloadPolicy) string { p.Port = 0; return "" },
		"root not PEM":      func(p *UpgradeDownloadPolicy) string { p.RootCA = "anything"; return "" },
		"two roots":         func(p *UpgradeDownloadPolicy) string { p.RootCA = testDownloadRootPEM + testDownloadRootPEM; return "" },
		"literal pins other": func(p *UpgradeDownloadPolicy) string {
			p.Host = "203.0.113.9"
			p.Addresses = []string{"203.0.113.8"}
			return "https://203.0.113.9:19445/x"
		},
	} {
		policy := good
		policy.Addresses = append([]string(nil), good.Addresses...)
		target := mutate(&policy)
		if target == "" {
			target = "https://cdnca.com:19445/x"
		}
		if err := policy.Validate(target); err == nil {
			t.Errorf("%s: accepted %+v for %s", name, policy, target)
		}
	}
}

// The policy is control-signed: it changes the control signature and a
// tampered copy is refused; without one the wire is byte-for-byte unchanged.
func TestUpgradeExecutionCarriesControlSignedDownloadPolicy(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	controlPublic, controlPrivate := upgradeGrantTestKey(0x81)
	edgePublic, edgePrivate := upgradeGrantTestKey(0x82)
	control := testSigner{id: "control-execution-1", private: controlPrivate}
	edge := testSigner{id: "edge-consumption-1", private: edgePrivate}
	execution := validUpgradeExecution(now)
	execution.DownloadURL = "https://cdnca.com:19445/downloads/edge-agent/upgrades/sha256/ab"
	plain, err := SignUpgradeExecution(context.Background(), execution, control, edge)
	if err != nil {
		t.Fatal(err)
	}
	plainWire, _ := plain.Encode()
	if strings.Contains(string(plainWire), "download_policy") {
		t.Fatal("an execution without a policy must not carry the field")
	}
	execution.DownloadPolicy = &UpgradeDownloadPolicy{Host: "cdnca.com", Port: 19445, Addresses: []string{"203.0.113.9"}, RootCA: testDownloadRootPEM}
	signed, err := SignUpgradeExecution(context.Background(), execution, control, edge)
	if err != nil {
		t.Fatal(err)
	}
	if signed.ControlSignature == plain.ControlSignature {
		t.Fatal("the control signature must cover the download policy")
	}
	wire, _ := signed.Encode()
	decoded, err := DecodeUpgradeExecution(wire)
	if err != nil {
		t.Fatal(err)
	}
	controlKeys, edgeKeys := NewKeyRing(), NewKeyRing()
	_ = controlKeys.Add("control-execution-1", controlPublic)
	_ = edgeKeys.Add("edge-consumption-1", edgePublic)
	verified, err := VerifyUpgradeExecution(decoded, controlKeys, edgeKeys, executionVerifyOptions(now, execution))
	if err != nil || verified.DownloadPolicy == nil || verified.DownloadPolicy.Port != 19445 {
		t.Fatalf("verify = %+v, %v", verified.DownloadPolicy, err)
	}
	tampered := strings.Replace(string(wire), `"port":19445`, `"port":19446`, 1)
	if tampered == string(wire) {
		t.Fatal("fixture did not find the policy port")
	}
	if decoded, err := DecodeUpgradeExecution([]byte(tampered)); err == nil {
		if _, err := VerifyUpgradeExecution(decoded, controlKeys, edgeKeys, executionVerifyOptions(now, execution)); err == nil {
			t.Fatal("a tampered download policy must not verify")
		}
	}
	execution.DownloadPolicy.Port = 443
	if _, err := SignUpgradeExecution(context.Background(), execution, control, edge); err == nil {
		t.Fatal("a policy that does not match download_url must not be signed")
	}
}
