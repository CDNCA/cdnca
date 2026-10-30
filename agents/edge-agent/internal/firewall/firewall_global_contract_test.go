package firewall

import (
	"strings"
	"testing"
)

func TestCompileScopesProtocolPortsAndHitLogsWithoutBreakingIPSets(t *testing.T) {
	version := validVersion("global-fw-task", "global-fw-v1")
	version.Entries = []Entry{
		{Action: ActionAllow, Network: "192.0.2.10/32", Protocol: ProtocolTCP, PortStart: 443, PortEnd: 443, Source: "manual", Reason: "trusted_https"},
		{Action: ActionDeny, Network: "198.51.100.0/24", Protocol: ProtocolTCP, PortStart: 443, PortEnd: 8443, Source: "policy", Reason: "blocked_https"},
		{Action: ActionDeny, Network: "2001:db8:1::/48", Protocol: ProtocolUDP, PortStart: 53, PortEnd: 53, Source: "policy", Reason: "blocked_dns"},
		{Action: ActionDeny, Network: "203.0.113.0/24", Protocol: ProtocolAny, Source: "ipset", Reason: "compatibility"},
	}
	compiled, err := Compile(version)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	batch := string(compiled.Batch)
	// Entries become one set per (action, family, protocol, ports), in entry
	// order after normalization: allow 192.0.2.10 (g1), deny 198.51.100/24
	// (g2), deny 2001:db8:1::/48 (g3).
	for _, fragment := range []string{
		"add element inet cdnca_firewall scoped_1 { 192.0.2.10/32 }",
		"add element inet cdnca_firewall scoped_2 { 198.51.100.0/24 }",
		"add element inet cdnca_firewall scoped_3 { 2001:db8:1::/48 }",
		"ip saddr @scoped_1 tcp dport 443 accept",
		"ip saddr @scoped_2 tcp dport 443-8443 counter limit name \"cdnca_drop_log\" log prefix \"cdnca-fw g2\" drop",
		"ip saddr @scoped_2 tcp dport 443-8443 drop",
		"ip6 saddr @scoped_3 udp dport 53 counter limit name \"cdnca_drop_log\" log prefix \"cdnca-fw g3\" drop",
		"ip saddr @deny_v4 counter limit name \"cdnca_drop_log\" log prefix \"cdnca-fw ipset\" drop",
	} {
		if !strings.Contains(batch, fragment) {
			t.Errorf("compiled batch missing %q:\n%s", fragment, batch)
		}
	}
	if strings.Index(batch, "@scoped_1 tcp dport 443 accept") > strings.Index(batch, "@scoped_2 tcp dport") {
		t.Fatal("scoped allow must precede scoped deny")
	}
	if strings.Contains(batch, "add element inet cdnca_firewall deny_v4 { 198.51.100.0/24") {
		t.Fatal("port-scoped CIDR leaked into the unconditional compatibility set")
	}
}

func TestCompileRejectsInvalidProtocolPortCombinations(t *testing.T) {
	tests := map[string]Entry{
		"unknown protocol": {Action: ActionDeny, Network: "198.51.100.0/24", Protocol: "sctp", Source: "policy", Reason: "bad"},
		"any with ports":   {Action: ActionDeny, Network: "198.51.100.0/24", Protocol: ProtocolAny, PortStart: 443, PortEnd: 443, Source: "policy", Reason: "bad"},
		"icmp with ports":  {Action: ActionDeny, Network: "198.51.100.0/24", Protocol: ProtocolICMP, PortStart: 8, PortEnd: 8, Source: "policy", Reason: "bad"},
		"half range":       {Action: ActionDeny, Network: "198.51.100.0/24", Protocol: ProtocolTCP, PortStart: 443, Source: "policy", Reason: "bad"},
		"reversed range":   {Action: ActionDeny, Network: "198.51.100.0/24", Protocol: ProtocolUDP, PortStart: 8443, PortEnd: 443, Source: "policy", Reason: "bad"},
	}
	for name, entry := range tests {
		t.Run(name, func(t *testing.T) {
			version := validVersion("global-fw-task", "global-fw-v1")
			version.Entries = []Entry{entry}
			if _, err := Compile(version); err == nil {
				t.Fatal("invalid protocol/port combination accepted")
			}
		})
	}
}
