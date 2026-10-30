package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestValidateFirewallCommandBindsProtocolAndPortScopeIntoDigest(t *testing.T) {
	command := testFirewallCommand()
	command.Targets[0].Protocol = agentv1.FirewallProtocol_FIREWALL_PROTOCOL_TCP
	command.Targets[0].PortStart = 443
	command.Targets[0].PortEnd = 8443
	sealTestFirewallCommand(command)
	if err := validateFirewallCommand(command, testFirewallNodeID); err != nil {
		t.Fatalf("valid scoped command rejected: %v", err)
	}

	for name, mutate := range map[string]func(*agentv1.FirewallCIDRTarget){
		"unknown protocol": func(target *agentv1.FirewallCIDRTarget) { target.Protocol = 99 },
		"any with ports": func(target *agentv1.FirewallCIDRTarget) {
			target.Protocol = agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ANY
			target.PortStart, target.PortEnd = 443, 443
		},
		"half range":     func(target *agentv1.FirewallCIDRTarget) { target.PortEnd = 0 },
		"reversed range": func(target *agentv1.FirewallCIDRTarget) { target.PortStart, target.PortEnd = 8443, 443 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proto.Clone(command).(*agentv1.FirewallCommand)
			mutate(candidate.Targets[0])
			sealTestFirewallCommand(candidate)
			if err := validateFirewallCommand(candidate, testFirewallNodeID); err == nil {
				t.Fatal("invalid protocol/port scope accepted")
			}
		})
	}
}

func TestValidateFirewallCommandRejectsScopeMutationWithoutResealing(t *testing.T) {
	command := testFirewallCommand()
	command.Targets[0].Protocol = agentv1.FirewallProtocol_FIREWALL_PROTOCOL_TCP
	command.Targets[0].PortStart = 443
	command.Targets[0].PortEnd = 443
	sealTestFirewallCommand(command)
	command.Targets[0].PortEnd = 8443
	if err := validateFirewallCommand(command, testFirewallNodeID); err == nil {
		t.Fatal("port mutation outside command digest accepted")
	}
}
