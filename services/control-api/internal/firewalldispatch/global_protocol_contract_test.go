package firewalldispatch

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/protobuf/proto"
)

func TestValidateClaimAllowsSameCIDRAcrossDistinctPorts(t *testing.T) {
	claim := validClaim(t, StatePending, 0)
	mutateClaimCommand(t, &claim, func(command *agentv1.FirewallCommand) {
		command.Targets[0].Protocol = agentv1.FirewallProtocol_FIREWALL_PROTOCOL_TCP
		command.Targets[0].PortStart, command.Targets[0].PortEnd = 80, 80
		second := proto.Clone(command.Targets[0]).(*agentv1.FirewallCIDRTarget)
		second.Ordinal = 2
		second.PortStart, second.PortEnd = 443, 443
		command.Targets = append(command.Targets, second)
	})
	if _, _, _, failure := validateClaim(claim, time.Now(), 1<<20, CommandSubjectPrefix, false); failure.code != "" {
		t.Fatalf("distinct port scopes rejected: %s", failure.code)
	}
}

func TestValidateClaimRejectsInvalidProtocolPortScope(t *testing.T) {
	for name, mutate := range map[string]func(*agentv1.FirewallCIDRTarget){
		"unknown protocol": func(target *agentv1.FirewallCIDRTarget) { target.Protocol = 99 },
		"any with ports": func(target *agentv1.FirewallCIDRTarget) {
			target.Protocol = agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ANY
			target.PortStart, target.PortEnd = 443, 443
		},
		"icmp with ports": func(target *agentv1.FirewallCIDRTarget) {
			target.Protocol = agentv1.FirewallProtocol_FIREWALL_PROTOCOL_ICMP
			target.PortStart, target.PortEnd = 8, 8
		},
		"reversed": func(target *agentv1.FirewallCIDRTarget) {
			target.Protocol = agentv1.FirewallProtocol_FIREWALL_PROTOCOL_UDP
			target.PortStart, target.PortEnd = 8443, 443
		},
	} {
		t.Run(name, func(t *testing.T) {
			claim := validClaim(t, StatePending, 0)
			mutateClaimCommand(t, &claim, func(command *agentv1.FirewallCommand) { mutate(command.Targets[0]) })
			if _, _, _, failure := validateClaim(claim, time.Now(), 1<<20, CommandSubjectPrefix, false); failure.code != "command_target_invalid" {
				t.Fatalf("failure = %q", failure.code)
			}
		})
	}
}
