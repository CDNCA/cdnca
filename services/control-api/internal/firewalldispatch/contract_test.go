package firewalldispatch

import (
	"os"
	"strings"
	"testing"
)

func TestPostgresContractKeepsClaimAndSettlementInOneFencedTransaction(t *testing.T) {
	source, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	required := []string{
		"FOR UPDATE OF outbox SKIP LOCKED",
		"ROW_NUMBER() OVER (PARTITION BY tenant_scope_id",
		"lower.node_id=outbox.node_id",
		"lower.policy_version<outbox.policy_version",
		"lower.state NOT IN ('acked','failed')",
		"state='retryable'", "SET state='pending'", "state='pending'",
		"attempts=$2", "state='published'", "state='failed'", "state='acked'",
	}
	for _, fragment := range required {
		if !strings.Contains(text, fragment) {
			t.Errorf("postgres contract missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DeploymentCommand", "edge_command_outbox", "node_deployments"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("postgres contract contains forbidden %q", forbidden)
		}
	}
}

func TestNATSContractUsesDedicatedTypedStreamsAndStableHeaders(t *testing.T) {
	source, err := os.ReadFile("nats.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, fragment := range []string{
		"AGENT_FIREWALL_COMMANDS", "AGENT_FIREWALL_STATUS",
		"cdnca.agent.firewall.commands", "cdnca.agent.firewall.status",
		"nats.MsgIdHdr", "nats.ExpectStream", "nats.AckExplicitPolicy",
	} {
		if !strings.Contains(text, fragment) {
			t.Errorf("NATS contract missing %q", fragment)
		}
	}
	if strings.Contains(text, "DeploymentCommand") || strings.Contains(text, "cdnca.agent.commands\"") {
		t.Fatal("firewall dispatch must not tunnel through deployment commands")
	}
}
