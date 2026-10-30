package edgepublishhttp

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// 端口范围 / 跟随端口回源 on a v8 node: the publish is refused
// with 422 node_capability_unavailable naming every node that lacks tcp v9.
func TestL4PortRangeOnOldNodesIs422NamingTheNodes(t *testing.T) {
	first, second := uuid.New(), uuid.New()
	err := fmt.Errorf("publish: %w", &edgepublish.TargetCapabilityError{NodeID: first, AgentVersion: "1.0.35-g5",
		Feature: "an L4 port range or follow-port origin (四层端口范围 / 跟随端口回源)",
		Capability: agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY, Required: 9, Advertised: 8, OtherNodeIDs: []uuid.UUID{second}})
	status, code, message := classifyError(err)
	if status != http.StatusUnprocessableEntity || code != "node_capability_unavailable" ||
		!strings.Contains(message, first.String()) || !strings.Contains(message, second.String()) ||
		!strings.Contains(message, "四层端口范围") || !strings.Contains(message, "v9 required, v8 declared") {
		t.Fatalf("mapping=(%d,%q,%q)", status, code, message)
	}
}
