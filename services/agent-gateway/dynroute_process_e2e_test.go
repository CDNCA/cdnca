package gateway

import (
	"os"
	"testing"
)

// Gateway half of tests/dynroute-e2e/run.sh: the production Connect service and NATS command bus between the
// control half (real node identity, edgepublish v9 releases, rule pack artifact set) and the edge-agent half in a
// node runtime container. It listens on every address (the container reaches it as host.docker.internal) and takes
// the node's artifact key ID from the identity the control half seeds (pki.json leaves it empty; the control half
// answers authorizations with the real key ID).
func TestDynRouteGatewayProcess(t *testing.T) {
	directory, natsURL := os.Getenv("DYNROUTE_E2E_DIR"), os.Getenv("DYNROUTE_E2E_NATS_URL")
	if directory == "" || natsURL == "" {
		t.Skip("DYNROUTE_E2E_DIR and DYNROUTE_E2E_NATS_URL are not set; run tests/dynroute-e2e/run.sh")
	}
	listen := os.Getenv("DYNROUTE_E2E_GATEWAY_LISTEN")
	if listen == "" {
		listen = "0.0.0.0:0"
	}
	serveE2EGateway(t, directory, natsURL, listen, "")
}
