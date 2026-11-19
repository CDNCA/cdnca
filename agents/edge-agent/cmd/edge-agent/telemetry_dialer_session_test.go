package main

import (
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/telemetryclient"
)

type fixedSessionEndpoint struct {
	endpoint gatewayclient.GatewayEndpoint
	ok       bool
}

func (f *fixedSessionEndpoint) SessionEndpoint() (gatewayclient.GatewayEndpoint, bool) {
	return f.endpoint, f.ok
}

type fixedEndpointStore struct {
	gatewayclient.GatewayEndpointStateStore
}

func (fixedEndpointStore) Active() gatewayclient.GatewayEndpointState {
	return gatewayclient.GatewayEndpointState{Address: "gateway.example.test:20407", ServerName: "gateway.example.test"}
}

// The telemetry dialer follows the control session's endpoint, transport
// included; before any session it dials the active address as before.
func TestTelemetryDialerFollowsSessionEndpoint(t *testing.T) {
	session := &fixedSessionEndpoint{}
	dialer := &switchingTelemetryDialer{store: fixedEndpointStore{}, session: session,
		base: telemetryclient.MTLSDialerConfig{Transport: "grpc", TunnelAudience: "aud"}}
	if config := dialer.config(); config.Address != "gateway.example.test:20407" || config.Transport != "grpc" {
		t.Fatalf("before a session: %+v", config)
	}
	session.endpoint, session.ok = gatewayclient.GatewayEndpoint{Address: "console.example.test:443", ServerName: "gateway.example.test",
		Transport: "ws", TunnelHost: "tunnel.example.test"}, true
	config := dialer.config()
	if config.Address != "console.example.test:443" || config.ServerName != "gateway.example.test" || config.Transport != "ws" ||
		config.TunnelHost != "tunnel.example.test" || config.TunnelAudience != "aud" {
		t.Fatalf("after a ws session: %+v", config)
	}
}
