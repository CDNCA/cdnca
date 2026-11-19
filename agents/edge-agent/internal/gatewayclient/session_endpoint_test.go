package gatewayclient

import (
	"context"
	"testing"
)

// The telemetry stream dials the endpoint the control session reached
// (a node that reaches its Gateway only through the ws entry: telemetry
// kept dialing the direct grpc address and never uploaded).
func TestFailoverDialerReportsSessionEndpoint(t *testing.T) {
	var calls []string
	base := MTLSDialerConfig{Address: "gw-a:20407", ServerName: "gw", Transport: "grpc"}
	dialer := newTestFailover(&calls, map[string]bool{"primary/grpc": true}, base,
		GatewayEndpoint{Address: "console:443", ServerName: "gw", Transport: "ws", TunnelHost: "tunnel"})
	if _, ok := dialer.SessionEndpoint(); ok {
		t.Fatal("session endpoint before any dial")
	}
	// the direct entry fails and its ws entry is dialed at once (cdn-auto-ws)
	if _, err := dialer.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	endpoint, ok := dialer.SessionEndpoint()
	if !ok || endpoint.Address != "console:443" || endpoint.Transport != "ws" || endpoint.TunnelHost != "tunnel" || endpoint.ServerName != "gw" {
		t.Fatalf("session endpoint = %+v %v (calls %v)", endpoint, ok, calls)
	}
	// grpc retried as ws on the same address: the session is ws there
	calls = nil
	same := newTestFailover(&calls, map[string]bool{"primary/grpc": true}, MTLSDialerConfig{Address: "gw-a:20407", ServerName: "gw",
		Transport: "grpc", TunnelAudience: "aud"})
	if _, err := same.Dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	if endpoint, ok := same.SessionEndpoint(); !ok || endpoint.Transport != "ws" || endpoint.Address != "gw-a:20407" {
		t.Fatalf("same-address session endpoint = %+v %v", endpoint, ok)
	}
}
