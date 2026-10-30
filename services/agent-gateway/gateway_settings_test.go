package gateway

import (
	"context"
	"errors"
	"net/http"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
)

type fakeSettingsClient struct {
	response *controlv1.GetGatewaySettingsResponse
	err      error
	instance string
}

func (f *fakeSettingsClient) GetGatewaySettings(_ context.Context, in *controlv1.GetGatewaySettingsRequest, _ ...grpc.CallOption) (*controlv1.GetGatewaySettingsResponse, error) {
	f.instance = in.GetGatewayInstanceId()
	return f.response, f.err
}

// The page's ranges replace the shipped list atomically; a bad answer or a
// failed poll keeps the previous settings.
func TestSettingsSyncReplacesTrustedProxiesAndEndpoints(t *testing.T) {
	shipped, _ := ParseTrustedProxyRanges(DefaultTrustedProxies)
	proxies := NewTrustedProxies(shipped)
	endpoints := &NodeEndpoints{}
	client := &fakeSettingsClient{response: &controlv1.GetGatewaySettingsResponse{
		TrustedProxies: []*controlv1.GatewayTrustedProxyRangeV1{{Cidr: "10.0.0.0/8", Header: "X-Real-IP"}},
		Endpoints: []*agentv1.GatewayEndpointV1{{Address: "gw.example.com:21444", ServerName: "gw.example.com", Transport: "grpc"},
			{Address: "cdn.example.com:443", ServerName: "gw.example.com", Transport: "ws", TunnelHost: "cdn.example.com"}},
		EndpointsVersion: "v1",
	}}
	sync := SettingsSync{Client: client, InstanceID: "gw-1", Proxies: proxies, Endpoints: endpoints}
	if err := sync.Poll(context.Background()); err != nil || client.instance != "gw-1" {
		t.Fatalf("poll: %v %q", err, client.instance)
	}
	if ip, source, _ := proxies.ClientIP("10.1.1.1:443", http.Header{"X-Real-Ip": {"198.51.100.9"}}); ip.String() != "198.51.100.9" || source != PeerIPSourceTrustedProxy {
		t.Fatalf("new range not applied: %v %s", ip, source)
	}
	if ip, _, _ := proxies.ClientIP("173.245.48.10:443", http.Header{"Cf-Connecting-Ip": {"198.51.100.2"}}); ip.String() != "173.245.48.10" {
		t.Fatal("removed Cloudflare range still trusted")
	}
	got, version := endpoints.Snapshot()
	if len(got) != 2 || version != "v1" || got[1].GetTunnelHost() != "cdn.example.com" {
		t.Fatalf("endpoints = %v %q", got, version)
	}

	client.response = &controlv1.GetGatewaySettingsResponse{TrustedProxies: []*controlv1.GatewayTrustedProxyRangeV1{{Cidr: "garbage", Header: "X"}}}
	if err := sync.Poll(context.Background()); err == nil {
		t.Fatal("invalid range applied")
	}
	client.response, client.err = nil, errors.New("unavailable")
	if err := sync.Poll(context.Background()); err == nil {
		t.Fatal("failed poll reported success")
	}
	if _, version := endpoints.Snapshot(); version != "v1" {
		t.Fatal("previous settings lost")
	}
	if ip, _, _ := proxies.ClientIP("10.1.1.1:443", http.Header{"X-Real-Ip": {"198.51.100.9"}}); ip.String() != "198.51.100.9" {
		t.Fatal("previous ranges lost")
	}
}

// GatewayHello carries the endpoint list (GW-07).
func TestGatewayHelloCarriesNodeEndpoints(t *testing.T) {
	endpoints := &NodeEndpoints{}
	endpoints.set([]*agentv1.GatewayEndpointV1{{Address: "gw.example.com:21444", ServerName: "gw.example.com", Transport: "grpc"}}, "v7")
	g := startSharedTestServersWith(t, func(gateway *Gateway) {
		if err := gateway.ConfigureNodeEndpoints(endpoints); err != nil {
			t.Fatal(err)
		}
	})
	connection := dialGateway(t, g.agent, g.pki.rootPool, g.node.certificate)
	defer connection.Close()
	hello := connectHello(t, connection)
	if hello.GetGatewayEndpointsVersion() != "v7" || len(hello.GetGatewayEndpoints()) != 1 || hello.GetGatewayEndpoints()[0].GetAddress() != "gw.example.com:21444" {
		t.Fatalf("hello endpoints = %v %q", hello.GetGatewayEndpoints(), hello.GetGatewayEndpointsVersion())
	}
}
