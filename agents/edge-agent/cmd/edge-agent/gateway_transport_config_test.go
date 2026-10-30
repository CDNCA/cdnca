package main

import (
	"strings"
	"testing"
)

func TestGatewayTransportConfig(t *testing.T) {
	const audience = "6f1c2a4e-8d3b-4c5a-9e7f-0a1b2c3d4e5f"
	for _, test := range []struct {
		name   string
		mutate func(*fileConfig)
		reject string
	}{
		{name: "default grpc", mutate: func(*fileConfig) {}},
		{name: "explicit grpc", mutate: func(c *fileConfig) { c.Gateway.Transport = "grpc" }},
		{name: "ws with audience", mutate: func(c *fileConfig) {
			c.Gateway.Transport, c.Gateway.TunnelHost, c.Gateway.TunnelAudience = "ws", "gw.example.com", audience
		}},
		{name: "unknown transport", mutate: func(c *fileConfig) { c.Gateway.Transport = "quic" }, reject: "gateway.transport"},
		{name: "tunnel host without ws", mutate: func(c *fileConfig) { c.Gateway.TunnelHost = "gw.example.com" }, reject: "tunnel_host"},
		{name: "ws without audience", mutate: func(c *fileConfig) {
			c.Gateway.Transport, c.Upgrade.Enabled, c.Upgrade.InstallationID = "ws", false, ""
		}, reject: "tunnel_audience"},
		{name: "extra endpoints", mutate: func(c *fileConfig) {
			c.Gateway.TunnelAudience = audience
			c.Gateway.Endpoints = []gatewayEndpointSettings{{Address: "gw.example.com:443", ServerName: "gateway.internal", Transport: "ws"},
				{Address: "203.0.113.10:21444", ServerName: "gateway.internal"}}
		}},
		{name: "endpoint bad address", mutate: func(c *fileConfig) {
			c.Gateway.Endpoints = []gatewayEndpointSettings{{Address: "gw.example.com", ServerName: "gateway.internal"}}
		}, reject: "gateway.endpoints"},
		{name: "endpoint ws without audience", mutate: func(c *fileConfig) {
			c.Upgrade.Enabled, c.Upgrade.InstallationID = false, ""
			c.Gateway.Endpoints = []gatewayEndpointSettings{{Address: "gw.example.com:443", ServerName: "gateway.internal", Transport: "ws"}}
		}, reject: "tunnel_audience"},
		{name: "ws bad tunnel host", mutate: func(c *fileConfig) {
			c.Gateway.Transport, c.Gateway.TunnelHost, c.Gateway.TunnelAudience = "ws", "gw.example.com:443", audience
		}, reject: "tunnel_host"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := validFileConfig()
			test.mutate(&config)
			_, err := config.validate()
			if test.reject == "" && err != nil {
				t.Fatalf("validate() = %v", err)
			}
			if test.reject != "" && (err == nil || !strings.Contains(err.Error(), test.reject)) {
				t.Fatalf("validate() = %v, want error mentioning %q", err, test.reject)
			}
		})
	}
	config := validFileConfig()
	config.Upgrade.InstallationID = audience
	if config.tunnelAudience() != audience {
		t.Fatal("tunnel audience does not default to upgrade.installation_id")
	}
}
