package controlgrpc

import (
	"errors"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	valid := DefaultConfig()
	valid.ServerCertificateFile = "server.crt"
	valid.ServerPrivateKeyFile = "server.key"
	valid.GatewayClientCAFile = "gateway-ca.crt"
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing host", mutate: func(c *Config) { c.ListenAddress = ":9091" }},
		{name: "missing port", mutate: func(c *Config) { c.ListenAddress = "localhost" }},
		{name: "zero port", mutate: func(c *Config) { c.ListenAddress = "localhost:0" }},
		{name: "port suffix", mutate: func(c *Config) { c.ListenAddress = "localhost:http" }},
		{name: "invalid host", mutate: func(c *Config) { c.ListenAddress = "bad_host:9091" }},
		{name: "missing certificate", mutate: func(c *Config) { c.ServerCertificateFile = "" }},
		{name: "missing private key", mutate: func(c *Config) { c.ServerPrivateKeyFile = "" }},
		{name: "missing client CA", mutate: func(c *Config) { c.GatewayClientCAFile = "" }},
		{name: "zero certificate window", mutate: func(c *Config) { c.MinimumCertificateValidity = 0 }},
		{name: "certificate window too large", mutate: func(c *Config) { c.MinimumCertificateValidity = maxCertificateWindow + time.Second }},
		{name: "zero startup", mutate: func(c *Config) { c.StartupTimeout = 0 }},
		{name: "startup too large", mutate: func(c *Config) { c.StartupTimeout = maxStartupTimeout + time.Second }},
		{name: "zero shutdown", mutate: func(c *Config) { c.ShutdownTimeout = 0 }},
		{name: "shutdown too large", mutate: func(c *Config) { c.ShutdownTimeout = maxShutdownTimeout + time.Second }},
		{name: "zero receive size", mutate: func(c *Config) { c.MaxReceiveMessageBytes = 0 }},
		{name: "receive size too large", mutate: func(c *Config) { c.MaxReceiveMessageBytes = maxMessageBytes + 1 }},
		{name: "zero send size", mutate: func(c *Config) { c.MaxSendMessageBytes = 0 }},
		{name: "send size too large", mutate: func(c *Config) { c.MaxSendMessageBytes = maxMessageBytes + 1 }},
		{name: "zero streams", mutate: func(c *Config) { c.MaxConcurrentStreams = 0 }},
		{name: "too many streams", mutate: func(c *Config) { c.MaxConcurrentStreams = maxConcurrentStreams + 1 }},
		{name: "zero connection timeout", mutate: func(c *Config) { c.ConnectionTimeout = 0 }},
		{name: "connection timeout too large", mutate: func(c *Config) { c.ConnectionTimeout = maxConnectionTimeout + time.Second }},
		{name: "zero keepalive time", mutate: func(c *Config) { c.KeepaliveTime = 0 }},
		{name: "keepalive time too large", mutate: func(c *Config) { c.KeepaliveTime = maxKeepaliveDuration + time.Second }},
		{name: "zero keepalive timeout", mutate: func(c *Config) { c.KeepaliveTimeout = 0 }},
		{name: "keepalive timeout too large", mutate: func(c *Config) { c.KeepaliveTimeout = maxKeepaliveDuration + time.Second }},
		{name: "zero minimum ping", mutate: func(c *Config) { c.MinimumClientPingTime = 0 }},
		{name: "minimum ping too large", mutate: func(c *Config) { c.MinimumClientPingTime = maxKeepaliveDuration + time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("validation error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestConfigValidateAcceptsIPv4IPv6AndHostname(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9091", "[::1]:9091", "control-internal.example:443"} {
		t.Run(address, func(t *testing.T) {
			config := DefaultConfig()
			config.ListenAddress = address
			config.ServerCertificateFile = "server.crt"
			config.ServerPrivateKeyFile = "server.key"
			config.GatewayClientCAFile = "gateway-ca.crt"
			if err := config.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
