package main

import (
	"errors"
	"testing"
)

func TestBootstrapUnauthenticatedNATSIsLimitedToLoopback(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, username, password string
		valid                              bool
	}{
		{name: "IPv4 loopback", endpoint: "nats://127.0.0.1:4322", valid: true},
		{name: "IPv6 loopback", endpoint: "nats://[::1]:4322", valid: true},
		{name: "localhost", endpoint: "nats://localhost:4322", valid: true},
		{name: "remote TLS", endpoint: "tls://nats.example.test:4222"},
		{name: "remote cleartext", endpoint: "nats://nats.example.test:4222"},
		{name: "container alias", endpoint: "nats://nats:4222"},
		{name: "username only", endpoint: "nats://127.0.0.1:4322", username: "runtime"},
		{name: "password only", endpoint: "nats://127.0.0.1:4322", password: "protected-value"},
		{name: "paired remote TLS", endpoint: "tls://nats.example.test:4222", username: "runtime", password: "protected-value", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := map[string]string{
				"DATABASE_URL":                   "postgres://database.example.test/control",
				"CONTROL_INSTALLATION_ID":        "70000000-0000-4000-8000-000000000001",
				"ANALYTICS_INGEST_NATS_URL":      test.endpoint,
				"ANALYTICS_INGEST_NATS_USER":     test.username,
				"ANALYTICS_INGEST_NATS_PASSWORD": test.password,
			}
			_, err := loadBootstrapConfig(func(name string) (string, bool) {
				value, exists := environment[name]
				return value, exists
			})
			if test.valid && err != nil || !test.valid && !errors.Is(err, errInvalidConfig) {
				t.Fatalf("valid=%t, error=%v", test.valid, err)
			}
		})
	}
}
