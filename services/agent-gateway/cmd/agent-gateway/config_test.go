package main

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadConfigRequiresAndValidatesProductionInputs(t *testing.T) {
	valid := validEnvironment()
	cfg, err := readConfig(mapLookup(valid))
	if err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	if cfg.healthAddress != defaultHealthAddress || cfg.healthCheckTimeout != defaultHealthCheckTimeout {
		t.Fatalf("health defaults = (%q, %s)", cfg.healthAddress, cfg.healthCheckTimeout)
	}
	if got := configStringField(t, cfg, "telemetryNATSURL"); got != valid["CDNCA_TELEMETRY_NATS_URL"] {
		t.Fatalf("telemetry NATS URL = %q, want independent URL %q", got, valid["CDNCA_TELEMETRY_NATS_URL"])
	}
	if got := configStringField(t, cfg, "telemetryNATSUser"); got != valid["CDNCA_TELEMETRY_NATS_USER"] {
		t.Fatalf("telemetry NATS user = %q, want configured user", got)
	}
	if got := configStringField(t, cfg, "telemetryNATSPassword"); got != valid["CDNCA_TELEMETRY_NATS_PASSWORD"] {
		t.Fatal("telemetry NATS password was not retained for connection setup")
	}
	podReachable := cloneEnvironment(valid)
	podReachable["CDNCA_GATEWAY_HEALTH_ADDR"] = ":8082"
	podReachable["CDNCA_GATEWAY_HEALTH_CHECK_TIMEOUT"] = "1s"
	cfg, err = readConfig(mapLookup(podReachable))
	if err != nil || cfg.healthAddress != ":8082" || cfg.healthCheckTimeout != time.Second {
		t.Fatalf("Pod health configuration = (%q, %s, %v)", cfg.healthAddress, cfg.healthCheckTimeout, err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "missing Agent CA", mutate: func(values map[string]string) { delete(values, "CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE") }},
		{name: "shared listener", mutate: func(values map[string]string) {
			values["CDNCA_GATEWAY_AGENT_ADDR"] = values["CDNCA_GATEWAY_ENROLLMENT_ADDR"]
		}},
		{name: "health port conflict", mutate: func(values map[string]string) {
			values["CDNCA_GATEWAY_HEALTH_ADDR"] = "0.0.0.0:8443"
		}},
		{name: "invalid health listener", mutate: func(values map[string]string) {
			values["CDNCA_GATEWAY_HEALTH_ADDR"] = "localhost"
		}},
		{name: "noncanonical instance", mutate: func(values map[string]string) { values["CDNCA_GATEWAY_INSTANCE_ID"] = "gateway-one" }},
		{name: "Control scheme", mutate: func(values map[string]string) { values["CDNCA_CONTROL_ADDRESS"] = "http://control:9443" }},
		{name: "invalid Control server name", mutate: func(values map[string]string) { values["CDNCA_CONTROL_SERVER_NAME"] = "control api" }},
		{name: "missing Control workload URI", mutate: func(values map[string]string) { delete(values, "CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN") }},
		{name: "relative Control workload URI", mutate: func(values map[string]string) { values["CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN"] = "/gateway/control" }},
		{name: "padded Control workload URI", mutate: func(values map[string]string) {
			values["CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN"] = " spiffe://cdn-platform/gateway/control "
		}},
		{name: "wildcard Control workload URI", mutate: func(values map[string]string) {
			values["CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN"] = "spiffe://cdn-platform/gateway/*"
		}},
		{name: "query Control workload URI", mutate: func(values map[string]string) {
			values["CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN"] = "spiffe://cdn-platform/gateway/control?role=admin"
		}},
		{name: "unsafe version", mutate: func(values map[string]string) { values["CDNCA_GATEWAY_VERSION"] = "1.0.0\nforged" }},
		{name: "invalid Redis", mutate: func(values map[string]string) { values["CDNCA_REDIS_URL"] = "redis://:do-not-log@[bad" }},
		{name: "invalid NATS scheme", mutate: func(values map[string]string) { values["CDNCA_NATS_URL"] = "http://do-not-log@nats:4222" }},
		{name: "invalid timeout", mutate: func(values map[string]string) { values["CDNCA_GATEWAY_STARTUP_TIMEOUT"] = "0s" }},
		{name: "padded health timeout", mutate: func(values map[string]string) { values["CDNCA_GATEWAY_HEALTH_CHECK_TIMEOUT"] = " 1s" }},
		{name: "health timeout exceeds startup", mutate: func(values map[string]string) {
			values["CDNCA_GATEWAY_HEALTH_CHECK_TIMEOUT"] = "20s"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := cloneEnvironment(valid)
			test.mutate(values)
			_, err := readConfig(mapLookup(values))
			if err == nil {
				t.Fatal("invalid configuration was accepted")
			}
			if strings.Contains(err.Error(), "do-not-log") {
				t.Fatalf("configuration error exposed a credential: %v", err)
			}
		})
	}
}

func TestReadConfigRequiresSecureDedicatedTelemetryNATS(t *testing.T) {
	valid := validEnvironment()
	tests := []struct {
		name      string
		mutate    func(map[string]string)
		forbidden []string
	}{
		{name: "missing URL", mutate: func(values map[string]string) { delete(values, "CDNCA_TELEMETRY_NATS_URL") }},
		{name: "padded URL", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = " tls://telemetry-nats.internal:4223 "
		}},
		{name: "userinfo in URL", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "tls://url-user:url-do-not-log@telemetry-nats.internal:4223"
		}, forbidden: []string{"url-user", "url-do-not-log"}},
		{name: "remote plaintext", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "nats://telemetry-nats.internal:4223"
		}},
		{name: "missing explicit port", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "tls://telemetry-nats.internal"
		}},
		{name: "zero port", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "tls://telemetry-nats.internal:0"
		}},
		{name: "non-numeric port", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "tls://telemetry-nats.internal:nats"
		}},
		{name: "path", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "tls://telemetry-nats.internal:4223/account"
		}},
		{name: "query", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "tls://telemetry-nats.internal:4223?token=query-do-not-log"
		}, forbidden: []string{"query-do-not-log"}},
		{name: "fragment", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_URL"] = "tls://telemetry-nats.internal:4223#fragment-do-not-log"
		}, forbidden: []string{"fragment-do-not-log"}},
		{name: "user without password", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_USER"] = "user-do-not-log"
			delete(values, "CDNCA_TELEMETRY_NATS_PASSWORD")
		}, forbidden: []string{"user-do-not-log"}},
		{name: "password without user", mutate: func(values map[string]string) {
			delete(values, "CDNCA_TELEMETRY_NATS_USER")
			values["CDNCA_TELEMETRY_NATS_PASSWORD"] = "password-do-not-log"
		}, forbidden: []string{"password-do-not-log"}},
		{name: "nonempty user with empty password", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_USER"] = "user-do-not-log"
			values["CDNCA_TELEMETRY_NATS_PASSWORD"] = ""
		}, forbidden: []string{"user-do-not-log"}},
		{name: "empty user with nonempty password", mutate: func(values map[string]string) {
			values["CDNCA_TELEMETRY_NATS_USER"] = ""
			values["CDNCA_TELEMETRY_NATS_PASSWORD"] = "password-do-not-log"
		}, forbidden: []string{"password-do-not-log"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := cloneEnvironment(valid)
			test.mutate(values)
			_, err := readConfig(mapLookup(values))
			if err == nil {
				t.Fatal("unsafe telemetry NATS configuration was accepted")
			}
			for _, value := range test.forbidden {
				if strings.Contains(err.Error(), value) {
					t.Fatalf("configuration error exposed telemetry NATS input: %q", err)
				}
			}
		})
	}
}

func TestReadConfigAcceptsSafeTelemetryNATSAuthenticationModes(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		username string
		password string
	}{
		{name: "remote TLS with credentials", url: "tls://telemetry-nats.internal:4223", username: "telemetry-user", password: "telemetry-password"},
		{name: "remote TLS without credentials", url: "tls://telemetry-nats.internal:4223"},
		{name: "loopback IPv4 plaintext", url: "nats://127.0.0.1:4223"},
		{name: "loopback IPv6 plaintext", url: "nats://[::1]:4223"},
		{name: "localhost plaintext", url: "nats://localhost:4223"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := cloneEnvironment(validEnvironment())
			values["CDNCA_TELEMETRY_NATS_URL"] = test.url
			values["CDNCA_TELEMETRY_NATS_USER"] = test.username
			values["CDNCA_TELEMETRY_NATS_PASSWORD"] = test.password
			cfg, err := readConfig(mapLookup(values))
			if err != nil {
				t.Fatalf("safe telemetry NATS configuration rejected: %v", err)
			}
			if got := configStringField(t, cfg, "telemetryNATSURL"); got != test.url {
				t.Fatalf("telemetry NATS URL = %q, want %q", got, test.url)
			}
		})
	}
}

func TestValidServerNameAcceptsDNSAndIPv6(t *testing.T) {
	for _, name := range []string{"control-api.internal", "localhost", "2001:db8::1"} {
		if !validServerName(name) {
			t.Fatalf("valid server name %q was rejected", name)
		}
	}
}

func validEnvironment() map[string]string {
	return map[string]string{
		"CDNCA_GATEWAY_ENROLLMENT_ADDR":         "127.0.0.1:8443",
		"CDNCA_GATEWAY_AGENT_ADDR":              "127.0.0.1:8444",
		"CDNCA_GATEWAY_INSTANCE_ID":             "018f47a2-5b9c-7d31-8a60-104c9c0b717f",
		"CDNCA_GATEWAY_VERSION":                 "1.0.0",
		"CDNCA_GATEWAY_TLS_CERT_FILE":           "/run/secrets/gateway.crt",
		"CDNCA_GATEWAY_TLS_KEY_FILE":            "/run/secrets/gateway.key",
		"CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE":    "/run/secrets/agent-ca.crt",
		"CDNCA_CONTROL_ADDRESS":                 "control-api:9443",
		"CDNCA_CONTROL_SERVER_NAME":             "control-api.internal",
		"CDNCA_CONTROL_CLIENT_CERT_FILE":        "/run/secrets/control-client.crt",
		"CDNCA_CONTROL_CLIENT_KEY_FILE":         "/run/secrets/control-client.key",
		"CDNCA_CONTROL_SERVER_CA_FILE":          "/run/secrets/control-ca.crt",
		"CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN": "spiffe://cdn-platform/gateway/control",
		"CDNCA_REDIS_URL":                       "redis://:do-not-log@redis:6379/0",
		"CDNCA_NATS_URL":                        "nats://do-not-log@nats:4222",
		"CDNCA_TELEMETRY_NATS_URL":              "tls://telemetry-nats.internal:4223",
		"CDNCA_TELEMETRY_NATS_USER":             "telemetry-user",
		"CDNCA_TELEMETRY_NATS_PASSWORD":         "telemetry-password",
	}
}

func configStringField(t *testing.T, cfg config, name string) string {
	t.Helper()
	field := reflect.ValueOf(cfg).FieldByName(name)
	if !field.IsValid() || field.Kind() != reflect.String {
		t.Fatalf("config is missing string field %q", name)
	}
	return field.String()
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func cloneEnvironment(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}
