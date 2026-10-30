package challengepolicy

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeConfigCoversLocalAndExternalModes(t *testing.T) {
	for _, mode := range []string{ModeDelay, ModeClick, ModeSlider, ModeCaptcha, ModeExternal} {
		t.Run(mode, func(t *testing.T) {
			config := validConfig(mode)
			if err := normalizeConfig(&config); err != nil {
				t.Fatalf("normalizeConfig(%s) error = %v", mode, err)
			}
			if config.BypassRoutes == nil || config.BypassRoutes[0].Path != "/api/" {
				t.Fatalf("normalized bypass routes = %#v", config.BypassRoutes)
			}
		})
	}
}

func TestNormalizeConfigRejectsBoundaryAndReferenceViolations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "priority zero", mutate: func(value *Config) { value.Priority = 0 }},
		{name: "delay too short", mutate: func(value *Config) { value.MinDelaySeconds = 4 }},
		{name: "challenge ttl too long", mutate: func(value *Config) { value.ChallengeTTLSeconds = 301 }},
		{name: "challenge ttl does not exceed skew", mutate: func(value *Config) { value.ChallengeTTLSeconds = 10; value.ClockSkewSeconds = 10 }},
		{name: "pass ttl zero", mutate: func(value *Config) { value.PassTTLSeconds = 0 }},
		{name: "clock skew too long", mutate: func(value *Config) { value.ClockSkewSeconds = 31 }},
		{name: "multiple attempts", mutate: func(value *Config) { value.AttemptsPerNonce = 2 }},
		{name: "failure window zero", mutate: func(value *Config) { value.FailureWindowSeconds = 0 }},
		{name: "too many failures", mutate: func(value *Config) { value.MaxFailuresPerWindow = 21 }},
		{name: "unknown binding", mutate: func(value *Config) { value.IPBinding = "subnet" }},
		{name: "secret instead of reference", mutate: func(value *Config) { value.KeyReference = "plaintext-secret" }},
		{name: "external mode missing provider", mutate: func(value *Config) { value.Mode = ModeExternal; value.ExternalProvider = nil }},
		{name: "unknown provider", mutate: func(value *Config) {
			value.Mode = ModeExternal
			value.ExternalProvider = &ExternalProviderReference{Provider: "other", AppReference: "appref:test"}
		}},
		{name: "provider app id instead of reference", mutate: func(value *Config) {
			value.Mode = ModeExternal
			value.ExternalProvider = &ExternalProviderReference{Provider: ProviderTencent, AppReference: "123456"}
		}},
		{name: "provider on local mode", mutate: func(value *Config) {
			value.ExternalProvider = &ExternalProviderReference{Provider: ProviderTencent, AppReference: "appref:test"}
		}},
		{name: "unsafe bypass", mutate: func(value *Config) { value.BypassRoutes[0].Path = "/api/%2e%2e/" }},
		{name: "duplicate bypass", mutate: func(value *Config) {
			value.BypassRoutes = append(value.BypassRoutes, value.BypassRoutes[0])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig(ModeClick)
			test.mutate(&config)
			if err := normalizeConfig(&config); !errors.Is(err, ErrValidation) {
				t.Fatalf("normalizeConfig() error = %v, want ErrValidation", err)
			}
		})
	}
}

func TestNormalizeHostAndBypassStrictASCII(t *testing.T) {
	if host, err := normalizeHost("WWW.Example.Test."); err != nil || host != "www.example.test" {
		t.Fatalf("normalizeHost() = (%q, %v)", host, err)
	}
	for _, host := range []string{"", "xn--.example", "é.example", "bad..example", "host:443", strings.Repeat("a", 64) + ".test"} {
		if _, err := normalizeHost(host); !errors.Is(err, ErrValidation) {
			t.Fatalf("normalizeHost(%q) error = %v", host, err)
		}
	}
	for _, route := range []BypassRoute{
		{Kind: BypassPrefix, Path: "/"},
		{Kind: BypassPrefix, Path: "/api"},
		{Kind: BypassExact, Path: "/a/../b"},
		{Kind: BypassExact, Path: "/a?b"},
		{Kind: BypassExact, Path: "/a//b"},
	} {
		if validBypassPath(route.Path, route.Kind) {
			t.Fatalf("validBypassPath(%#v) = true", route)
		}
	}
}

func TestStrictJSONAndRequestLimits(t *testing.T) {
	for _, raw := range []string{
		`{"config":{"mode":"click","mode":"slider"}}`,
		`{"config":{},"unknown":true}`,
		`{} {}`,
	} {
		request := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(raw))
		response := httptest.NewRecorder()
		var body updateBody
		if err := decodeBody(response, request, &body); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("decodeBody(%s) error = %v", raw, err)
		}
	}
	request := httptest.NewRequest(http.MethodPatch, "/", bytes.NewReader(bytes.Repeat([]byte("x"), maxRequestBytes+1)))
	if err := decodeBody(httptest.NewRecorder(), request, &updateBody{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized decodeBody error = %v", err)
	}
}

func TestEmptyCommandBodyAcceptsOnlyAbsentOrEmptyObject(t *testing.T) {
	for _, raw := range []string{"", "{}", " { }\n"} {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(raw))
		if !emptyCommandBody(httptest.NewRecorder(), request) {
			t.Fatalf("emptyCommandBody(%q) = false", raw)
		}
	}
	for _, raw := range []string{" ", "null", "[]", `{"unknown":true}`, `{"x":1,"x":2}`, "{} {}"} {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(raw))
		if emptyCommandBody(httptest.NewRecorder(), request) {
			t.Fatalf("emptyCommandBody(%q) = true", raw)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte("x"), maxRequestBytes+1)))
	if emptyCommandBody(httptest.NewRecorder(), request) {
		t.Fatal("emptyCommandBody accepted oversized body")
	}
}

func TestInvalidCorrelationHeadersAreBoundedAndNotReflected(t *testing.T) {
	handler, err := NewHandler(&Service{store: &Store{}}, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return Actor{}, ErrUnauthenticated
	}))
	if err != nil {
		t.Fatal(err)
	}
	oversized := strings.Repeat("x", maxResponseBytes+1)
	request := httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/not-a-uuid/challenge-policies", nil)
	request.Header.Set("X-Request-ID", oversized)
	request.Header.Set("X-Trace-ID", oversized)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Body.Len() >= 1024 {
		t.Fatalf("invalid metadata response status=%d bytes=%d", response.Code, response.Body.Len())
	}
	if response.Header().Get("X-Request-ID") != "invalid" || response.Header().Get("X-Trace-ID") != "invalid" ||
		strings.Contains(response.Body.String(), strings.Repeat("x", 128)) {
		t.Fatalf("invalid metadata was reflected: headers=%v body=%s", response.Header(), response.Body)
	}
}

func TestOversizedResponseFailsClosedWithinLimit(t *testing.T) {
	handler, err := NewHandler(&Service{store: &Store{}}, AuthenticatorFunc(func(*http.Request) (Actor, error) {
		return Actor{}, ErrUnauthenticated
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Request-ID", "response-limit-request")
	request.Header.Set("X-Trace-ID", "response-limit-trace")
	response := httptest.NewRecorder()
	handler.writeJSON(response, request, http.StatusOK, strings.Repeat("x", maxResponseBytes))
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() >= 1024 {
		t.Fatalf("oversized response status=%d bytes=%d body=%s", response.Code, response.Body.Len(), response.Body)
	}
	assertHTTPError(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func validConfig(mode string) Config {
	config := Config{
		Priority: 10, Mode: mode, ChallengeTTLSeconds: 60, PassTTLSeconds: 300,
		ClockSkewSeconds: 5, AttemptsPerNonce: 1, FailureWindowSeconds: 60,
		MaxFailuresPerWindow: 5, IPBinding: IPBindingExact, BindUserAgent: true,
		BypassRoutes: []BypassRoute{{Kind: BypassExact, Path: "/healthz"}, {Kind: BypassPrefix, Path: "/api/"}},
		KeyReference: "keyref:challenge-2026-07",
	}
	if mode == ModeDelay {
		config.MinDelaySeconds = 5
	}
	if mode == ModeExternal {
		config.ExternalProvider = &ExternalProviderReference{
			Provider: ProviderTencent, AppReference: "appref:tencent-production",
		}
	}
	return config
}
