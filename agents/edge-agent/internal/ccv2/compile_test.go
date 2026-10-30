package ccv2

import (
	"errors"
	"strings"
	"testing"
)

func TestCompileSourceIndependentlyProducesExactCCV2Bytes(t *testing.T) {
	source := []byte(`{"schema_version":"cdnca.security-policy.runtime/v1","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":6,"kind":"cc","enabled":true,"default_action":"allow","rules":[{"id":"018f1000-0000-7000-8000-000000000021","priority":10,"enabled":true,"conditions":[{"field":"host","operator":"equals","values":["security.example.test"]},{"field":"method","operator":"equals","values":["GET"]},{"field":"path","operator":"prefix","values":["/api"]},{"field":"port","operator":"number_eq","values":["8080"]}],"action":"rate_limit","flow":"continue","action_config":{"rate_limit":{"window_seconds":60,"max_requests":2,"algorithm":"fixed_window","response_action":"log"}}},{"id":"018f1000-0000-7000-8000-000000000022","priority":20,"enabled":true,"conditions":[{"field":"client_ip","operator":"ip_in_cidr","values":["198.51.100.0/24"]},{"field":"path","operator":"equals","values":["/"]}],"action":"rate_limit","flow":"stop","action_config":{"rate_limit":{"algorithm":"leaky_bucket","rate_per_second":3,"burst":4,"response_action":"temporary_ban","ban_seconds":30}}}]}`)
	binding := Binding{BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 4,
		PublicationID: "018f1000-0000-7000-8000-000000000031"}
	canonical, err := CompileSource(source, binding)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}
	want := `{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":6,"binding_id":"018f1000-0000-7000-8000-000000000030","binding_revision":4,"publication_id":"018f1000-0000-7000-8000-000000000031","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":[{"rule_id":"018f1000-0000-7000-8000-000000000021","priority":10,"flow":"continue","match":{"host":"security.example.test","port":8080,"method":"GET","path":{"kind":"prefix","value":"/api"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":2,"window_seconds":60},"action":{"kind":"log"}},{"rule_id":"018f1000-0000-7000-8000-000000000022","priority":20,"flow":"stop","match":{"path":{"kind":"exact","value":"/"},"source_cidr":"198.51.100.0/24"},"dimension":"client_ip","limit":{"algorithm":"leaky_bucket","rate_per_second":3,"burst":4},"action":{"kind":"temporary_ban","ban_seconds":30}}]}`
	if string(canonical) != want {
		t.Fatalf("canonical:\n%s\nwant:\n%s", canonical, want)
	}
}

func TestCompileSourceAccessPortMatchesCanonicalPortBytes(t *testing.T) {
	port := []byte(`{"schema_version":"cdnca.security-policy.runtime/v1","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":6,"kind":"cc","enabled":true,"default_action":"allow","rules":[{"id":"018f1000-0000-7000-8000-000000000021","priority":10,"enabled":true,"conditions":[{"field":"port","operator":"number_eq","values":["8080"]}],"action":"rate_limit","flow":"stop","action_config":{"rate_limit":{"window_seconds":60,"max_requests":2,"algorithm":"fixed_window","response_action":"reject_429"}}}]}`)
	accessPort := []byte(strings.Replace(string(port), `"field":"port"`, `"field":"access_port"`, 1))
	binding := Binding{BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 4,
		PublicationID: "018f1000-0000-7000-8000-000000000031"}
	portCanonical, err := CompileSource(port, binding)
	if err != nil {
		t.Fatal(err)
	}
	accessPortCanonical, err := CompileSource(accessPort, binding)
	if err != nil {
		t.Fatal(err)
	}
	if string(accessPortCanonical) != string(portCanonical) ||
		!strings.Contains(string(accessPortCanonical), `"match":{"port":8080}`) {
		t.Fatalf("access_port bytes = %s, want canonical port bytes %s", accessPortCanonical, portCanonical)
	}
}

func TestCompileSourceRejectsTamperingAndUnsupportedSemantics(t *testing.T) {
	valid := `{"schema_version":"cdnca.security-policy.runtime/v1","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":1,"kind":"cc","enabled":true,"default_action":"allow","rules":[{"id":"018f1000-0000-7000-8000-000000000021","priority":1,"enabled":true,"conditions":[{"field":"path","operator":"prefix","values":["/"]}],"action":"rate_limit","flow":"stop","action_config":{"rate_limit":{"window_seconds":60,"max_requests":2,"algorithm":"fixed_window","response_action":"reject_429"}}}]}`
	binding := Binding{BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 1, PublicationID: "018f1000-0000-7000-8000-000000000031"}
	tests := map[string]string{
		"unknown field":   strings.Replace(valid, `"kind":"cc"`, `"unknown":true,"kind":"cc"`, 1),
		"duplicate key":   strings.Replace(valid, `"kind":"cc"`, `"kind":"cc","kind":"cc"`, 1),
		"adaptive":        strings.Replace(valid, `"algorithm":"fixed_window"`, `"algorithm":"adaptive"`, 1),
		"continue reject": strings.Replace(valid, `"flow":"stop"`, `"flow":"continue"`, 1),
		"challenge":       strings.Replace(valid, `"action":"rate_limit"`, `"action":"challenge"`, 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileSource([]byte(raw), binding); !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("error = %v, want ErrInvalidSource", err)
			}
		})
	}
}

func TestCompileSourceMatchesControlForCanonicalClientIPEqualsAndRootPrefix(t *testing.T) {
	source := []byte(`{"schema_version":"cdnca.security-policy.runtime/v1","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":1,"kind":"cc","enabled":true,"default_action":"allow","rules":[{"id":"018f1000-0000-7000-8000-000000000021","priority":1,"enabled":true,"conditions":[{"field":"client_ip","operator":"equals","values":["192.0.2.9"]},{"field":"path","operator":"prefix","values":["/"]}],"action":"rate_limit","flow":"stop","action_config":{"rate_limit":{"window_seconds":60,"max_requests":2,"algorithm":"fixed_window","response_action":"reject_429"}}},{"id":"018f1000-0000-7000-8000-000000000022","priority":2,"enabled":true,"conditions":[{"field":"client_ip","operator":"equals","values":["2001:db8::9"]}],"action":"rate_limit","flow":"stop","action_config":{"rate_limit":{"window_seconds":60,"max_requests":2,"algorithm":"fixed_window","response_action":"reject_429"}}}]}`)
	binding := Binding{BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 1,
		PublicationID: "018f1000-0000-7000-8000-000000000031"}
	compiled, err := CompileSource(source, binding)
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}
	for _, required := range []string{`"value":"/"`, `"source_cidr":"192.0.2.9/32"`, `"source_cidr":"2001:db8::9/128"`} {
		if !strings.Contains(string(compiled), required) {
			t.Fatalf("compiled policy missing %s: %s", required, compiled)
		}
	}
}
