package ccv2

import (
	"strings"
	"testing"
)

func TestSEC11CountMatchersAreIndependentlyCompiled(t *testing.T) {
	source := []byte(`{"schema_version":"cdnca.security-policy.runtime/v1","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":7,"kind":"cc","enabled":true,"default_action":"allow","rules":[{"id":"018f1000-0000-7000-8000-000000000021","priority":10,"enabled":true,"conditions":[{"field":"distinct_user_agents","operator":"number_gte","values":["3"]},{"field":"port","operator":"number_eq","values":["8080"]},{"field":"status_404_count","operator":"number_gte","values":["2"]}],"action":"rate_limit","flow":"stop","action_config":{"rate_limit":{"window_seconds":60,"max_requests":10,"algorithm":"fixed_window","response_action":"reject_429"}}}]}`)
	compiled, err := CompileSource(source, Binding{
		BindingID: "018f1000-0000-7000-8000-000000000030", BindingRevision: 4,
		PublicationID: "018f1000-0000-7000-8000-000000000031",
	})
	if err != nil {
		t.Fatalf("CompileSource: %v", err)
	}
	for _, want := range []string{`"distinct_user_agents":3`, `"status_404_count":2`, `"port":8080`} {
		if !strings.Contains(string(compiled), want) {
			t.Fatalf("compiled policy missing %s: %s", want, compiled)
		}
	}
}
