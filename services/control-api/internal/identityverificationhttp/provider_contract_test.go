package identityverificationhttp

import (
	"os"
	"strings"
	"testing"
)

func TestIAM10ProviderRoutesAndOpenAPIStayAligned(t *testing.T) {
	routes := []struct {
		method string
		path   string
		kind   providerRouteKind
	}{
		{"POST", "/v1/identity-verification/provider-sessions", providerRouteStart},
		{"POST", "/v1/identity-verification/provider-sessions/00000000-0000-7000-8000-000000000001/uploads", providerRouteUpload},
		{"POST", "/v1/identity-verification/provider-sessions/00000000-0000-7000-8000-000000000001/uploads/00000000-0000-7000-8000-000000000002/finalize", providerRouteFinalize},
		{"POST", "/v1/identity-verification/provider-callbacks/trusted-kyc", providerRouteCallback},
	}
	sourceBytes, err := os.ReadFile("../../../../api/control-identity-verification.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	for _, expected := range routes {
		route, matched := resolveProviderRoute(expected.path)
		if !matched || route.kind != expected.kind || route.method != expected.method {
			t.Errorf("route %s %s = %#v matched=%t", expected.method, expected.path, route, matched)
		}
		marker := "  " + strings.ReplaceAll(expected.path, "00000000-0000-7000-8000-000000000001", "{session_id}")
		marker = strings.ReplaceAll(marker, "00000000-0000-7000-8000-000000000002", "{upload_id}") + ":"
		marker = strings.ReplaceAll(marker, "trusted-kyc", "{provider}")
		if !strings.Contains(source, marker) {
			t.Errorf("OpenAPI missing path %q", marker)
		}
	}
	for _, required := range []string{
		"private object store", "object_version", "encryption_key_id", "callback signature",
		"Idempotency-Key", "X-Request-ID", "identity_verification_provider_callback_replay_conflict",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("OpenAPI missing IAM-10 contract %q", required)
		}
	}
}
