package httpapi

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
)

func TestNormalizeAPIKeyIPAllowlistHTTPContract(t *testing.T) {
	input := []string{"2001:db8::/32", "192.0.2.0/24", "10.0.0.0/8"}
	want := append([]string(nil), input...)
	sort.Strings(want)
	got, failure := normalizeAPIKeyIPAllowlist(input)
	if failure != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized allowlist = (%v, %#v), want %v", got, failure, want)
	}

	tooMany := make([]string, 33)
	for index := range tooMany {
		tooMany[index] = "198.51.100." + string(rune('A'+index)) + "/32"
	}
	for _, test := range []struct {
		name   string
		values []string
		code   string
		params map[string]any
	}{
		{"invalid", []string{"192.0.2.1/24"}, "api_key_ip_allowlist_invalid_cidr", map[string]any{"field": "ip_allowlist", "index": 0}},
		{"unsupported", []string{"::ffff:192.0.2.0/120"}, "api_key_ip_allowlist_unsupported_prefix", map[string]any{"field": "ip_allowlist", "index": 0}},
		{"duplicate", []string{"192.0.2.0/24", "192.0.2.0/24"}, "api_key_ip_allowlist_duplicate", map[string]any{"field": "ip_allowlist", "index": 1, "duplicate_of": 0}},
		{"overlap", []string{"192.0.2.0/24", "192.0.2.128/25"}, "api_key_ip_allowlist_overlap", map[string]any{"field": "ip_allowlist", "index": 1, "overlaps": 0}},
		{"too many", tooMany, "api_key_ip_allowlist_too_many", map[string]any{"field": "ip_allowlist", "maximum": 32, "actual": 33}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, failure := normalizeAPIKeyIPAllowlist(test.values)
			if failure == nil || failure.Code != test.code || !reflect.DeepEqual(failure.Params, test.params) {
				t.Fatalf("failure = %#v, want code=%q params=%v", failure, test.code, test.params)
			}
		})
	}
}

func TestAPIKeyIPAllowlistJSONAndOpenAPIContract(t *testing.T) {
	allowlist := []string{"192.0.2.0/24", "2001:db8::/32"}
	for name, value := range map[string]any{
		"fields request":   apiKeyFieldsRequest{IPAllowlist: allowlist},
		"mutation request": apiKeyMutationRequest{IPAllowlist: allowlist},
		"key response":     apikey.Key{IPAllowlist: allowlist},
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), `"ip_allowlist":["192.0.2.0/24","2001:db8::/32"]`) {
			t.Fatalf("%s does not carry exact allowlist: %s", name, encoded)
		}
		if strings.Contains(strings.ToLower(string(encoded)), "secret") {
			t.Fatalf("%s leaks a secret field: %s", name, encoded)
		}
	}

	source, err := os.ReadFile("../../../../api/control-api-keys.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(source)
	for _, required := range []string{
		"operationId: listSelfAPIKeys", "operationId: createSelfAPIKey",
		"operationId: getSelfAPIKey", "operationId: updateSelfAPIKey",
		"operationId: activateSelfAPIKey", "operationId: rotateSelfAPIKey",
		"operationId: revokeSelfAPIKey", "operationId: adminListUserAPIKeys",
		"operationId: adminCreateUserAPIKey", "operationId: adminRevokeUserAPIKey",
		"IPAllowlist:", "maxItems: 32", "uniqueItems: true",
		"api_key_ip_allowlist_invalid_cidr", "api_key_ip_allowlist_unsupported_prefix",
		"api_key_ip_allowlist_duplicate", "api_key_ip_allowlist_overlap",
		"api_key_ip_allowlist_too_many", "unknown result",
	} {
		if !strings.Contains(contract, required) {
			t.Errorf("OpenAPI is missing %q", required)
		}
	}
	for _, forbidden := range []string{"matching_prefix", "matched_cidr", "secret_digest"} {
		if strings.Contains(contract, forbidden) {
			t.Errorf("OpenAPI exposes forbidden denial field %q", forbidden)
		}
	}
}
