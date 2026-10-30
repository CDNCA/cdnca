package accountregistrationhttp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type registrationOpenAPIDocument struct {
	Paths map[string]struct {
		Post struct {
			Responses map[string]any `yaml:"responses"`
		} `yaml:"post"`
	} `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Required   []string       `yaml:"required"`
			Properties map[string]any `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func TestIAM02RegistrationOpenAPIContract(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve contract test path")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "api", "openapi", "v1", "account-registration.yaml")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document registrationOpenAPIDocument
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	operation, exists := document.Paths[registrationPath]
	if !exists {
		t.Fatalf("OpenAPI omits %s", registrationPath)
	}
	for _, status := range []string{"202", "409", "422", "429", "503"} {
		if _, exists := operation.Post.Responses[status]; !exists {
			t.Errorf("registration responses omit %s", status)
		}
	}
	request := document.Components.Schemas["AccountRegistrationRequest"]
	wantRequired := []string{"username", "password", "display_name", "email", "phone", "terms_accepted", "terms_version", "verification_channel"}
	if strings.Join(request.Required, ",") != strings.Join(wantRequired, ",") {
		t.Fatalf("request required = %v", request.Required)
	}
	for _, forbidden := range []string{"proof", "proof_token", "human_verified", "contact_verified"} {
		if _, exists := request.Properties[forbidden]; exists {
			t.Errorf("client request exposes proof shortcut %q", forbidden)
		}
	}
	text := string(source)
	for _, required := range []string{
		"account_registration_invalid_input", "account_registration_terms_required",
		"account_registration_rate_limited", "account_registration_idempotency_conflict",
		"account_registration_unavailable", "accepted", "replayed",
		"Idempotency-Key", "X-Request-ID", "additionalProperties: false",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("OpenAPI missing %q", required)
		}
	}
}
