package accountregistrationchallengehttp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIAM02RegistrationChallengeOpenAPIContract(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "api", "openapi", "v1", "account-registration-challenge.yaml")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]struct {
			Post struct {
				Responses map[string]any `yaml:"responses"`
			} `yaml:"post"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ChallengePath, VerificationPath} {
		operation, exists := document.Paths[path]
		if !exists {
			t.Errorf("OpenAPI omits %s", path)
			continue
		}
		for _, status := range []string{"409", "422", "429", "503"} {
			if _, exists := operation.Post.Responses[status]; !exists {
				t.Errorf("%s omits response %s", path, status)
			}
		}
	}
	text := string(source)
	for _, required := range []string{
		"Idempotency-Key", "X-Request-ID", "human_token", "challenge_id", "otp", "writeOnly: true",
		"Set-Cookie", "account_registration_challenge_invalid", "account_registration_challenge_rate_limited",
		"account_registration_challenge_conflict", "account_registration_challenge_unavailable",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("OpenAPI missing %q", required)
		}
	}
	for _, forbidden := range []string{"proof_reference", "otp_value", "human_verified", "contact_verified"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("OpenAPI exposes internal field %q", forbidden)
		}
	}
}
