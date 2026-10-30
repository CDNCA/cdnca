package originauthcontrol

import (
	"os"
	"strings"
	"testing"
)

func TestOpenAPIBearerAuthIsAccessSessionOnly(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-origin-auth.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(source)
	start := strings.Index(fragment, "    bearerAuth:\n")
	end := strings.Index(fragment, "\n  parameters:")
	if start < 0 || end <= start {
		t.Fatal("bearerAuth security scheme block not found")
	}
	block := fragment[start:end]
	for _, required := range []string{
		"bearerFormat: access-session",
		"Accepts only a Bearer access session",
		"every request with identity.AuthenticateSession",
		"inside the business PostgreSQL transaction",
		"with iamlock.AuthorizeSession",
	} {
		if !strings.Contains(block, required) {
			t.Fatalf("bearerAuth is missing %q: %s", required, block)
		}
	}
	lowerBlock := strings.ToLower(block)
	for _, forbidden := range []string{"session-or-api-principal", "api-principal", "api principal", "api key"} {
		if strings.Contains(lowerBlock, forbidden) {
			t.Fatalf("bearerAuth promises unsupported credential %q: %s", forbidden, block)
		}
	}
}
