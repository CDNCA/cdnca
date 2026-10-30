package dnscredentialrewraphttp

import (
	"os"
	"strings"
	"testing"
)

func TestProductionBoundaryUsesLivePlatformSessionAuthorization(t *testing.T) {
	source, err := os.ReadFile("production.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"AuthenticateSession(ctx, rawSession)",
		`principal.ScopeKind != "platform"`,
		"principal.TenantID != nil",
		"AuthorizeSession(",
		"PermissionManage",
		`authorization.CredentialKind() != "session"`,
		"authorization.CredentialID() != session.SessionID",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("production authorization missing %q", required)
		}
	}
	for _, forbidden := range []string{"AuthorizeAPIKey(", "Workload", "tenant.admin"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("production authorization admits forbidden credential path %q", forbidden)
		}
	}
}

func TestProductionConstructorFailsClosedWithoutDependencies(t *testing.T) {
	if _, err := NewProductionHandler(t.Context(), ProductionConfig{}, ProductionDependencies{}); err != ErrInvalidConfig {
		t.Fatalf("error=%v, want ErrInvalidConfig", err)
	}
}
