package accountregistration

import (
	"os"
	"strings"
	"testing"
)

func TestIAM02PostgresRegistrationTransactionContract(t *testing.T) {
	content, err := os.ReadFile("postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		"pgx.BeginFunc", "account_registration_requests_159", "FOR UPDATE",
		"INSERT INTO tenants", "INSERT INTO access_scopes", "INSERT INTO users",
		"INSERT INTO memberships", "identity.SeedTenantSystemRoles",
		"INSERT INTO role_assignments", "account_registration_terms_159",
		"account_registration_verification_intents_159", "identity.account_registration.accept",
		"tx.Begin(ctx)", "users_username_lower_idx", "users_email_registration_unique_159",
		"users_phone_registration_unique_159", "ErrIdempotencyConflict",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("postgres registration source missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"identity_write_requests", `"password":`, `"email":`, `"phone":`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("postgres registration source contains forbidden %q", forbidden)
		}
	}
}
