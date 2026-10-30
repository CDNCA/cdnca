package dnsproviderremotesource

import (
	"os"
	"strings"
	"testing"
)

func TestReconcileCredentialAuthorityRejectsRevokedOrNonpositiveVersion(t *testing.T) {
	raw, err := os.ReadFile("reconcile.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	authorityStart := strings.Index(source, "func loadMutationClaimAuthority(")
	authorityEnd := strings.Index(source, "func sameMutationClaimAuthority(")
	historicalStart := strings.Index(source, "func loadExistingMutationClaim(")
	if authorityStart < 0 || authorityEnd <= authorityStart || historicalStart < 0 || historicalStart >= authorityStart {
		t.Fatal("locate reconcile credential authority queries")
	}

	queries := []struct {
		name  string
		value string
	}{
		{name: "current revision", value: reconcileScopeQuery(false)},
		{name: "mutation claim", value: source[authorityStart:authorityEnd]},
	}
	for _, query := range queries {
		t.Run(query.name, func(t *testing.T) {
			compact := strings.Join(strings.Fields(query.value), " ")
			for _, required := range []string{
				"provider.status='verified'",
				"provider.credential_revoked=false",
				"provider.credential_version>0",
			} {
				if !strings.Contains(compact, required) {
					t.Errorf("query lacks live credential authority predicate %q", required)
				}
			}
			for _, forbidden := range []string{
				"fmt.", "log.", "slog.", "string(ciphertext)", "string(plaintext)", "string(keyID)",
			} {
				if strings.Contains(query.value, forbidden) {
					t.Errorf("credential authority path exposes secret material through %q", forbidden)
				}
			}
		})
	}

	historical := strings.Join(strings.Fields(source[historicalStart:authorityStart]), " ")
	for _, livePredicate := range []string{"provider.credential_revoked=false", "provider.credential_version>0"} {
		if strings.Contains(historical, livePredicate) {
			t.Errorf("durable terminal replay unexpectedly requires %q", livePredicate)
		}
	}
}
