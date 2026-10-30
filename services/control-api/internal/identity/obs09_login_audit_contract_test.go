package identity

import (
	"os"
	"strings"
	"testing"
)

func TestOBS09LoginFailuresUseExistingAuditChainWithoutSecrets(t *testing.T) {
	service, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	store, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	serviceText, storeText := string(service), string(store)
	for _, required := range []string{"RecordLoginFailure", "invalid_credentials", "account_disabled", "membership_disabled"} {
		if !strings.Contains(serviceText, required) {
			t.Fatalf("service missing %q", required)
		}
	}
	for _, required := range []string{`Action:       "auth.login"`, `Result:       "denied"`, `"source_ip"`, `"reason_code"`, `"user_agent"`} {
		if !strings.Contains(storeText, required) {
			t.Fatalf("store missing %q", required)
		}
	}
	if strings.Contains(storeText, `"password"`) {
		t.Fatal("login audit must never persist password")
	}
}
