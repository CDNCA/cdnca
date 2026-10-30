package dnsproviderremote

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestProviderConfigRedactsCredentialsAndCustomerIdentity(t *testing.T) {
	tenantID := uuid.New()
	scopeID := uuid.New()
	providerID := uuid.New()
	zoneID := uuid.New()
	actorID := uuid.New()
	config := ProviderConfig{
		TenantID: tenantID, ScopeID: scopeID, TenantScopeID: scopeID,
		OperationID: "customer-operation-secret", ActorUserID: actorID,
		ProviderID: providerID, ProviderType: providerCloudflare,
		ZoneID: zoneID, ZoneName: "customer-zone.example.test",
		Credentials: map[string]string{
			"api_token": "provider-credential-secret",
		},
		CredentialVersion: 7,
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, nil))
	logger.Info("provider configuration", "config", config)
	outputs := []string{
		fmt.Sprintf("%v", config),
		fmt.Sprintf("%+v", config),
		fmt.Sprintf("%#v", config),
		fmt.Sprintf("%s", config),
		string(encoded),
		logBuffer.String(),
	}
	for _, output := range outputs {
		for _, sensitive := range []string{
			"api_token", "provider-credential-secret", "customer-operation-secret",
			"customer-zone.example.test", tenantID.String(), scopeID.String(),
			providerID.String(), zoneID.String(), actorID.String(),
		} {
			if strings.Contains(output, sensitive) {
				t.Fatalf("provider config output leaked %q: %s", sensitive, output)
			}
		}
		if !strings.Contains(output, providerCloudflare) ||
			!strings.Contains(output, "credentials_configured") ||
			!strings.Contains(output, "credential_version") {
			t.Fatalf("provider config output lacks safe diagnostics: %s", output)
		}
	}
}
