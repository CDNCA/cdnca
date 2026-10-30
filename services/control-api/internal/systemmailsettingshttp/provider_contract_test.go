package systemmailsettingshttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"gopkg.in/yaml.v3"
)

func TestHandlerRejectsUnsupportedSMSProviderWithStableValidationError(t *testing.T) {
	for _, provider := range []string{"aliyun", "smsbao", "submail", "tencent", "disabled"} {
		t.Run(provider, func(t *testing.T) {
			handler, err := New(&systemmailsettings.Service{}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
			if err != nil {
				t.Fatal(err)
			}
			value := systemmailsettings.DefaultSettings()
			value.SMSProvider = provider
			body, err := json.Marshal(map[string]any{"value": value})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPut, route, bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer session")
			request.Header.Set("X-Request-ID", "mail-provider-invalid")
			request.Header.Set("Idempotency-Key", "mail-provider-invalid")
			request.Header.Set("If-Match", `"0"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var result struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusBadRequest || result.Error.Code != "system_mail_settings_validation_error" || result.Error.RequestID != "mail-provider-invalid" || response.Header().Get("ETag") != "" {
				t.Fatalf("status=%d body=%s headers=%v", response.Code, response.Body.String(), response.Header())
			}
		})
	}
}

type mailSettingsOpenAPISchema struct {
	Ref        string                               `yaml:"$ref"`
	Properties map[string]mailSettingsOpenAPISchema `yaml:"properties"`
	AllOf      []mailSettingsOpenAPISchema          `yaml:"allOf"`
	Enum       []string                             `yaml:"enum"`
}

func TestOpenAPILimitsSMSProviderWritesWithoutRejectingLegacyReads(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-system-mail-settings.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Components struct {
			Schemas map[string]mailSettingsOpenAPISchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	schemas := document.Components.Schemas
	write := schemas["WriteRequest"].Properties["value"].AllOf
	if len(write) != 2 || write[0].Ref != "#/components/schemas/Settings" || !reflect.DeepEqual(write[1].Properties["sms_provider"].Enum, []string{"", "https_json"}) {
		t.Fatalf("write provider schema=%+v", write)
	}
	if schemas["Document"].Properties["value"].Ref != "#/components/schemas/Settings" || len(schemas["Settings"].Properties["sms_provider"].Enum) != 0 {
		t.Fatal("read schema must retain legacy provider values")
	}
}
