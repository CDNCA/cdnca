package systemmailsettings

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSaveRejectsUnsupportedSMSProviderBeforeStorage(t *testing.T) {
	for _, provider := range []string{"smsbao", "tencent", "disabled", "HTTPS_JSON", " https_json", "https_json\n", "unknown", "ALIYUN"} {
		t.Run(provider, func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Fatal("unsupported SMS provider reached storage")
				}
			}()
			value := DefaultSettings()
			value.SMSProvider = provider
			_, err := (&Service{}).Save(context.Background(), Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}, SaveRequest{
				Value: value, RequestID: "sms-provider-validation", IdempotencyKey: "sms-provider-validation",
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v, want ErrInvalidInput", err)
			}
		})
	}
}
