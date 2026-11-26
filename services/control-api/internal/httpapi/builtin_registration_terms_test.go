package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type termsRegistrationStore struct {
	records []accountregistration.RegistrationRecord
}

func (store *termsRegistrationStore) Register(_ context.Context, record accountregistration.RegistrationRecord) (accountregistration.StoreResult, error) {
	store.records = append(store.records, record)
	return accountregistration.StoreResult{}, nil
}

func (store *termsRegistrationStore) CompletedRegistration(context.Context, string, [32]byte) (bool, error) {
	return false, nil
}

type termsRegistrationPolicy struct{}

func (termsRegistrationPolicy) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{RegistrationEnabled: true, UsernameRequired: true, TermsVersion: "terms-0123456789ab"}, nil
}

type termsRegistrationCaptcha struct{}

func (termsRegistrationCaptcha) ConsumeCaptcha(context.Context, identity.LoginCaptchaProof) error {
	return nil
}

// through POST /v1/auth/register and the real built-in service:
// with no readable terms a sign-up without any terms field is accepted and
// records no acceptance; once terms are required the same body is refused
// with account_registration_terms_required before anything is stored.
func TestBuiltInRegisterRouteFollowsTermsRequirement(t *testing.T) {
	store := &termsRegistrationStore{}
	service, err := accountregistration.NewBuiltInService(store, termsRegistrationPolicy{}, termsRegistrationCaptcha{}, bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	required := false
	service.RequireTermsWhen(func(context.Context) (bool, error) { return required, nil })
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), BuiltInRegistration: service}).Handler()
	post := func(key string) *httptest.ResponseRecorder {
		body := `{"username":"terms-none","password":"Correct-horse-battery-1","display_name":"terms-none","email":"none@example.com",` +
			`"verification_channel":"email","captcha":{"id":"22222222-2222-4222-8222-222222222222","answer":"AB2CD"}}`
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		request.RemoteAddr = "203.0.113.9:4000"
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		return response
	}
	if response := post("registration-no-terms"); response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"accepted":true`) {
		t.Fatalf("no terms required: status=%d body=%s", response.Code, response.Body)
	}
	if len(store.records) != 1 || store.records[0].TermsVersion != "" {
		t.Fatalf("an acceptance was recorded: %#v", store.records)
	}
	required = true
	if response := post("registration-terms-required"); response.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(response.Body.String(), "account_registration_terms_required") {
		t.Fatalf("terms required: status=%d body=%s", response.Code, response.Body)
	}
	if len(store.records) != 1 {
		t.Fatalf("a refused sign-up reached the store: %d", len(store.records))
	}
}
