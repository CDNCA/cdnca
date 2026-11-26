package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type registrationTermsStub struct {
	switchableRegistrationConfig
	terms RegistrationTerms
	err   error
}

func (stub registrationTermsStub) RegistrationTerms(context.Context) (RegistrationTerms, error) {
	return stub.terms, stub.err
}

// GET /v1/auth/registration-terms is anonymous and answers the
// terms of the settings page with the version registration-config reports.
func TestRegistrationTermsRoute(t *testing.T) {
	read := func(source RegistrationConfigSource) *httptest.ResponseRecorder {
		api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), RegistrationConfig: source}).Handler()
		response := httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/auth/registration-terms", nil))
		return response
	}
	config := &RegistrationConfig{RegistrationEnabled: true, Mode: "builtin", TermsVersion: "terms-0123456789ab"}
	stub := registrationTermsStub{switchableRegistrationConfig: switchableRegistrationConfig{config: config},
		terms: RegistrationTerms{Title: "用户协议", Body: "第一条\n<b>不是标签</b>", Version: "terms-0123456789ab"}}
	response := read(stub)
	var body struct {
		Data RegistrationTerms `json:"data"`
	}
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Data != stub.terms {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	// no published terms on the settings page is a 404 the page tells apart
	stub.err = ErrRegistrationTermsNotConfigured
	if response := read(stub); response.Code != http.StatusNotFound ||
		!strings.Contains(response.Body.String(), `"registration_terms_not_configured"`) {
		t.Fatalf("not configured: %d %s", response.Code, response.Body)
	}
	stub.err = errors.New("settings unavailable")
	if response := read(stub); response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), "account_registration_unavailable") {
		t.Fatalf("unavailable: %d %s", response.Code, response.Body)
	}
	if response := read(nil); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("no source: %d", response.Code)
	}
}
