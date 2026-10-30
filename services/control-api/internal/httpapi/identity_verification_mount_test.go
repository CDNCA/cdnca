package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIdentityVerificationRoutesAreAbsentWhenDisabled(t *testing.T) {
	t.Parallel()
	api := New(nil, nil, Config{})
	for _, path := range identityVerificationMountTestPaths() {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled identity verification route %s status=%d, want 404", path, response.Code)
		}
	}
}

func TestIdentityVerificationMountForwardsOnlyExactRoutes(t *testing.T) {
	t.Parallel()
	var paths []string
	inner := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		if request.Header.Get("X-Request-ID") == "" {
			t.Fatal("mounted identity verification handler did not receive a request ID")
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), IdentityVerificationHandlerFactory: func() (http.Handler, error) {
		return inner, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range identityVerificationMountTestPaths() {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("X-Request-ID", "identity-verification-mount")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("mounted identity verification route %s status=%d", path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/identity-verification",
		"/v1/identity-verification/",
		"/v1/identity-verification/cases/",
		"/v1/identity-verification/reviewer/cases/unknown/action",
		"/v1/identity-verification-v2/cases",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusNoContent {
			t.Fatalf("adjacent route %s reached identity verification handler", path)
		}
	}
	if len(paths) != len(identityVerificationMountTestPaths()) {
		t.Fatalf("forwarded paths=%v", paths)
	}
}

func TestIdentityVerificationFactoryFailsClosed(t *testing.T) {
	t.Parallel()
	want := errors.New("identity verification dependencies unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), IdentityVerificationHandlerFactory: func() (http.Handler, error) {
		return nil, want
	}})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("initialization error=%v, want %v", api.InitializationError(), want)
	}

	var typedNil *identityVerificationMountTestHandler
	api = New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), IdentityVerificationHandlerFactory: func() (http.Handler, error) {
		return typedNil, nil
	}})
	if api.InitializationError() == nil {
		t.Fatal("typed-nil identity verification handler was accepted")
	}
}

type identityVerificationMountTestHandler struct{}

func (*identityVerificationMountTestHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func identityVerificationMountTestPaths() []string {
	caseID := "11111111-1111-4111-8111-111111111111"
	sessionID := "22222222-2222-4222-8222-222222222222"
	uploadID := "33333333-3333-4333-8333-333333333333"
	return []string{
		"/v1/identity-verification/status",
		"/v1/identity-verification/cases",
		"/v1/identity-verification/cases/" + caseID,
		"/v1/identity-verification/cases/" + caseID + "/submit",
		"/v1/identity-verification/cases/" + caseID + "/withdraw",
		"/v1/identity-verification/cases/" + caseID + "/expire",
		"/v1/identity-verification/provider-sessions",
		"/v1/identity-verification/provider-sessions/" + sessionID + "/uploads",
		"/v1/identity-verification/provider-sessions/" + sessionID + "/uploads/" + uploadID + "/finalize",
		"/v1/identity-verification/provider-callbacks/trusted-kyc",
		"/v1/identity-verification/reviewer/cases",
		"/v1/identity-verification/reviewer/cases/" + caseID,
		"/v1/identity-verification/reviewer/cases/" + caseID + "/claim",
		"/v1/identity-verification/reviewer/cases/" + caseID + "/decision",
		"/v1/identity-verification/admin/cases",
	}
}
