package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallengehttp"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// switchableRegistrationConfig is a registration-config source whose answer
// the test changes between requests.
type switchableRegistrationConfig struct{ config *RegistrationConfig }

func (source switchableRegistrationConfig) RegistrationConfig(context.Context) (RegistrationConfig, error) {
	return *source.config, nil
}

// loginPolicyStub is the raw settings row: 开放注册 on, so a login-methods
// answer that disagrees with registration-config shows.
type loginPolicyStub struct{}

func (loginPolicyStub) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return systemusersettings.PublicSettings{RegistrationEnabled: true, EmailAntiAbuseMode: "native", SMSAntiAbuseMode: "native"}, nil
}

type loginIssuerStub struct{}

func (loginIssuerStub) LoginVerified(context.Context, identity.VerifiedLoginInput, identity.RequestInfo) (identity.AuthResult, error) {
	return identity.AuthResult{}, nil
}

type loginContactsStub struct{}

func (loginContactsStub) Enqueue(context.Context, pgx.Tx, accountloginchallenge.ContactRequest) error {
	return nil
}

// mountedLoginRuntime is the account login runtime as main.go builds it: its
// login-methods reads 开放注册 from the registration-config source. The pool
// is never connected (GET login-methods does not touch it).
func mountedLoginRuntime(t *testing.T, source RegistrationConfigSource) MountedHandlerFactory {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), "postgres://unused@127.0.0.1:1/unused")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	service, err := accountloginchallenge.NewService(pool, accountloginchallenge.Config{
		DigestKey: bytes.Repeat([]byte{3}, 32), Policy: loginPolicyStub{}, Issuer: loginIssuerStub{}, Contacts: loginContactsStub{},
		Registration: LoginMethodsRegistration{Source: source},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := accountloginchallengehttp.NewHandler(service,
		accountloginchallengehttp.TrustedContextResolverFunc(func(*http.Request) (accountloginchallengehttp.TrustedContext, error) {
			return accountloginchallengehttp.TrustedContext{ScopeID: uuid.New(), SourceIP: "192.0.2.44"}, nil
		}), accountloginchallengehttp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return func() (http.Handler, error) { return handler, nil }
}

func publicData(t *testing.T, api http.Handler, path string) map[string]any {
	t.Helper()
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data
}

// with 开放注册 on, registration-config said
// registration_enabled=true (mode builtin) while the mounted login runtime's
// login-methods said false (accountloginchallenge.Service.Methods ANDed the
// switch with "Turnstile runtime mounted"). Both endpoints now answer from
// the same projection, with and without the login runtime, for the built-in
// and the Turnstile ("verified") flow.
func TestLoginMethodsRegistrationMatchesRegistrationConfig(t *testing.T) {
	for _, loginMounted := range []bool{false, true} {
		for _, mode := range []string{"builtin", "verified"} {
			config := &RegistrationConfig{}
			source := switchableRegistrationConfig{config: config}
			apiConfig := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), RegistrationConfig: source}
			if loginMounted {
				apiConfig.AccountLoginHandlerFactory = mountedLoginRuntime(t, source)
			}
			api := New(nil, nil, apiConfig).Handler()
			wantMode := map[string]string{"builtin": "builtin", "verified": ""}[mode]

			*config = RegistrationConfig{RegistrationEnabled: true, Mode: mode, HumanCheck: "builtin_captcha", Ready: true,
				Email: RegistrationChannel{Required: true, Available: true}}
			open, methods := publicData(t, api, "/v1/auth/registration-config"), publicData(t, api, "/v1/auth/login-methods")
			if open["registration_enabled"] != true || methods["registration_enabled"] != true || methods["registration_mode"] != wantMode {
				t.Fatalf("login mounted=%t mode=%s open: config=%v methods=%v", loginMounted, mode, open, methods)
			}

			*config = RegistrationConfig{Mode: "closed", HumanCheck: "builtin_captcha"}
			closed, methods := publicData(t, api, "/v1/auth/registration-config"), publicData(t, api, "/v1/auth/login-methods")
			if closed["registration_enabled"] != false || methods["registration_enabled"] != false || methods["registration_mode"] != "" {
				t.Fatalf("login mounted=%t mode=%s closed: config=%v methods=%v", loginMounted, mode, closed, methods)
			}
		}
	}
}
