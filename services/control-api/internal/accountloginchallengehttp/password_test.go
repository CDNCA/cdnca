package accountloginchallengehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoverycontext"
	"github.com/google/uuid"
)

type passwordRequestCapture struct {
	fakeLoginService
	calls int
	input accountloginchallenge.PasswordCreateInput
}

func (fake *passwordRequestCapture) CreatePassword(_ context.Context, input accountloginchallenge.PasswordCreateInput) (accountloginchallenge.CreateResult, error) {
	fake.calls++
	fake.input = input
	return accountloginchallenge.CreateResult{ChallengeID: uuid.New(), ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func TestPasswordChallengeUsesCredentialScopeAndTrustedSourceOnly(t *testing.T) {
	fake := new(passwordRequestCapture)
	source, err := accountrecoverycontext.NewSourceIPResolver(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	hostCalls := 0
	handler, err := NewHandler(fake, TrustedContextResolverFunc(func(*http.Request) (TrustedContext, error) {
		hostCalls++
		return TrustedContext{}, errors.New("platform host must not choose tenant credential scope")
	}), Config{SourceIPResolver: source})
	if err != nil {
		t.Fatal(err)
	}
	scopeID := uuid.NewString()
	for _, test := range []struct {
		name, body, forwarded string
		status                int
	}{
		{"valid", `{"username":"alice","password":"secret-in-memory","scope_id":"` + scopeID + `"}`, "", 202},
		{"mixed identifier", `{"username":"alice","password":"secret","identifier":"","channel":"email"}`, "", 422},
		{"missing password", `{"username":"alice"}`, "", 422},
		{"null password shape", `{"username":null,"identifier":"user@example.com","channel":"email"}`, "", 422},
		{"null mixed identifier", `{"username":"alice","password":"secret","identifier":null}`, "", 422},
		{"null scope", `{"username":"alice","password":"secret","scope_id":null}`, "", 422},
		{"duplicate password", `{"username":"alice","password":"first","password":"second"}`, "", 422},
		{"spoofed source", `{"username":"alice","password":"secret"}`, "203.0.113.1", 403},
		{"source body", `{"username":"alice","password":"secret","source":"192.0.2.1"}`, "", 422},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", ChallengePath, strings.NewReader(test.body))
			r.RemoteAddr = "192.0.2.1:4567"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "password-create")
			r.Header.Set("X-Request-ID", "password-request")
			if test.forwarded != "" {
				r.Header.Set("X-Forwarded-For", test.forwarded)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status=%d response=%s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "secret") || len(w.Result().Cookies()) != 0 {
				t.Fatal("challenge response leaked credentials or created session")
			}
		})
	}
	if hostCalls != 0 || fake.calls != 1 || fake.input.Source != "192.0.2.1" || fake.input.Login.ScopeID == nil || fake.input.Login.ScopeID.String() != scopeID {
		t.Fatalf("host calls=%d password calls=%d", hostCalls, fake.calls)
	}
}
