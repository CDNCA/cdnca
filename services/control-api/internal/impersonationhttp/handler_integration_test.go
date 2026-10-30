package impersonationhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/impersonation"
)

func TestSessionAuthorizerFailsClosedBeforeCoreOnMissingOrDuplicateCredential(t *testing.T) {
	var calls int
	service := &serviceStub{authorize: func(context.Context, impersonation.UseRequest) (impersonation.EffectiveIdentity, error) {
		calls++
		return impersonation.EffectiveIdentity{}, errors.New("must not be called")
	}}
	authorizer, err := NewSessionAuthorizer(service, decoderStub(func(context.Context, string) (impersonation.Session, error) {
		t.Fatal("decoder must not be called")
		return impersonation.Session{}, nil
	}), HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}

	for _, mutate := range []func(*http.Request){
		func(*http.Request) {},
		func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: CookieName, Value: "one"})
			request.AddCookie(&http.Cookie{Name: CookieName, Value: "two"})
		},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/sites", nil)
		request.Header.Set("X-Request-ID", "authorize-rejected")
		request.Header.Set("Traceparent", testTraceparent)
		mutate(request)
		if _, err := authorizer.Authorize(request, "sites.read"); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Authorize() error = %v, want %v", err, ErrUnauthenticated)
		}
	}
	if calls != 0 {
		t.Fatalf("core authorize calls = %d", calls)
	}
}
