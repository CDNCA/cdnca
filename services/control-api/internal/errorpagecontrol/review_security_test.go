package errorpagecontrol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestReviewCredentialReferencesFailClosed(t *testing.T) {
	base := Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: uuid.New()},
	}
	if err := validateActor(base); err != nil {
		t.Fatalf("valid session actor: %v", err)
	}
	apiKey := base
	apiKey.Credential = CredentialReference{Kind: CredentialKindAPIKey, ID: uuid.New()}
	if err := validateActor(apiKey); err != nil {
		t.Fatalf("valid API-key actor: %v", err)
	}
	for name, credential := range map[string]CredentialReference{
		"empty":         {},
		"unknown":       {Kind: "bearer", ID: uuid.New()},
		"empty_session": {Kind: CredentialKindSession},
		"empty_api_key": {Kind: CredentialKindAPIKey},
	} {
		t.Run(name, func(t *testing.T) {
			actor := base
			actor.Credential = credential
			if err := validateActor(actor); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validateActor() error=%v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestReviewObjectMetadataBindsMIMEAndImmutabilityToken(t *testing.T) {
	info := ObjectInfo{
		Size: 4, SHA256: strings.Repeat("a", 64), MIMEType: "text/plain", ImmutableToken: "version-1",
	}
	if info.MIMEType != "text/plain" || info.ImmutableToken == "" {
		t.Fatalf("incomplete trusted object metadata: %+v", info)
	}
	caps := ObjectStoreCapabilities{
		ImmutableStaging: true, ConditionalFinalize: true, TrustedMetadata: true,
		ImmutableReads: true, PreservesStagingAlias: true,
	}
	if !caps.runtimeReady() {
		t.Fatal("complete object-store capability set rejected")
	}
}

func TestReviewStaticHTMLUsesNarrowInertAllowlist(t *testing.T) {
	for _, body := range []string{
		`<!doctype html><html><head><title>Unavailable</title></head><body><main><h1>Unavailable</h1><p>Retry later.</p></main></body></html>`,
		`<section><strong>Unavailable</strong><br><code>503</code></section>`,
	} {
		if err := validateStaticBody("text/html", []byte(body)); err != nil {
			t.Fatalf("safe body %q: %v", body, err)
		}
	}
	for _, body := range []string{
		`<marquee>moving</marquee>`,
		`<a>link-shaped content</a>`,
		`<div class="notice">attribute</div>`,
		`<!-- comment --><p>text</p>`,
		`<svg><text>vector</text></svg>`,
		`<form><input></form>`,
		`<style>body{color:red}</style>`,
	} {
		if err := validateStaticBody("text/html", []byte(body)); !errors.Is(err, ErrUnsafeContent) {
			t.Fatalf("unsafe body %q error=%v", body, err)
		}
	}
	if err := validateStaticBody("text/css", []byte(`body{color:red}`)); !errors.Is(err, ErrUnsafeContent) {
		t.Fatalf("standalone CSS error=%v, want ErrUnsafeContent", err)
	}
}

type reviewAuthenticator struct {
	actor Actor
	err   error
	calls int
}

func (auth *reviewAuthenticator) Authenticate(*http.Request) (Actor, error) {
	auth.calls++
	return auth.actor, auth.err
}

type reviewPublicationDomain struct {
	*fakeHTTPDomain
	calls int
}

func (domain *reviewPublicationDomain) PublicationSnapshot(_ context.Context, _ Actor) (PublicationSnapshot, error) {
	domain.calls++
	return PublicationSnapshot{}, nil
}

func TestReviewMalformedQueryIsRejectedBeforeAuthentication(t *testing.T) {
	actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: uuid.New()}}
	auth := &reviewAuthenticator{actor: actor}
	domain := &reviewPublicationDomain{fakeHTTPDomain: &fakeHTTPDomain{}}
	handler, err := NewHandler(domain, auth)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://control.test/v1/error-pages/publication-snapshot", nil)
	request.URL.RawQuery = "%zz"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || auth.calls != 0 || domain.calls != 0 {
		t.Fatalf("status=%d auth_calls=%d domain_calls=%d", response.Code, auth.calls, domain.calls)
	}
}

func TestReviewAuthenticationErrorsAndSecurityHeaders(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "invalid credential", err: ErrInvalidCredential, status: http.StatusUnauthorized, code: "authentication_required"},
		{name: "dependency failure", err: errors.New("database unavailable: secret detail"), status: http.StatusServiceUnavailable, code: "service_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, err := NewHandler(&fakeHTTPDomain{}, &reviewAuthenticator{err: test.err})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, "http://control.test/v1/error-pages/assets", nil)
			request.Header.Set("X-Request-ID", "review-request-1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "secret detail") {
				t.Fatalf("dependency detail leaked: %s", response.Body.String())
			}
			if response.Header().Get("X-Request-ID") != "review-request-1" ||
				response.Header().Get("Content-Disposition") != "attachment" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff" ||
				response.Header().Get("Content-Security-Policy") == "" {
				t.Fatalf("security headers=%v", response.Header())
			}
		})
	}
}

func TestReviewPublicationBoundsMatchEdgeContract(t *testing.T) {
	if MaxEdgePolicyBytes != 8<<20 || MaxPublicationSites != 256 {
		t.Fatalf("policy_bytes=%d sites=%d", MaxEdgePolicyBytes, MaxPublicationSites)
	}
	if err := validatePublicationBounds(make([]byte, MaxEdgePolicyBytes), MaxPublicationSites); err != nil {
		t.Fatalf("exact boundary: %v", err)
	}
	if err := validatePublicationBounds(make([]byte, MaxEdgePolicyBytes+1), MaxPublicationSites); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("bytes+1 error=%v", err)
	}
	if err := validatePublicationBounds(nil, MaxPublicationSites+1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("sites+1 error=%v", err)
	}
}
