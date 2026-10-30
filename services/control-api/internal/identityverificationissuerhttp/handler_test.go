package identityverificationissuerhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	identityverificationhttp "github.com/cdnca/cdnca/services/control-api/internal/identityverificationhttp"
	"github.com/google/uuid"
)

func TestHandlerIssuesOnlyBoundNonPlaintextEvidence(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	actor := testActor(t)
	principal := testPrincipal(actor)
	claimDigest := sha256.Sum256([]byte("claim"))
	envelopeDigest := sha256.Sum256([]byte("envelope"))
	objectReference := "private/kyc/opaque-1"
	evidence := identityverificationhttp.ResolvedEvidence{
		Kind:               identityverification.KindPersonalInitial,
		SubjectFingerprint: bytes.Repeat([]byte{0x31}, sha256.Size),
	}
	var gotResolve EvidenceResolveRequest
	var gotIssue identityverificationhttp.RuntimeEvidenceIssueRequest
	resolver := resolverFunc(func(_ context.Context, request EvidenceResolveRequest) (ResolvedEvidence, error) {
		gotResolve = request
		return ResolvedEvidence{
			Principal:              identityverificationhttp.RuntimeEvidencePrincipal{TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID, SessionID: actor.SessionID()},
			Kind:                   request.Kind,
			PrivateObjectReference: objectReference,
			PrivateEnvelopeDigest:  envelopeDigest,
			EvidenceClaimDigest:    claimDigest,
			Evidence:               evidence,
			ExpiresAt:              request.ExpiresAt,
			RequestDigest:          request.RequestDigest,
		}, nil
	})
	issuer := issuerFunc(func(_ context.Context, gotPrincipal identityverificationhttp.RuntimeEvidencePrincipal, request identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error) {
		if gotPrincipal.ActorUserID != actor.UserID || gotPrincipal.TenantScopeID != actor.ScopeID || gotPrincipal.SessionID != actor.SessionID() {
			t.Fatalf("issuer principal=%#v", gotPrincipal)
		}
		gotIssue = request
		return identityverificationhttp.RuntimeEvidenceIssueResult{
			Token:                 "opaque-issued-token",
			ResolverReference:     "trusted-kyc/reservation-1",
			EvidenceRequestDigest: sha256.Sum256([]byte("source-generated-request-digest")),
			EvidenceClaimDigest:   claimDigest,
			ExpiresAt:             request.ExpiresAt,
		}, nil
	})
	handler, err := NewHandler(Dependencies{Authenticator: authenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) {
		return principal, nil
	}), Resolver: resolver, Issuer: issuer, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	request := httptest.NewRequest(http.MethodPost, IssuePath,
		strings.NewReader(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"`+expiresAt+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-1")
	request.Header.Set("X-Request-ID", "request-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if gotResolve.WorkloadID != principal.WorkloadID || gotResolve.Audience != principal.Audience ||
		gotResolve.Kind != identityverification.KindPersonalInitial || gotResolve.EvidenceReference != "opaque-ref" ||
		!gotResolve.ExpiresAt.Equal(now.Add(5*time.Minute)) || gotResolve.IdempotencyKey != "idem-1" ||
		gotResolve.RequestID != "request-1" {
		t.Fatalf("resolver request=%#v", gotResolve)
	}
	expectedIssuerDigest := requestDigestForTest(principal, identityverification.KindPersonalInitial,
		"opaque-ref", now.Add(5*time.Minute), "idem-1", "request-1")
	if gotIssue.PrivateObjectReference != objectReference || gotIssue.PrivateEnvelopeDigest != envelopeDigest ||
		gotIssue.EvidenceClaimDigest != claimDigest || gotIssue.Evidence.Kind != evidence.Kind ||
		gotIssue.ExpiresAt != now.Add(5*time.Minute) || gotIssue.RequestID != "request-1" ||
		gotIssue.IssuerWorkloadID != principal.WorkloadID ||
		gotIssue.IssuerCertificateFingerprint != principal.CertificateFingerprint ||
		gotIssue.IssuerIdempotencyKey != "idem-1" || gotIssue.IssuerRequestDigest != expectedIssuerDigest {
		t.Fatalf("issue request=%#v", gotIssue)
	}
	var responseFields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &responseFields); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"token", "resolver_reference", "evidence_digest", "expires_at"} {
		if _, ok := responseFields[field]; !ok {
			t.Fatalf("missing response field %q: %s", field, response.Body.String())
		}
	}
	if len(responseFields) != 4 || strings.Contains(response.Body.String(), objectReference) ||
		strings.Contains(response.Body.String(), "envelope") || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("sensitive response=%s", response.Body.String())
	}
}

func TestHandlerRejectsUntrustedOrMalformedIssuerRequests(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	actor := testActor(t)
	validPrincipal := testPrincipal(actor)
	baseDependencies := func(principal WorkloadPrincipal, authErr error, resolverErr, issuerErr error) Dependencies {
		return Dependencies{
			Authenticator: authenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) { return principal, authErr }),
			Resolver: resolverFunc(func(_ context.Context, request EvidenceResolveRequest) (ResolvedEvidence, error) {
				resolved := validResolvedEvidence(actor, request.ExpiresAt)
				resolved.RequestDigest = request.RequestDigest
				return resolved, resolverErr
			}),
			Issuer: issuerFunc(func(context.Context, identityverificationhttp.RuntimeEvidencePrincipal, identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error) {
				return identityverificationhttp.RuntimeEvidenceIssueResult{}, issuerErr
			}),
			Clock: func() time.Time { return now },
		}
	}
	tests := []struct {
		name        string
		request     func(*http.Request)
		principal   WorkloadPrincipal
		authErr     error
		resolverErr error
		issuerErr   error
		path        string
		method      string
		wantStatus  int
		wantCode    string
	}{
		{name: "bearer rejected", request: func(r *http.Request) { r.Header.Set("Authorization", "Bearer session") }, principal: validPrincipal, wantStatus: http.StatusUnauthorized, wantCode: CodeAuthenticationRequired},
		{name: "session cookie rejected", request: func(r *http.Request) { r.Header.Set("Cookie", "session=secret") }, principal: validPrincipal, wantStatus: http.StatusUnauthorized, wantCode: CodeAuthenticationRequired},
		{name: "auth failure", principal: validPrincipal, authErr: ErrUnauthenticated, wantStatus: http.StatusUnauthorized, wantCode: CodeAuthenticationRequired},
		{name: "wrong audience", principal: func() WorkloadPrincipal { p := validPrincipal; p.Audience = "other"; return p }(), wantStatus: http.StatusForbidden, wantCode: CodePermissionDenied},
		{name: "missing permission", principal: func() WorkloadPrincipal { p := validPrincipal; p.Permissions = nil; return p }(), wantStatus: http.StatusForbidden, wantCode: CodePermissionDenied},
		{name: "cross scope", principal: func() WorkloadPrincipal { p := validPrincipal; p.WorkloadID = ""; return p }(), wantStatus: http.StatusForbidden, wantCode: CodePermissionDenied},
		{name: "unknown field plaintext", request: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"2026-08-06T10:05:00Z","document":"passport"}`))
		}, principal: validPrincipal, wantStatus: http.StatusBadRequest, wantCode: CodeInvalidRequest},
		{name: "wrong content type", request: func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, principal: validPrincipal, wantStatus: http.StatusBadRequest, wantCode: CodeInvalidRequest},
		{name: "expired", request: func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"2026-08-06T09:59:00Z"}`))
		}, principal: validPrincipal, wantStatus: http.StatusUnprocessableEntity, wantCode: CodeEvidenceInvalid},
		{name: "resolver unavailable sanitized", principal: validPrincipal, resolverErr: errors.New("kms object-secret provider SQL password"), wantStatus: http.StatusServiceUnavailable, wantCode: CodeEvidenceUnavailable},
		{name: "resolver replay conflict", principal: validPrincipal, resolverErr: ErrReplayConflict, wantStatus: http.StatusConflict, wantCode: CodeReplayConflict},
		{name: "issuer unavailable sanitized", principal: validPrincipal, issuerErr: errors.New("provider object-secret"), wantStatus: http.StatusServiceUnavailable, wantCode: CodeEvidenceUnavailable},
		{name: "wrong path", principal: validPrincipal, path: "/internal/v1/identity-verification/other", wantStatus: http.StatusNotFound},
		{name: "wrong method", principal: validPrincipal, method: http.MethodGet, wantStatus: http.StatusMethodNotAllowed, wantCode: CodeMethodNotAllowed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := test.path
			if path == "" {
				path = IssuePath
			}
			method := test.method
			if method == "" {
				method = http.MethodPost
			}
			handler, err := NewHandler(baseDependencies(test.principal, test.authErr, test.resolverErr, test.issuerErr))
			if err != nil {
				t.Fatal(err)
			}
			expiresAt := now.Add(5 * time.Minute).Format(time.RFC3339Nano)
			request := httptest.NewRequest(method, path,
				strings.NewReader(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"`+expiresAt+`"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "idem-1")
			request.Header.Set("X-Request-ID", "request-1")
			if test.request != nil {
				test.request(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.wantCode != "" && !strings.Contains(response.Body.String(), `"code":"`+test.wantCode+`"`) {
				t.Fatalf("body=%s", response.Body.String())
			}
			if strings.Contains(response.Body.String(), "object-secret") || strings.Contains(response.Body.String(), "password") || strings.Contains(response.Body.String(), "provider") {
				t.Fatalf("provider detail leaked: %s", response.Body.String())
			}
		})
	}
}

func TestHandlerRejectsResolverBindingMismatchBeforeIssue(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	actor := testActor(t)
	principal := testPrincipal(actor)
	mutations := map[string]func(*ResolvedEvidence, EvidenceResolveRequest){
		"actor": func(value *ResolvedEvidence, _ EvidenceResolveRequest) { value.Principal.ActorUserID = uuid.Nil },
		"scope": func(value *ResolvedEvidence, _ EvidenceResolveRequest) { value.Principal.TenantScopeID = uuid.Nil },
		"kind": func(value *ResolvedEvidence, _ EvidenceResolveRequest) {
			value.Kind = identityverification.KindEnterprise
			value.Evidence.Kind = identityverification.KindEnterprise
		},
		"expiry": func(value *ResolvedEvidence, request EvidenceResolveRequest) {
			value.ExpiresAt = request.ExpiresAt.Add(time.Second)
		},
		"request digest": func(value *ResolvedEvidence, _ EvidenceResolveRequest) { value.RequestDigest[0] ^= 0xff },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			issueCalls := 0
			handler, err := NewHandler(Dependencies{
				Authenticator: authenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) { return principal, nil }),
				Resolver: resolverFunc(func(_ context.Context, request EvidenceResolveRequest) (ResolvedEvidence, error) {
					resolved := validResolvedEvidence(actor, request.ExpiresAt)
					resolved.RequestDigest = request.RequestDigest
					mutate(&resolved, request)
					return resolved, nil
				}),
				Issuer: issuerFunc(func(context.Context, identityverificationhttp.RuntimeEvidencePrincipal, identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error) {
					issueCalls++
					return identityverificationhttp.RuntimeEvidenceIssueResult{}, nil
				}),
				Clock: func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			request := issuerRequest(now.Add(5 * time.Minute))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), `"code":"`+CodeEvidenceInvalid+`"`) || issueCalls != 0 {
				t.Fatalf("status=%d body=%s issue_calls=%d", response.Code, response.Body.String(), issueCalls)
			}
		})
	}
}

func TestHandlerStrictBodyAndIdempotencyBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	actor := testActor(t)
	principal := testPrincipal(actor)
	newHandler := func(t *testing.T) *Handler {
		t.Helper()
		handler, err := NewHandler(Dependencies{
			Authenticator: authenticatorFunc(func(*http.Request) (WorkloadPrincipal, error) { return principal, nil }),
			Resolver: resolverFunc(func(_ context.Context, request EvidenceResolveRequest) (ResolvedEvidence, error) {
				resolved := validResolvedEvidence(actor, request.ExpiresAt)
				resolved.RequestDigest = request.RequestDigest
				return resolved, nil
			}),
			Issuer: issuerFunc(func(context.Context, identityverificationhttp.RuntimeEvidencePrincipal, identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error) {
				return identityverificationhttp.RuntimeEvidenceIssueResult{Token: "token", ResolverReference: "ref", EvidenceRequestDigest: sha256.Sum256([]byte("request")), EvidenceClaimDigest: sha256.Sum256([]byte("claim")), ExpiresAt: now.Add(5 * time.Minute)}, nil
			}),
			Clock: func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		return handler
	}
	tests := []struct {
		name string
		body []byte
		edit func(*http.Request)
	}{
		{name: "duplicate json key", body: []byte(`{"kind":"personal_initial","kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"2026-08-06T10:05:00Z"}`)},
		{name: "invalid utf8", body: append([]byte(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"2026-08-06T10:05:00Z","x":"`), 0xff, '"', '}')},
		{name: "oversized body", body: []byte(`{"kind":"personal_initial","evidence_reference":"` + strings.Repeat("x", 17<<10) + `","expires_at":"2026-08-06T10:05:00Z"}`)},
		{name: "missing idempotency", body: []byte(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"2026-08-06T10:05:00Z"}`), edit: func(request *http.Request) { request.Header.Del("Idempotency-Key") }},
		{name: "duplicate idempotency", body: []byte(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"2026-08-06T10:05:00Z"}`), edit: func(request *http.Request) { request.Header.Add("Idempotency-Key", "idem-2") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, IssuePath, bytes.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "idem-1")
			request.Header.Set("X-Request-ID", "request-1")
			if test.edit != nil {
				test.edit(request)
			}
			response := httptest.NewRecorder()
			newHandler(t).ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"`+CodeInvalidRequest+`"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func issuerRequest(expiresAt time.Time) *http.Request {
	request := httptest.NewRequest(http.MethodPost, IssuePath, strings.NewReader(`{"kind":"personal_initial","evidence_reference":"opaque-ref","expires_at":"`+expiresAt.Format(time.RFC3339Nano)+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idem-1")
	request.Header.Set("X-Request-ID", "request-1")
	return request
}

type authenticatorFunc func(*http.Request) (WorkloadPrincipal, error)

func (function authenticatorFunc) Authenticate(request *http.Request) (WorkloadPrincipal, error) {
	return function(request)
}

type resolverFunc func(context.Context, EvidenceResolveRequest) (ResolvedEvidence, error)

func (function resolverFunc) Resolve(ctx context.Context, request EvidenceResolveRequest) (ResolvedEvidence, error) {
	return function(ctx, request)
}

type issuerFunc func(context.Context, identityverificationhttp.RuntimeEvidencePrincipal, identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error)

func (function issuerFunc) IssuePrincipal(ctx context.Context, principal identityverificationhttp.RuntimeEvidencePrincipal, request identityverificationhttp.RuntimeEvidenceIssueRequest) (identityverificationhttp.RuntimeEvidenceIssueResult, error) {
	return function(ctx, principal, request)
}

func testActor(t *testing.T) identityverification.Actor {
	t.Helper()
	actor, err := identityverification.NewSessionActor(uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		uuid.MustParse("22222222-2222-4222-8222-222222222222"), "tenant",
		uuid.MustParse("33333333-3333-4333-8333-333333333333"), "opaque-session")
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func testPrincipal(actor identityverification.Actor) WorkloadPrincipal {
	return WorkloadPrincipal{WorkloadID: "kyc-issuer-1", Audience: WorkloadAudience,
		Permissions:            []string{IssuePermission},
		CertificateFingerprint: sha256.Sum256([]byte("workload-cert"))}
}

func validResolvedEvidence(actor identityverification.Actor, expiresAt time.Time) ResolvedEvidence {
	return ResolvedEvidence{Principal: identityverificationhttp.RuntimeEvidencePrincipal{TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID, SessionID: actor.SessionID()},
		Kind: identityverification.KindPersonalInitial, PrivateObjectReference: "private/kyc/opaque-ref",
		PrivateEnvelopeDigest: sha256.Sum256([]byte("envelope")), EvidenceClaimDigest: sha256.Sum256([]byte("claim")),
		Evidence: identityverificationhttp.ResolvedEvidence{Kind: identityverification.KindPersonalInitial,
			SubjectFingerprint: bytes.Repeat([]byte{0x41}, sha256.Size)}, ExpiresAt: expiresAt}
}

func requestDigestForTest(principal WorkloadPrincipal, kind, reference string, expiresAt time.Time, idempotencyKey, requestID string) [32]byte {
	value := struct {
		WorkloadID, Audience, CertificateFingerprint, Kind, EvidenceReference, ExpiresAt, IdempotencyKey, RequestID string
	}{WorkloadID: principal.WorkloadID, Audience: principal.Audience,
		CertificateFingerprint: fmt.Sprintf("%x", principal.CertificateFingerprint[:]), Kind: kind,
		EvidenceReference: reference, ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
		IdempotencyKey: idempotencyKey, RequestID: requestID}
	encoded, _ := json.Marshal(value)
	return sha256.Sum256(append([]byte(requestDigestDomain), encoded...))
}
