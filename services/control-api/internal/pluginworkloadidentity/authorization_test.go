package pluginworkloadidentity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeprovider"
	"github.com/google/uuid"
)

var workloadTestNow = time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)

const frozenWorkloadRequestID = "16614cfbd30b6768b0938df650226f38f003d8e7611103e248a985c95b7eba76"

type providerStub struct {
	requests         []pluginruntimeprovider.Request
	identity         []byte
	decision         []byte
	returnedIdentity [][]byte
	returnedDecision [][]byte
	err              error
}

func (stub *providerStub) Resolve(_ context.Context,
	request pluginruntimeprovider.Request) (pluginruntimeprovider.Facts, error) {
	stub.requests = append(stub.requests, request)
	if stub.err != nil {
		return pluginruntimeprovider.Facts{}, stub.err
	}
	identity := append([]byte(nil), stub.identity...)
	decision := append([]byte(nil), stub.decision...)
	stub.returnedIdentity = append(stub.returnedIdentity, identity)
	stub.returnedDecision = append(stub.returnedDecision, decision)
	return pluginruntimeprovider.Facts{IdentityJSON: identity, DecisionJSON: decision}, nil
}

type verifierStub struct {
	expected      []pluginruntimeauth.ExpectedAction
	identities    [][]byte
	decisions     [][]byte
	authorization pluginruntimeauth.Authorization
	err           error
	authorize     func(pluginruntimeauth.ExpectedAction) pluginruntimeauth.Authorization
}

func (stub *verifierStub) Authorize(identityJSON, decisionJSON []byte,
	expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
	stub.identities = append(stub.identities, identityJSON)
	stub.decisions = append(stub.decisions, decisionJSON)
	stub.expected = append(stub.expected, expected)
	if stub.err != nil {
		return pluginruntimeauth.Authorization{}, stub.err
	}
	if stub.authorize != nil {
		return stub.authorize(expected), nil
	}
	return stub.authorization, nil
}

func TestAuthorizeBindsExactWorkloadActionAndSealsAuthorization(t *testing.T) {
	request := validWorkloadRequest()
	inputIdentity := append([]byte(nil), request.ServiceIdentityJSON...)
	provider := &providerStub{identity: request.ServiceIdentityJSON, decision: []byte(`{"schema":"signed-decision"}`)}
	verifier := &verifierStub{authorization: matchingWorkloadAuthorization(frozenWorkloadRequestID, request)}
	authorizer := newTestAuthorizer(t, provider, verifier)

	sealed, err := authorizer.Authorize(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(provider.requests) != 1 || provider.requests[0].RequestID != frozenWorkloadRequestID {
		t.Fatalf("provider requests = %+v", provider.requests)
	}
	gotRequest := provider.requests[0]
	// The license customer is bound to the installation; control does not claim one (tenant IDs differ).
	if gotRequest.CustomerID != uuid.Nil || gotRequest.InstallationID != request.InstallationID ||
		gotRequest.Action != request.Action || gotRequest.ManifestSHA256 != request.ManifestSHA256 ||
		gotRequest.VerificationID != request.VerificationID || gotRequest.AttestationID != request.AttestationID ||
		gotRequest.AttestationRevision != request.AttestationRevision ||
		gotRequest.KnownApprovalRevision != request.ApprovalRevision || gotRequest.CapabilityKind != request.CapabilityKind ||
		gotRequest.CapabilityCode != request.CapabilityCode || !gotRequest.RequestedAt.Equal(request.RequestedAt) {
		t.Fatalf("provider request = %+v", gotRequest)
	}
	if len(verifier.expected) != 1 || verifier.expected[0] != (pluginruntimeauth.ExpectedAction{
		InstallationID: request.InstallationID, RequestID: frozenWorkloadRequestID,
		CapabilityKind: request.CapabilityKind, CapabilityCode: request.CapabilityCode, Action: request.Action,
	}) {
		t.Fatalf("verifier expected = %+v", verifier.expected)
	}
	if !sealed.ValidFor(request, workloadTestNow) || sealed.RequestID() != frozenWorkloadRequestID ||
		sealed.TenantID() != request.TenantID || sealed.InstallationID() != request.InstallationID ||
		sealed.InvocationID() != request.InvocationID || sealed.PluginID() != request.PluginID ||
		sealed.CapabilityKind() != request.CapabilityKind || sealed.CapabilityCode() != request.CapabilityCode ||
		sealed.Action() != request.Action || !sealed.ExpiresAt().Equal(workloadTestNow.Add(45*time.Second)) {
		t.Fatalf("sealed authorization does not match exact request")
	}
	if _, err := json.Marshal(sealed); err == nil || fmt.Sprint(sealed) != "pluginworkloadidentity.Authorization{sealed}" ||
		fmt.Sprintf("%#v", sealed) != "pluginworkloadidentity.Authorization{sealed}" {
		t.Fatal("sealed authorization is serializable or exposes internals")
	}
	if !bytes.Equal(request.ServiceIdentityJSON, inputIdentity) {
		t.Fatal("Authorize mutated caller-owned service identity")
	}
	if !zeroed(provider.requests[0].ServiceIdentityJSON) || !zeroed(verifier.identities[0]) ||
		!zeroed(verifier.decisions[0]) || !zeroed(provider.returnedIdentity[0]) || !zeroed(provider.returnedDecision[0]) {
		t.Fatal("Authorize retained proof bytes")
	}

	mutations := []struct {
		name string
		edit func(*Request)
	}{
		{name: "tenant", edit: func(value *Request) { value.TenantID = uuid.MustParse("11111111-1111-4111-8111-111111111112") }},
		{name: "installation", edit: func(value *Request) { value.InstallationID = uuid.MustParse("22222222-2222-4222-8222-222222222223") }},
		{name: "invocation", edit: func(value *Request) { value.InvocationID = uuid.MustParse("018f47de-0f4a-7c4b-8f3b-f8d51df94b7a") }},
		{name: "plugin", edit: func(value *Request) { value.PluginID = "other.runtime" }},
		{name: "capability kind", edit: func(value *Request) { value.CapabilityKind, value.CapabilityCode = "webhook", "plugin.callback" }},
		{name: "capability code", edit: func(value *Request) { value.CapabilityCode = "plugin.write" }},
		{name: "action", edit: func(value *Request) { value.Action = "site.config.write" }},
		{name: "requested at", edit: func(value *Request) { value.RequestedAt = value.RequestedAt.Add(-time.Second) }},
		{name: "identity", edit: func(value *Request) { value.ServiceIdentityJSON = []byte(`{"schema":"other-identity"}`) }},
		{name: "manifest", edit: func(value *Request) { value.ManifestSHA256 = strings.Repeat("b", 64) }},
		{name: "verification", edit: func(value *Request) { value.VerificationID = uuid.MustParse("44444444-4444-4444-8444-444444444445") }},
		{name: "attestation", edit: func(value *Request) { value.AttestationID = uuid.MustParse("55555555-5555-4555-8555-555555555556") }},
		{name: "attestation revision", edit: func(value *Request) { value.AttestationRevision++ }},
		{name: "approval revision", edit: func(value *Request) { value.ApprovalRevision++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := cloneWorkloadRequest(request)
			mutation.edit(&changed)
			if sealed.ValidFor(changed, workloadTestNow) {
				t.Fatal("sealed authorization accepted a changed binding")
			}
		})
	}
	if sealed.ValidFor(request, sealed.ExpiresAt()) {
		t.Fatal("sealed authorization remained valid at expiry")
	}
}

func TestAuthorizeAlwaysCallsProviderAndFreshInvocationChangesRequestID(t *testing.T) {
	request := validWorkloadRequest()
	provider := &providerStub{identity: request.ServiceIdentityJSON, decision: []byte(`{"schema":"signed-decision"}`)}
	verifier := &verifierStub{authorize: func(expected pluginruntimeauth.ExpectedAction) pluginruntimeauth.Authorization {
		return matchingWorkloadAuthorization(expected.RequestID, request)
	}}
	authorizer := newTestAuthorizer(t, provider, verifier)
	if _, err := authorizer.Authorize(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := authorizer.Authorize(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	fresh := cloneWorkloadRequest(request)
	fresh.InvocationID = uuid.MustParse("018f47de-0f4a-7c4b-8f3b-f8d51df94b7a")
	if _, err := authorizer.Authorize(t.Context(), fresh); err != nil {
		t.Fatal(err)
	}
	if len(provider.requests) != 3 || len(verifier.expected) != 3 ||
		provider.requests[0].RequestID != provider.requests[1].RequestID ||
		provider.requests[2].RequestID == provider.requests[0].RequestID {
		t.Fatalf("provider request IDs = %+v", provider.requests)
	}
}

func TestAuthorizeDefaultsDeniedForDependencyErrorsAndBindingMismatches(t *testing.T) {
	request := validWorkloadRequest()
	for _, test := range []struct {
		name       string
		provider   error
		verifier   error
		editFacts  func(*providerStub)
		editResult func(*pluginruntimeauth.Authorization)
		want       error
	}{
		{name: "provider unavailable", provider: pluginruntimeprovider.ErrUnavailable, want: ErrUnavailable},
		{name: "provider rate limited", provider: pluginruntimeprovider.ErrRateLimited, want: ErrRateLimited},
		{name: "provider denied", provider: pluginruntimeprovider.ErrDenied, want: ErrDenied},
		{name: "provider invalid", provider: pluginruntimeprovider.ErrInvalid, want: ErrDenied},
		{name: "verifier unavailable", verifier: pluginruntimeauth.ErrTrustUnavailable, want: ErrUnavailable},
		{name: "verifier rate limited", verifier: pluginruntimeauth.ErrRateLimited, want: ErrRateLimited},
		{name: "verifier denied", verifier: pluginruntimeauth.ErrDenied, want: ErrDenied},
		{name: "verifier invalid", verifier: pluginruntimeauth.ErrInvalid, want: ErrDenied},
		{name: "identity changed", editFacts: func(value *providerStub) { value.identity = []byte(`{"schema":"other-identity"}`) }, want: ErrDenied},
		{name: "plugin changed", editResult: func(value *pluginruntimeauth.Authorization) { value.PluginID = "other.runtime" }, want: ErrDenied},
		{name: "manifest changed", editResult: func(value *pluginruntimeauth.Authorization) { value.ManifestSHA256 = strings.Repeat("b", 64) }, want: ErrDenied},
		{name: "verification changed", editResult: func(value *pluginruntimeauth.Authorization) { value.VerificationID = uuid.New() }, want: ErrDenied},
		{name: "attestation changed", editResult: func(value *pluginruntimeauth.Authorization) { value.AttestationRevision++ }, want: ErrDenied},
		{name: "approval changed", editResult: func(value *pluginruntimeauth.Authorization) { value.ApprovalRevision++ }, want: ErrDenied},
		{name: "expired", editResult: func(value *pluginruntimeauth.Authorization) { value.ExpiresAt = workloadTestNow }, want: ErrDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &providerStub{identity: request.ServiceIdentityJSON, decision: []byte(`{"schema":"signed-decision"}`), err: test.provider}
			if test.editFacts != nil {
				test.editFacts(provider)
			}
			authorization := matchingWorkloadAuthorization(frozenWorkloadRequestID, request)
			if test.editResult != nil {
				test.editResult(&authorization)
			}
			verifier := &verifierStub{authorization: authorization, err: test.verifier}
			authorizer := newTestAuthorizer(t, provider, verifier)
			sealed, err := authorizer.Authorize(t.Context(), request)
			if !errors.Is(err, test.want) || sealed.ValidFor(request, workloadTestNow) {
				t.Fatalf("Authorize() = (%v, %v), want %v", sealed, err, test.want)
			}
		})
	}
}

func TestNewAuthorizerAndRequestValidationFailClosed(t *testing.T) {
	request := validWorkloadRequest()
	provider := &providerStub{identity: request.ServiceIdentityJSON, decision: []byte(`{"schema":"signed-decision"}`)}
	verifier := &verifierStub{authorization: matchingWorkloadAuthorization(frozenWorkloadRequestID, request)}
	var nilProvider *providerStub
	for _, config := range []Config{
		{Verifier: verifier, Now: func() time.Time { return workloadTestNow }},
		{Provider: provider, Now: func() time.Time { return workloadTestNow }},
		{Provider: nilProvider, Verifier: verifier, Now: func() time.Time { return workloadTestNow }},
		{Provider: provider, Verifier: verifier},
		{Provider: provider, Verifier: verifier, Now: func() time.Time { return time.Time{} }},
	} {
		if _, err := NewAuthorizer(config); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("NewAuthorizer() error = %v", err)
		}
	}
	authorizer := newTestAuthorizer(t, provider, verifier)
	mutations := []func(*Request){
		func(value *Request) { value.TenantID = uuid.Nil },
		func(value *Request) { value.InstallationID = uuid.Nil },
		func(value *Request) { value.InvocationID = uuid.New() },
		func(value *Request) { value.PluginID = "invalid" },
		func(value *Request) { value.CapabilityKind = "invalid" },
		func(value *Request) { value.CapabilityCode = "invalid" },
		func(value *Request) { value.Action = "Invalid Action" },
		func(value *Request) { value.ServiceIdentityJSON = nil },
		func(value *Request) { value.ManifestSHA256 = strings.Repeat("A", 64) },
		func(value *Request) { value.VerificationID = uuid.Nil },
		func(value *Request) { value.AttestationID = uuid.Nil },
		func(value *Request) { value.AttestationRevision = 0 },
		func(value *Request) { value.ApprovalRevision = 0 },
		func(value *Request) { value.RequestedAt = value.RequestedAt.Add(time.Nanosecond) },
		func(value *Request) { value.RequestedAt = value.RequestedAt.In(time.FixedZone("offset", 3600)) },
		func(value *Request) { value.RequestedAt = workloadTestNow.Add(-5*time.Minute - time.Second) },
		func(value *Request) { value.RequestedAt = workloadTestNow.Add(time.Minute + time.Second) },
	}
	for index, mutate := range mutations {
		changed := cloneWorkloadRequest(request)
		mutate(&changed)
		if _, err := authorizer.Authorize(t.Context(), changed); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("mutation %d error = %v", index, err)
		}
	}
	if _, err := authorizer.Authorize(nil, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error = %v", err)
	}
	if len(provider.requests) != 0 || len(verifier.expected) != 0 {
		t.Fatalf("invalid input reached dependencies: provider=%d verifier=%d", len(provider.requests), len(verifier.expected))
	}
}

func newTestAuthorizer(t *testing.T, provider Provider, verifier Verifier) *Authorizer {
	t.Helper()
	authorizer, err := NewAuthorizer(Config{Provider: provider, Verifier: verifier, Now: func() time.Time { return workloadTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func validWorkloadRequest() Request {
	return Request{
		TenantID:            uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		InstallationID:      uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		InvocationID:        uuid.MustParse("018f47de-0f4a-7c4b-8f3b-f8d51df94b79"),
		PluginID:            "acme.runtime",
		CapabilityKind:      "scope",
		CapabilityCode:      "plugin.read",
		Action:              "plugin.read",
		ServiceIdentityJSON: []byte(`{"schema":"signed-identity"}`),
		ManifestSHA256:      strings.Repeat("a", 64),
		VerificationID:      uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		AttestationID:       uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		AttestationRevision: 9,
		ApprovalRevision:    4,
		RequestedAt:         workloadTestNow,
	}
}

func matchingWorkloadAuthorization(requestID string, request Request) pluginruntimeauth.Authorization {
	return pluginruntimeauth.Authorization{
		RequestID: requestID, CustomerID: licenseCustomerForTest, Action: request.Action,
		InstallationID:  request.InstallationID,
		AuthorizationID: uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		TokenID:         uuid.MustParse("77777777-7777-4777-8777-777777777777"), IdentityGeneration: 3,
		PluginID: request.PluginID, PluginVersion: "1.2.3", ManifestSHA256: request.ManifestSHA256,
		VerificationID: request.VerificationID, AttestationID: request.AttestationID,
		AttestationRevision: request.AttestationRevision,
		ApprovalReceiptID:   uuid.MustParse("88888888-8888-4888-8888-888888888888"),
		ApprovalRevision:    request.ApprovalRevision,
		CapabilityKind:      request.CapabilityKind, CapabilityCode: request.CapabilityCode,
		EvaluatedAt: workloadTestNow, ExpiresAt: workloadTestNow.Add(45 * time.Second),
	}
}

func cloneWorkloadRequest(request Request) Request {
	request.ServiceIdentityJSON = append([]byte(nil), request.ServiceIdentityJSON...)
	return request
}

func zeroed(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

// licenseCustomerForTest is the platform customer the license service derives from the installation. It is a
// different ID space from the control tenant on purpose.
var licenseCustomerForTest = uuid.MustParse("abababab-abab-4bab-8bab-abababababab")
