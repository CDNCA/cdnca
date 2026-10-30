package pluginruntimecomposition

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeauth"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginruntimeprovider"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginwebhook"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginworkloadidentity"
	"github.com/google/uuid"
)

var compositionTestNow = time.Date(2026, 8, 7, 8, 0, 0, 0, time.UTC)

func TestProjectionClientUsesMTLSCanonicalProofAndVerifiesProjection(t *testing.T) {
	fixture := newProjectionFixture(t)
	defer fixture.close()
	client := fixture.client(t)
	request := fixture.request("projection-request-1")

	projection, err := client.Resolve(t.Context(), request)
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if projection.RequestID != request.RequestID || projection.InstallationID != request.InstallationID ||
		projection.CertificateID != fixture.certificateID || projection.AuthorizationID == uuid.Nil ||
		!bytes.Equal(projection.ServiceIdentityJSON, fixture.identityJSON) {
		t.Fatalf("projection = %+v", projection)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression ||
		transport.MaxResponseHeaderBytes != maximumResponseHeaderBytes || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("transport = %#v", client.http.Transport)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if !fixture.sawClientCertificate || !fixture.sawCanonicalProof || fixture.requests != 1 {
		t.Fatalf("mTLS=%t proof=%t requests=%d", fixture.sawClientCertificate, fixture.sawCanonicalProof, fixture.requests)
	}
}

func TestProjectionClientRejectsNoncanonicalUntrustedStaleAndTransportResponses(t *testing.T) {
	for _, test := range []struct {
		name string
		mode projectionResponseMode
		want error
	}{
		{name: "missing LF", mode: projectionMissingLF, want: ErrInvalid},
		{name: "unknown field", mode: projectionUnknownField, want: ErrInvalid},
		{name: "duplicate field", mode: projectionDuplicateField, want: ErrInvalid},
		{name: "content encoding", mode: projectionContentEncoding, want: ErrInvalid},
		{name: "bad signature", mode: projectionBadSignature, want: ErrInvalid},
		{name: "wrong key", mode: projectionWrongKey, want: ErrInvalid},
		{name: "echo mismatch", mode: projectionEchoMismatch, want: ErrDenied},
		{name: "issued before request", mode: projectionIssuedBeforeRequest, want: ErrDenied},
		{name: "expired", mode: projectionExpired, want: ErrDenied},
		{name: "body overflow", mode: projectionBodyOverflow, want: ErrInvalid},
		{name: "redirect", mode: projectionRedirect, want: ErrInvalid},
		{name: "revoked", mode: projectionRevoked, want: ErrDenied},
		{name: "conflict", mode: projectionConflict, want: ErrDenied},
		{name: "rate limited", mode: projectionRateLimited, want: ErrUnavailable},
		{name: "unavailable", mode: projectionUnavailable, want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProjectionFixture(t)
			defer fixture.close()
			fixture.mode = test.mode
			_, err := fixture.client(t).Resolve(t.Context(), fixture.request("strict-projection"))
			if !errors.Is(err, test.want) {
				t.Fatalf("Resolve() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProjectionClientRejectsIncompleteConfiguration(t *testing.T) {
	fixture := newProjectionFixture(t)
	defer fixture.close()
	valid := fixture.config()
	for _, test := range []struct {
		name string
		edit func(*ProjectionClientConfig)
	}{
		{name: "HTTP", edit: func(value *ProjectionClientConfig) { value.BaseURL = "http://license.test" }},
		{name: "path", edit: func(value *ProjectionClientConfig) { value.BaseURL += "/api" }},
		{name: "roots", edit: func(value *ProjectionClientConfig) { value.TLSConfig.RootCAs = nil }},
		{name: "client certificate", edit: func(value *ProjectionClientConfig) { value.TLSConfig.Certificates = nil }},
		{name: "installation", edit: func(value *ProjectionClientConfig) { value.InstallationID = uuid.Nil }},
		{name: "trust", edit: func(value *ProjectionClientConfig) { value.Trust = nil }},
		{name: "clock", edit: func(value *ProjectionClientConfig) { value.Now = nil }},
		{name: "timeout", edit: func(value *ProjectionClientConfig) { value.Timeout = 6 * time.Second }},
		{name: "body", edit: func(value *ProjectionClientConfig) { value.MaxBodyBytes = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.TLSConfig = valid.TLSConfig.Clone()
			test.edit(&candidate)
			if _, err := NewProjectionClient(candidate); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewProjectionClient() error = %v", err)
			}
		})
	}
}

func TestProjectionClientUsesOneDynamicCredentialSnapshotPerResolve(t *testing.T) {
	fixture := newProjectionFixture(t)
	defer fixture.close()
	master := RuntimeCredential{CertificateID: fixture.certificateID,
		PrivateKey:     append(ed25519.PrivateKey(nil), fixture.clientPrivate...),
		TLSCertificate: cloneTestTLSCertificate(fixture.clientTLS.Certificates[0]),
		RootCAs:        fixture.clientTLS.RootCAs.Clone()}
	source := &recordingRuntimeCredentialSource{credential: master}
	config := fixture.config()
	config.TLSConfig = nil
	config.Credentials = source
	client, err := NewProjectionClient(config)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		request := fixture.request(fmt.Sprintf("dynamic-projection-%d", index+1))
		projection, resolveErr := client.Resolve(t.Context(), request)
		if resolveErr != nil {
			t.Fatalf("Resolve(%d) error = %v", index+1, resolveErr)
		}
		if projection.CertificateID != master.CertificateID {
			t.Fatalf("Resolve(%d) certificate = %s", index+1, projection.CertificateID)
		}
	}
	calls, returned, preserved := source.snapshot()
	if calls != 2 || len(returned) != 2 {
		t.Fatalf("Ensure calls=%d returned=%d", calls, len(returned))
	}
	for index, credential := range returned {
		if !allZero(credential.PrivateKey) {
			t.Errorf("returned private key %d was not cleared", index)
		}
		private, ok := credential.TLSCertificate.PrivateKey.(ed25519.PrivateKey)
		if !ok || !allZero(private) {
			t.Errorf("returned TLS private key %d was not cleared", index)
		}
	}
	if allZero(preserved.PrivateKey) {
		t.Fatal("credential source master private key was corrupted")
	}
	private, ok := preserved.TLSCertificate.PrivateKey.(ed25519.PrivateKey)
	if !ok || allZero(private) {
		t.Fatal("credential source master TLS key was corrupted")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.requests != 2 || !fixture.sawClientCertificate || !fixture.sawCanonicalProof {
		t.Fatalf("requests=%d mTLS=%t proof=%t", fixture.requests, fixture.sawClientCertificate, fixture.sawCanonicalProof)
	}
}

func TestProjectionClientRejectsAmbiguousStaticAndDynamicCredentials(t *testing.T) {
	fixture := newProjectionFixture(t)
	defer fixture.close()
	config := fixture.config()
	config.Credentials = &recordingRuntimeCredentialSource{credential: RuntimeCredential{
		CertificateID: fixture.certificateID, PrivateKey: append(ed25519.PrivateKey(nil), fixture.clientPrivate...),
		TLSCertificate: cloneTestTLSCertificate(fixture.clientTLS.Certificates[0]), RootCAs: fixture.clientTLS.RootCAs.Clone()}}
	if _, err := NewProjectionClient(config); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewProjectionClient() error = %v, want %v", err, ErrInvalidConfiguration)
	}
}

func TestWebhookDelivererUsesFreshAttemptAuthorizationWithoutChangingDeliveryIdentity(t *testing.T) {
	installationID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	projection := validProjection("first", installationID)
	expectedIdentity := append([]byte(nil), projection.ServiceIdentityJSON...)
	var projectionRequests []ProjectionRequest
	var resolvedIdentities [][]byte
	resolver := projectionResolverFunc(func(_ context.Context, request ProjectionRequest) (Projection, error) {
		projectionRequests = append(projectionRequests, request)
		result := projection
		result.RequestID = request.RequestID
		result.CapabilityKind = request.CapabilityKind
		result.CapabilityCode = request.CapabilityCode
		result.ServiceIdentityJSON = append([]byte(nil), expectedIdentity...)
		resolvedIdentities = append(resolvedIdentities, result.ServiceIdentityJSON)
		return result, nil
	})
	var authorizationRequests []pluginworkloadidentity.Request
	authorizer := workloadAuthorizerFunc(func(ctx context.Context, request pluginworkloadidentity.Request) (pluginworkloadidentity.Authorization, error) {
		authorizationRequests = append(authorizationRequests, copyWorkloadRequest(request))
		return sealWorkloadAuthorization(t, ctx, request), nil
	})
	delegate := &recordingDelegate{result: pluginwebhook.SendResult{Success: true, Code: "delivered", StatusCode: 204}}
	deliverer, err := NewWebhookDeliverer(WebhookDelivererConfig{InstallationID: installationID,
		Projection: resolver, Authorizer: authorizer, Delegate: delegate, Now: func() time.Time { return compositionTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	item := validV2Item()
	if item.Event.Type != "io.cdnca.dns.v1.changed" {
		t.Fatalf("event type = %q", item.Event.Type)
	}
	secret := []byte("01234567890123456789012345678901")
	for _, attempt := range []uint64{1, 2} {
		if result := deliverer.DeliverV2(t.Context(), item, attempt, secret); !result.Success {
			t.Fatalf("attempt %d result = %+v", attempt, result)
		}
	}
	if len(projectionRequests) != 2 || projectionRequests[0].RequestID == projectionRequests[1].RequestID ||
		projectionRequests[0].ConsumerID != item.SubscriptionID || projectionRequests[0].TargetScopeID != item.TargetScopeID ||
		projectionRequests[0].CapabilityKind != "webhook" || projectionRequests[0].CapabilityCode != "webhook.deliver" ||
		projectionRequests[1].CapabilityKind != "webhook" || projectionRequests[1].CapabilityCode != "webhook.deliver" {
		t.Fatalf("projection requests = %+v", projectionRequests)
	}
	if len(authorizationRequests) != 2 {
		t.Fatalf("authorization requests = %+v", authorizationRequests)
	}
	for _, request := range authorizationRequests {
		if request.TenantID != item.TenantID || request.InstallationID != installationID ||
			request.InvocationID != item.EventID || request.PluginID != "acme.runtime" ||
			request.CapabilityKind != "webhook" || request.CapabilityCode != "webhook.deliver" ||
			request.Action != "plugin.webhook.deliver" || !bytes.Equal(request.ServiceIdentityJSON, expectedIdentity) ||
			request.ManifestSHA256 != projection.ManifestSHA256 || request.VerificationID != projection.VerificationID ||
			request.AttestationID != projection.AttestationID || request.AttestationRevision != projection.AttestationRevision ||
			request.ApprovalRevision != projection.ApprovalRevision || !request.RequestedAt.Equal(compositionTestNow) {
			t.Fatalf("authorization request = %+v", request)
		}
	}
	if len(delegate.items) != 2 || delegate.items[0].DeliveryID != item.DeliveryID ||
		delegate.items[1].IdempotencyKey != item.IdempotencyKey || delegate.attempts[0] != 1 || delegate.attempts[1] != 2 ||
		delegate.items[0].Event.Type != "io.cdnca.dns.v1.changed" || delegate.items[1].Event.Type != "io.cdnca.dns.v1.changed" ||
		len(delegate.secrets) != 2 || !bytes.Equal(delegate.secrets[0], secret) || !bytes.Equal(delegate.secrets[1], secret) {
		t.Fatalf("delegate items=%+v attempts=%v secrets=%d", delegate.items, delegate.attempts, len(delegate.secrets))
	}
	for _, identity := range resolvedIdentities {
		if !allZero(identity) {
			t.Fatalf("projection identity was not cleared: %q", identity)
		}
	}
}

func TestWebhookDelivererFailsClosedBeforeDelegate(t *testing.T) {
	installationID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	for _, test := range []struct {
		name           string
		resolve        error
		identity       []byte
		authorize      error
		mismatchSealed bool
		wantCode       string
		retryable      bool
		rateLimited    bool
		wantCalls      int
	}{
		{name: "projection revoked", resolve: ErrDenied, wantCode: "runtime_authorization_denied"},
		{name: "projection stale", resolve: ErrInvalid, wantCode: "runtime_authorization_denied"},
		{name: "projection unavailable", resolve: ErrUnavailable, wantCode: "runtime_authorization_unavailable", retryable: true},
		{name: "malformed identity", identity: []byte(`{"authorization_id":`), wantCode: "runtime_authorization_denied"},
		{name: "missing plugin", identity: []byte(`{"authorization_id":"55555555-5555-4555-8555-555555555555"}`), wantCode: "runtime_authorization_denied"},
		{name: "authorization mismatch", identity: []byte(`{"authorization_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","plugin_id":"acme.runtime"}`), wantCode: "runtime_authorization_denied"},
		{name: "authorizer denied", authorize: pluginworkloadidentity.ErrDenied, wantCode: "runtime_authorization_denied", wantCalls: 1},
		{name: "authorizer unavailable", authorize: pluginworkloadidentity.ErrUnavailable, wantCode: "runtime_authorization_unavailable", retryable: true, wantCalls: 1},
		{name: "authorizer rate limited", authorize: pluginworkloadidentity.ErrRateLimited, wantCode: "runtime_rate_limited", retryable: true, rateLimited: true, wantCalls: 1},
		{name: "authorizer unknown", authorize: errors.New("unknown authorizer failure"), wantCode: "runtime_authorization_denied", wantCalls: 1},
		{name: "sealed authorization mismatch", mismatchSealed: true, wantCode: "runtime_authorization_denied", wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection := validProjection("request", installationID)
			if test.identity != nil {
				projection.ServiceIdentityJSON = append([]byte(nil), test.identity...)
			}
			delegate := &recordingDelegate{}
			resolver := projectionResolverFunc(func(_ context.Context, request ProjectionRequest) (Projection, error) {
				result := projection
				result.RequestID = request.RequestID
				return result, test.resolve
			})
			calls := 0
			authorizer := workloadAuthorizerFunc(func(ctx context.Context, request pluginworkloadidentity.Request) (pluginworkloadidentity.Authorization, error) {
				calls++
				if test.authorize != nil {
					return pluginworkloadidentity.Authorization{}, test.authorize
				}
				if test.mismatchSealed {
					request.InvocationID = uuid.MustParse("018f47de-0f4c-7c4b-8f3b-f8d51df94b79")
				}
				return sealWorkloadAuthorization(t, ctx, request), nil
			})
			deliverer, err := NewWebhookDeliverer(WebhookDelivererConfig{InstallationID: installationID,
				Projection: resolver, Authorizer: authorizer, Delegate: delegate, Now: func() time.Time { return compositionTestNow }})
			if err != nil {
				t.Fatal(err)
			}
			result := deliverer.DeliverV2(t.Context(), validV2Item(), 1, []byte("01234567890123456789012345678901"))
			if result.Code != test.wantCode || result.Retryable != test.retryable || result.Success ||
				(test.rateLimited && (result.RetryAfter <= 0 || result.RetryAfter > time.Minute)) ||
				(!test.rateLimited && result.RetryAfter != 0) ||
				len(delegate.items) != 0 || calls != test.wantCalls {
				t.Fatalf("result=%+v delegate=%d authorizer_calls=%d", result, len(delegate.items), calls)
			}
		})
	}
}

func TestWebhookDelivererRequiresUUIDv7EventInvocation(t *testing.T) {
	installationID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	resolverCalls, authorizerCalls := 0, 0
	resolver := projectionResolverFunc(func(_ context.Context, request ProjectionRequest) (Projection, error) {
		resolverCalls++
		return validProjection(request.RequestID, installationID), nil
	})
	authorizer := workloadAuthorizerFunc(func(context.Context, pluginworkloadidentity.Request) (pluginworkloadidentity.Authorization, error) {
		authorizerCalls++
		return pluginworkloadidentity.Authorization{}, nil
	})
	deliverer, err := NewWebhookDeliverer(WebhookDelivererConfig{InstallationID: installationID,
		Projection: resolver, Authorizer: authorizer, Delegate: &recordingDelegate{}, Now: func() time.Time { return compositionTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	item := validV2Item()
	item.EventID = uuid.MustParse("99999999-9999-4999-8999-999999999999")
	item.Event.ID = item.EventID.String()
	result := deliverer.DeliverV2(t.Context(), item, 1, []byte("01234567890123456789012345678901"))
	if result.Code != "runtime_authorization_denied" || result.Retryable || resolverCalls != 0 || authorizerCalls != 0 {
		t.Fatalf("result=%+v resolver_calls=%d authorizer_calls=%d", result, resolverCalls, authorizerCalls)
	}
}

func TestWebhookDelivererRejectsUnknownEventBeforeProjection(t *testing.T) {
	installationID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	projectionCalls, authorizerCalls := 0, 0
	resolver := projectionResolverFunc(func(context.Context, ProjectionRequest) (Projection, error) {
		projectionCalls++
		return validProjection("unknown-event", installationID), nil
	})
	authorizer := workloadAuthorizerFunc(func(context.Context, pluginworkloadidentity.Request) (pluginworkloadidentity.Authorization, error) {
		authorizerCalls++
		return pluginworkloadidentity.Authorization{}, nil
	})
	delegate := &recordingDelegate{result: pluginwebhook.SendResult{Success: true}}
	deliverer, err := NewWebhookDeliverer(WebhookDelivererConfig{InstallationID: installationID,
		Projection: resolver, Authorizer: authorizer, Delegate: delegate, Now: func() time.Time { return compositionTestNow }})
	if err != nil {
		t.Fatal(err)
	}
	item := validV2Item()
	item.Event.Type = "io.cdnca.unknown.v1.event"
	result := deliverer.DeliverV2(t.Context(), item, 1, []byte("01234567890123456789012345678901"))
	if result.Success || result.Code != "runtime_authorization_denied" || result.Retryable ||
		projectionCalls != 0 || authorizerCalls != 0 || len(delegate.items) != 0 {
		t.Fatalf("unknown event crossed authorization fence: result=%+v projection=%d authorizer=%d delegate=%d",
			result, projectionCalls, authorizerCalls, len(delegate.items))
	}
}

type projectionResponseMode uint8

const (
	projectionValid projectionResponseMode = iota
	projectionMissingLF
	projectionUnknownField
	projectionDuplicateField
	projectionContentEncoding
	projectionBadSignature
	projectionWrongKey
	projectionEchoMismatch
	projectionIssuedBeforeRequest
	projectionExpired
	projectionBodyOverflow
	projectionRedirect
	projectionRevoked
	projectionConflict
	projectionRateLimited
	projectionUnavailable
)

type projectionFixture struct {
	t                    *testing.T
	mu                   sync.Mutex
	mode                 projectionResponseMode
	requests             int
	sawClientCertificate bool
	sawCanonicalProof    bool
	installationID       uuid.UUID
	certificateID        uuid.UUID
	clientPrivate        ed25519.PrivateKey
	signingKeyID         string
	signingPrivate       ed25519.PrivateKey
	identityJSON         []byte
	trust                *entitlementguard.TrustStore
	server               *httptest.Server
	clientTLS            *tls.Config
}

func newProjectionFixture(t *testing.T) *projectionFixture {
	t.Helper()
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &projectionFixture{t: t,
		installationID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		certificateID:  uuid.MustParse("018f47de-0f4a-7c4b-8f3b-f8d51df94b79"),
		signingKeyID:   "projection-signing-key-1", signingPrivate: signingPrivate,
		identityJSON: []byte(`{"schema":"test-service-identity"}`),
	}
	fixture.trust, err = entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{KeyID: fixture.signingKeyID, PublicKey: signingPublic}})
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, clientCertificate, clientPrivate, roots := projectionTestPKI(t, fixture.installationID, fixture.certificateID)
	fixture.clientPrivate = clientPrivate
	fixture.clientTLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{clientCertificate}}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	fixture.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	fixture.server.StartTLS()
	return fixture
}

func (fixture *projectionFixture) close() { fixture.server.Close() }

func (fixture *projectionFixture) config() ProjectionClientConfig {
	return ProjectionClientConfig{BaseURL: fixture.server.URL, TLSConfig: fixture.clientTLS.Clone(),
		InstallationID: fixture.installationID, Trust: fixture.trust, Now: func() time.Time { return compositionTestNow },
		Timeout: 2 * time.Second, MaxBodyBytes: maximumBodyBytes}
}

func (fixture *projectionFixture) client(t *testing.T) *ProjectionClient {
	t.Helper()
	client, err := NewProjectionClient(fixture.config())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (fixture *projectionFixture) request(requestID string) ProjectionRequest {
	return ProjectionRequest{RequestID: requestID, InstallationID: fixture.installationID,
		ConsumerKind: "webhook", ConsumerID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		TargetScopeID:  uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		CapabilityKind: "webhook", CapabilityCode: "io.cdnca.webhook.v1.test", RequestedAt: compositionTestNow.Add(-time.Second)}
}

func (fixture *projectionFixture) serveHTTP(response http.ResponseWriter, request *http.Request) {
	fixture.mu.Lock()
	fixture.requests++
	fixture.sawClientCertificate = request.TLS != nil && len(request.TLS.PeerCertificates) > 0
	mode := fixture.mode
	fixture.mu.Unlock()
	if mode == projectionRedirect {
		http.Redirect(response, request, "/redirected", http.StatusTemporaryRedirect)
		return
	}
	status := map[projectionResponseMode]int{projectionRevoked: http.StatusForbidden, projectionConflict: http.StatusConflict,
		projectionRateLimited: http.StatusTooManyRequests, projectionUnavailable: http.StatusServiceUnavailable}[mode]
	if status != 0 {
		response.WriteHeader(status)
		return
	}
	encoded, err := io.ReadAll(io.LimitReader(request.Body, maximumBodyBytes+1))
	if err != nil || request.Method != http.MethodPost || request.URL.Path != projectionPath {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	var body projectionRequestBody
	if json.Unmarshal(encoded, &body) != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	payload, _ := json.Marshal(projectionRequestPayload{Schema: body.Schema, RequestID: body.RequestID,
		InstallationID: body.InstallationID, CertificateID: body.CertificateID, ConsumerKind: body.ConsumerKind,
		ConsumerID: body.ConsumerID, TargetScopeID: body.TargetScopeID, CapabilityKind: body.CapabilityKind,
		CapabilityCode: body.CapabilityCode, RequestedAt: body.RequestedAt})
	proof, _ := base64.RawURLEncoding.DecodeString(body.Proof)
	canonicalBody, _ := json.Marshal(body)
	canonical := bytes.Equal(canonicalBody, encoded) && ed25519.Verify(fixture.clientPrivate.Public().(ed25519.PublicKey),
		lengthPrefixed(projectionRequestDomain, payload), proof)
	fixture.mu.Lock()
	fixture.sawCanonicalProof = canonical
	fixture.mu.Unlock()
	if !canonical {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	result := testProjectionWire{Schema: projectionSchema, RequestID: body.RequestID,
		InstallationID: fixture.installationID, CertificateID: fixture.certificateID, Generation: 2,
		BindingID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), BindingRevision: 3,
		AuthorizationID: uuid.MustParse("55555555-5555-4555-8555-555555555555"), ServiceIdentity: fixture.identityJSON,
		ManifestSHA256: strings.Repeat("a", 64), VerificationID: uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		AttestationID: uuid.MustParse("77777777-7777-4777-8777-777777777777"), AttestationRevision: 4, ApprovalRevision: 5,
		CapabilityKind: body.CapabilityKind, CapabilityCode: body.CapabilityCode,
		IssuedAt: compositionTestNow, ExpiresAt: compositionTestNow.Add(time.Minute), Algorithm: "Ed25519", KeyID: fixture.signingKeyID}
	if mode == projectionEchoMismatch {
		result.RequestID = "other-request"
	}
	if mode == projectionIssuedBeforeRequest {
		result.IssuedAt = body.RequestedAt.Add(-time.Second)
	}
	if mode == projectionExpired {
		result.IssuedAt, result.ExpiresAt = compositionTestNow.Add(-2*time.Minute), compositionTestNow.Add(-time.Minute)
	}
	payloadBytes, _ := json.Marshal(result)
	result.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.signingPrivate,
		lengthPrefixed(projectionSigningDomain, payloadBytes)))
	if mode == projectionBadSignature {
		result.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	}
	if mode == projectionWrongKey {
		result.KeyID = "unknown-projection-key"
	}
	wire, _ := json.Marshal(result)
	switch mode {
	case projectionUnknownField:
		wire = append(wire[:len(wire)-1], []byte(`,"unexpected":true}`)...)
	case projectionDuplicateField:
		wire = append(wire[:len(wire)-1], []byte(`,"request_id":"duplicate"}`)...)
	case projectionBodyOverflow:
		wire = bytes.Repeat([]byte("x"), int(maximumBodyBytes+2))
	case projectionContentEncoding:
		response.Header().Set("Content-Encoding", "gzip")
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	if mode == projectionMissingLF {
		_, _ = response.Write(wire)
	} else {
		_, _ = response.Write(append(wire, '\n'))
	}
}

type testProjectionWire struct {
	Schema              string          `json:"schema"`
	RequestID           string          `json:"request_id"`
	InstallationID      uuid.UUID       `json:"installation_id"`
	CertificateID       uuid.UUID       `json:"certificate_id"`
	Generation          uint64          `json:"generation"`
	BindingID           uuid.UUID       `json:"binding_id"`
	BindingRevision     uint64          `json:"binding_revision"`
	AuthorizationID     uuid.UUID       `json:"authorization_id"`
	ServiceIdentity     json.RawMessage `json:"service_identity"`
	ManifestSHA256      string          `json:"manifest_sha256"`
	VerificationID      uuid.UUID       `json:"verification_id"`
	AttestationID       uuid.UUID       `json:"attestation_id"`
	AttestationRevision uint64          `json:"attestation_revision"`
	ApprovalRevision    uint64          `json:"approval_revision"`
	CapabilityKind      string          `json:"capability_kind"`
	CapabilityCode      string          `json:"capability_code"`
	IssuedAt            time.Time       `json:"issued_at"`
	ExpiresAt           time.Time       `json:"expires_at"`
	Algorithm           string          `json:"algorithm"`
	KeyID               string          `json:"key_id"`
	Signature           string          `json:"signature,omitempty"`
}

func projectionTestPKI(t *testing.T, installationID, certificateID uuid.UUID) (tls.Certificate, tls.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	t.Helper()
	now := compositionTestNow.Add(-24 * time.Hour)
	notAfter := now.Add(365 * 24 * time.Hour)
	caPublic, caPrivate, _ := ed25519.GenerateKey(rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "projection-ca"},
		NotBefore: now, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	issue := func(template *x509.Certificate) (tls.Certificate, ed25519.PrivateKey) {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		der, createErr := x509.CreateCertificate(rand.Reader, template, ca, public, caPrivate)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private}, private
	}
	server, _ := issue(&x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})
	identityURI, _ := url.Parse("spiffe://cdn-platform/installation/" + installationID.String())
	client, clientPrivate := issue(&x509.Certificate{SerialNumber: new(big.Int).SetBytes(certificateID[:]), NotBefore: now, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identityURI}})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return server, client, clientPrivate, roots
}

type projectionResolverFunc func(context.Context, ProjectionRequest) (Projection, error)

func (function projectionResolverFunc) Resolve(ctx context.Context, request ProjectionRequest) (Projection, error) {
	return function(ctx, request)
}

type runtimeProviderFunc func(context.Context, pluginruntimeprovider.Request) (pluginruntimeprovider.Facts, error)

func (function runtimeProviderFunc) Resolve(ctx context.Context, request pluginruntimeprovider.Request) (pluginruntimeprovider.Facts, error) {
	return function(ctx, request)
}

type runtimeVerifierFunc func([]byte, []byte, pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error)

func (function runtimeVerifierFunc) Authorize(identity, decision []byte, expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
	return function(identity, decision, expected)
}

type workloadAuthorizerFunc func(context.Context, pluginworkloadidentity.Request) (pluginworkloadidentity.Authorization, error)

func (function workloadAuthorizerFunc) Authorize(ctx context.Context, request pluginworkloadidentity.Request) (pluginworkloadidentity.Authorization, error) {
	return function(ctx, request)
}

type recordingDelegate struct {
	items    []pluginwebhook.QueueItem
	attempts []uint64
	secrets  [][]byte
	result   pluginwebhook.SendResult
}

func (delegate *recordingDelegate) Deliver(context.Context, pluginwebhook.QueueItem, uint64) pluginwebhook.SendResult {
	return pluginwebhook.SendResult{Code: "invalid_delivery"}
}

func (delegate *recordingDelegate) DeliverV2(_ context.Context, item pluginwebhook.QueueItem, attempt uint64, secret []byte) pluginwebhook.SendResult {
	delegate.items = append(delegate.items, item)
	delegate.attempts = append(delegate.attempts, attempt)
	delegate.secrets = append(delegate.secrets, append([]byte(nil), secret...))
	return delegate.result
}

func validProjection(requestID string, installationID uuid.UUID) Projection {
	return Projection{RequestID: requestID, InstallationID: installationID,
		CertificateID: uuid.MustParse("018f47de-0f4a-7c4b-8f3b-f8d51df94b79"), Generation: 2,
		BindingID: uuid.MustParse("44444444-4444-4444-8444-444444444444"), BindingRevision: 3,
		AuthorizationID:     uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		ServiceIdentityJSON: []byte(`{"authorization_id":"55555555-5555-4555-8555-555555555555","plugin_id":"acme.runtime"}`), ManifestSHA256: strings.Repeat("a", 64),
		VerificationID: uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		AttestationID:  uuid.MustParse("77777777-7777-4777-8777-777777777777"), AttestationRevision: 4,
		ApprovalRevision: 5, CapabilityKind: "webhook", CapabilityCode: "webhook.deliver",
		IssuedAt: compositionTestNow, ExpiresAt: compositionTestNow.Add(time.Minute)}
}

func matchingAuthorization(expected pluginruntimeauth.ExpectedAction, request pluginworkloadidentity.Request) pluginruntimeauth.Authorization {
	return pluginruntimeauth.Authorization{RequestID: expected.RequestID,
		CustomerID: uuid.MustParse("abababab-abab-4bab-8bab-abababababab"),
		Action:     expected.Action, InstallationID: expected.InstallationID,
		AuthorizationID: uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		TokenID:         uuid.MustParse("22222222-2222-4222-8222-222222222222"), IdentityGeneration: 2,
		PluginID: request.PluginID, PluginVersion: "1.2.3", ManifestSHA256: request.ManifestSHA256,
		VerificationID: request.VerificationID, AttestationID: request.AttestationID,
		AttestationRevision: request.AttestationRevision,
		ApprovalReceiptID:   uuid.MustParse("33333333-3333-4333-8333-333333333333"), ApprovalRevision: request.ApprovalRevision,
		CapabilityKind: expected.CapabilityKind, CapabilityCode: expected.CapabilityCode,
		EvaluatedAt: compositionTestNow, ExpiresAt: compositionTestNow.Add(time.Minute)}
}

func sealWorkloadAuthorization(t *testing.T, ctx context.Context, request pluginworkloadidentity.Request) pluginworkloadidentity.Authorization {
	t.Helper()
	provider := runtimeProviderFunc(func(_ context.Context, providerRequest pluginruntimeprovider.Request) (pluginruntimeprovider.Facts, error) {
		return pluginruntimeprovider.Facts{IdentityJSON: append([]byte(nil), providerRequest.ServiceIdentityJSON...), DecisionJSON: []byte("decision")}, nil
	})
	verifier := runtimeVerifierFunc(func(_ []byte, _ []byte, expected pluginruntimeauth.ExpectedAction) (pluginruntimeauth.Authorization, error) {
		return matchingAuthorization(expected, request), nil
	})
	authorizer, err := pluginworkloadidentity.NewAuthorizer(pluginworkloadidentity.Config{
		Provider: provider, Verifier: verifier, Now: func() time.Time { return compositionTestNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := authorizer.Authorize(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func copyWorkloadRequest(request pluginworkloadidentity.Request) pluginworkloadidentity.Request {
	request.ServiceIdentityJSON = append([]byte(nil), request.ServiceIdentityJSON...)
	return request
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

type recordingRuntimeCredentialSource struct {
	mu         sync.Mutex
	credential RuntimeCredential
	returned   []RuntimeCredential
	calls      int
}

func (source *recordingRuntimeCredentialSource) Ensure(context.Context) (RuntimeCredential, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	result := cloneTestRuntimeCredential(source.credential)
	source.returned = append(source.returned, result)
	return result, nil
}

func (source *recordingRuntimeCredentialSource) snapshot() (int, []RuntimeCredential, RuntimeCredential) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls, append([]RuntimeCredential(nil), source.returned...), cloneTestRuntimeCredential(source.credential)
}

func cloneTestRuntimeCredential(value RuntimeCredential) RuntimeCredential {
	result := value
	result.PrivateKey = append(ed25519.PrivateKey(nil), value.PrivateKey...)
	result.TLSCertificate = cloneTestTLSCertificate(value.TLSCertificate)
	if value.RootCAs != nil {
		result.RootCAs = value.RootCAs.Clone()
	}
	return result
}

func cloneTestTLSCertificate(value tls.Certificate) tls.Certificate {
	result := value
	result.Certificate = make([][]byte, len(value.Certificate))
	for index := range value.Certificate {
		result.Certificate[index] = append([]byte(nil), value.Certificate[index]...)
	}
	if private, ok := value.PrivateKey.(ed25519.PrivateKey); ok {
		result.PrivateKey = append(ed25519.PrivateKey(nil), private...)
	}
	if value.Leaf != nil {
		result.Leaf = value.Leaf
	}
	return result
}

func validV2Item() pluginwebhook.QueueItem {
	return pluginwebhook.QueueItem{Schema: pluginwebhook.QueueSchemaV2,
		DeliveryID:     uuid.MustParse("88888888-8888-4888-8888-888888888888"),
		IdempotencyKey: "plugin-webhook-v2-" + strings.Repeat("a", 64), TargetURL: "https://hooks.example.test/runtime",
		Event:           pluginwebhook.CloudEvent{ID: "018f47de-0f4b-7c4b-8f3b-f8d51df94b79", Type: "io.cdnca.dns.v1.changed"},
		TargetScopeID:   uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		TenantID:        uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		SubscriptionID:  uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc"),
		SecretVersionID: uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"),
		EventID:         uuid.MustParse("018f47de-0f4b-7c4b-8f3b-f8d51df94b79")}
}
