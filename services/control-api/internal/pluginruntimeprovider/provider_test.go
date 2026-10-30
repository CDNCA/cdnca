package pluginruntimeprovider

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/google/uuid"
)

var providerTestNow = time.Date(2026, 8, 7, 4, 0, 0, 0, time.UTC)

func TestProviderUsesMTLSCanonicalProofAndExactRetry(t *testing.T) {
	fixture := newProviderFixture(t)
	defer fixture.close()
	provider := fixture.provider(t, 4)
	transport, ok := provider.http.Transport.(*http.Transport)
	if !ok || !transport.DisableCompression || transport.MaxResponseHeaderBytes != maximumResponseHeaderBytes {
		t.Fatalf("transport = %#v, want disabled compression and bounded response headers", provider.http.Transport)
	}
	request := fixture.request("runtime-request-1")

	first, err := provider.Resolve(t.Context(), request)
	if err != nil {
		t.Fatalf("first Resolve() error = %v", err)
	}
	first.IdentityJSON[0] ^= 0xff
	first.DecisionJSON[0] ^= 0xff
	second, err := provider.Resolve(t.Context(), request)
	if err != nil {
		t.Fatalf("second Resolve() error = %v", err)
	}
	if !bytes.Equal(second.IdentityJSON, fixture.identityJSON) || len(second.DecisionJSON) == 0 {
		t.Fatal("Resolve() did not return cloned verified facts")
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if !fixture.sawClientCertificate || len(fixture.bodies) != 2 || !bytes.Equal(fixture.bodies[0], fixture.bodies[1]) {
		t.Fatalf("mTLS=%t bodies=%d equal=%t", fixture.sawClientCertificate, len(fixture.bodies),
			len(fixture.bodies) == 2 && bytes.Equal(fixture.bodies[0], fixture.bodies[1]))
	}
}

func TestProviderStrictResponseAndStableErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		mode responseMode
		want error
	}{
		{name: "missing LF", mode: responseMissingLF, want: ErrInvalid},
		{name: "CRLF", mode: responseCRLF, want: ErrInvalid},
		{name: "trailing space", mode: responseTrailingSpace, want: ErrInvalid},
		{name: "unknown field", mode: responseUnknownField, want: ErrInvalid},
		{name: "duplicate field", mode: responseDuplicateField, want: ErrInvalid},
		{name: "content encoding", mode: responseContentEncoding, want: ErrInvalid},
		{name: "bad signature", mode: responseBadSignature, want: ErrInvalid},
		{name: "signed deny", mode: responseDeny, want: ErrDenied},
		{name: "bad request", mode: responseBadRequest, want: ErrInvalid},
		{name: "forbidden", mode: responseForbidden, want: ErrDenied},
		{name: "not found", mode: responseNotFound, want: ErrDenied},
		{name: "stale", mode: responseConflict, want: ErrDenied},
		{name: "rate limited", mode: responseRateLimited, want: ErrRateLimited},
		{name: "server unavailable", mode: responseUnavailable, want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newProviderFixture(t)
			defer fixture.close()
			fixture.mode = test.mode
			provider := fixture.provider(t, 2)
			facts, err := provider.Resolve(t.Context(), fixture.request("strict-"+strings.ReplaceAll(test.name, " ", "-")))
			if !errors.Is(err, test.want) || len(facts.IdentityJSON) != 0 || len(facts.DecisionJSON) != 0 {
				t.Fatalf("Resolve() = (%+v, %v), want %v", facts, err, test.want)
			}
		})
	}
}

func TestProviderOfflineCacheIsExactBoundedAndReverified(t *testing.T) {
	fixture := newProviderFixture(t)
	defer fixture.close()
	provider := fixture.provider(t, 1)
	request := fixture.request("cache-request-1")
	if _, err := provider.Resolve(t.Context(), request); err != nil {
		t.Fatalf("prime Resolve() error = %v", err)
	}
	fixture.setMode(responseUnavailable)
	if _, err := provider.Resolve(t.Context(), request); err != nil {
		t.Fatalf("exact offline Resolve() error = %v", err)
	}
	changedID := request
	changedID.RequestID = "cache-request-2"
	if _, err := provider.Resolve(t.Context(), changedID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("new request Resolve() error = %v, want ErrUnavailable", err)
	}
	changedAction := request
	changedAction.CapabilityCode, changedAction.Action = "plugin.write", "plugin.write"
	if _, err := provider.Resolve(t.Context(), changedAction); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("changed action Resolve() error = %v, want ErrUnavailable", err)
	}
	fixture.advance(61 * time.Second)
	if _, err := provider.Resolve(t.Context(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired cache Resolve() error = %v, want ErrUnavailable", err)
	}
	fixture.mu.Lock()
	calls := len(fixture.bodies)
	fixture.mu.Unlock()
	if calls != 5 {
		t.Fatalf("online attempts = %d, want 5", calls)
	}
}

func TestNewProviderRejectsIncompleteProductionConfiguration(t *testing.T) {
	fixture := newProviderFixture(t)
	defer fixture.close()
	valid := fixture.config(2)
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{name: "HTTP", edit: func(value *Config) { value.BaseURL = "http://license.example.test" }},
		{name: "path", edit: func(value *Config) { value.BaseURL += "/api" }},
		{name: "TLS 1.2", edit: func(value *Config) { value.TLSConfig.MinVersion = tls.VersionTLS12 }},
		{name: "roots", edit: func(value *Config) { value.TLSConfig.RootCAs = nil }},
		{name: "client certificate", edit: func(value *Config) { value.TLSConfig.Certificates = nil }},
		{name: "installation", edit: func(value *Config) { value.InstallationID = uuid.Nil }},
		{name: "private key", edit: func(value *Config) { value.InstallationPrivateKey = nil }},
		{name: "trust", edit: func(value *Config) { value.Verifier.Trust = nil }},
		{name: "clock", edit: func(value *Config) { value.Now = nil }},
		{name: "timeout", edit: func(value *Config) { value.Timeout = 0 }},
		{name: "body limit", edit: func(value *Config) { value.MaxBodyBytes = 0 }},
		{name: "capacity", edit: func(value *Config) { value.CacheCapacity = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.TLSConfig = valid.TLSConfig.Clone()
			test.edit(&candidate)
			if _, err := New(candidate); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}
}

type responseMode uint8

const (
	responseValid responseMode = iota
	responseMissingLF
	responseCRLF
	responseTrailingSpace
	responseUnknownField
	responseDuplicateField
	responseContentEncoding
	responseBadSignature
	responseDeny
	responseBadRequest
	responseForbidden
	responseNotFound
	responseConflict
	responseRateLimited
	responseUnavailable
)

type providerFixture struct {
	t                    *testing.T
	mu                   sync.Mutex
	now                  time.Time
	mode                 responseMode
	bodies               [][]byte
	sawClientCertificate bool
	installationID       uuid.UUID
	installationPrivate  ed25519.PrivateKey
	signingKeyID         string
	signingPrivate       ed25519.PrivateKey
	identityJSON         []byte
	verificationID       uuid.UUID
	attestationID        uuid.UUID
	server               *httptest.Server
	clientTLS            *tls.Config
	trust                *entitlementguard.TrustStore
}

func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	_, installationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &providerFixture{
		t: t, now: providerTestNow,
		installationID:      uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		installationPrivate: installationPrivate,
		signingKeyID:        "runtime-signing-key-1",
		signingPrivate:      signingPrivate,
		verificationID:      uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		attestationID:       uuid.MustParse("55555555-5555-4555-8555-555555555555"),
	}
	fixture.identityJSON = fixture.signIdentity()
	fixture.trust, err = entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: fixture.signingKeyID, PublicKey: signingPublic,
	}})
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, clientCertificate, roots := providerTestPKI(t)
	fixture.clientTLS = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{clientCertificate}}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(fixture.serveHTTP))
	fixture.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	fixture.server.StartTLS()
	return fixture
}

func (fixture *providerFixture) close() { fixture.server.Close() }

func (fixture *providerFixture) advance(duration time.Duration) {
	fixture.mu.Lock()
	fixture.now = fixture.now.Add(duration)
	fixture.mu.Unlock()
}

func (fixture *providerFixture) setMode(mode responseMode) {
	fixture.mu.Lock()
	fixture.mode = mode
	fixture.mu.Unlock()
}

func (fixture *providerFixture) clock() time.Time {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.now
}

func (fixture *providerFixture) config(capacity int) Config {
	return Config{BaseURL: fixture.server.URL, TLSConfig: fixture.clientTLS.Clone(),
		InstallationID: fixture.installationID, InstallationPrivateKey: fixture.installationPrivate,
		Verifier: pluginruntimeauth.Verifier{Trust: fixture.trust}, Now: fixture.clock,
		Timeout: 2 * time.Second, MaxBodyBytes: 64 << 10, CacheCapacity: capacity}
}

func (fixture *providerFixture) provider(t *testing.T, capacity int) *Provider {
	t.Helper()
	provider, err := New(fixture.config(capacity))
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func (fixture *providerFixture) request(requestID string) Request {
	return Request{RequestID: requestID, CustomerID: uuid.MustParse("99999999-9999-4999-8999-999999999999"),
		InstallationID:      fixture.installationID,
		ServiceIdentityJSON: append([]byte(nil), fixture.identityJSON...), ManifestSHA256: strings.Repeat("a", 64),
		VerificationID: fixture.verificationID, AttestationID: fixture.attestationID,
		AttestationRevision: 9, KnownApprovalRevision: 4,
		CapabilityKind: "scope", CapabilityCode: "plugin.read", Action: "plugin.read", RequestedAt: providerTestNow}
}

func (fixture *providerFixture) serveHTTP(response http.ResponseWriter, request *http.Request) {
	body := make([]byte, request.ContentLength)
	if request.ContentLength <= 0 || request.ContentLength > 64<<10 {
		fixture.t.Errorf("request content length = %d", request.ContentLength)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	if _, err := io.ReadFull(request.Body, body); err != nil {
		fixture.t.Errorf("read request: %v", err)
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	fixture.mu.Lock()
	fixture.bodies = append(fixture.bodies, append([]byte(nil), body...))
	fixture.sawClientCertificate = request.TLS != nil && len(request.TLS.PeerCertificates) > 0
	mode, now := fixture.mode, fixture.now
	fixture.mu.Unlock()
	if request.Method != http.MethodPost || request.URL.Path != runtimeAuthorizationPath ||
		request.Header.Get("Content-Type") != "application/json" || !fixture.verifyRequestProof(body) {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	switch mode {
	case responseBadRequest:
		response.WriteHeader(http.StatusBadRequest)
		return
	case responseForbidden:
		response.WriteHeader(http.StatusForbidden)
		return
	case responseNotFound:
		response.WriteHeader(http.StatusNotFound)
		return
	case responseConflict:
		response.WriteHeader(http.StatusConflict)
		return
	case responseUnavailable:
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var received requestBody
	if json.Unmarshal(body, &received) != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	decision := fixture.signDecision(received, now, mode)
	if mode == responseBadSignature {
		decision.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	}
	encoded, err := json.Marshal(decision)
	if err != nil {
		fixture.t.Error(err)
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch mode {
	case responseUnknownField:
		encoded = append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...)
	case responseDuplicateField:
		encoded = append(encoded[:len(encoded)-1], []byte(`,"request_id":"duplicate"}`)...)
	}
	response.Header().Set("Content-Type", "application/json")
	if mode == responseContentEncoding {
		response.Header().Set("Content-Encoding", "gzip")
	}
	response.WriteHeader(http.StatusOK)
	switch mode {
	case responseMissingLF:
		_, _ = response.Write(encoded)
	case responseCRLF:
		_, _ = response.Write(append(encoded, '\r', '\n'))
	case responseTrailingSpace:
		_, _ = response.Write(append(encoded, '\n', ' '))
	default:
		_, _ = response.Write(append(encoded, '\n'))
	}
}

func (fixture *providerFixture) verifyRequestProof(encoded []byte) bool {
	var body requestBody
	if json.Unmarshal(encoded, &body) != nil || body.Schema != requestSchema || body.InstallationID != fixture.installationID {
		return false
	}
	proof, err := base64.RawURLEncoding.DecodeString(body.Proof)
	if err != nil || len(proof) != ed25519.SignatureSize {
		return false
	}
	payload, err := json.Marshal(requestPayload{Schema: body.Schema, RequestID: body.RequestID,
		InstallationID: body.InstallationID, ServiceIdentity: body.ServiceIdentity,
		ManifestSHA256: body.ManifestSHA256, VerificationID: body.VerificationID,
		AttestationID: body.AttestationID, AttestationRevision: body.AttestationRevision,
		KnownApprovalRevision: body.KnownApprovalRevision, CapabilityKind: body.CapabilityKind,
		CapabilityCode: body.CapabilityCode, Action: body.Action, RequestedAt: body.RequestedAt})
	return err == nil && ed25519.Verify(fixture.installationPrivate.Public().(ed25519.PublicKey),
		lengthPrefixed(requestProofDomain, payload), proof)
}

type testIdentity struct {
	Schema             string    `json:"schema"`
	Algorithm          string    `json:"algorithm"`
	KeyID              string    `json:"key_id"`
	TokenID            uuid.UUID `json:"token_id"`
	AuthorizationID    uuid.UUID `json:"authorization_id"`
	InstallationID     uuid.UUID `json:"installation_id"`
	PluginID           string    `json:"plugin_id"`
	PluginVersion      string    `json:"plugin_version"`
	IdentityGeneration uint64    `json:"identity_generation"`
	Scopes             []string  `json:"scopes"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Signature          string    `json:"signature,omitempty"`
}

func (fixture *providerFixture) signIdentity() []byte {
	identity := testIdentity{Schema: "cdnca.plugin-service-identity/v1", Algorithm: "Ed25519",
		KeyID: fixture.signingKeyID, TokenID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		AuthorizationID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		InstallationID:  fixture.installationID, PluginID: "acme.runtime", PluginVersion: "1.2.3",
		IdentityGeneration: 7, Scopes: []string{"plugin.read", "plugin.write"},
		IssuedAt: providerTestNow.Add(-time.Minute), ExpiresAt: providerTestNow.Add(10 * time.Minute)}
	payload, _ := json.Marshal(identity)
	identity.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.signingPrivate,
		lengthPrefixed("cdnca-plugin-service-identity/v1", payload)))
	encoded, _ := json.Marshal(identity)
	return encoded
}

type testDecision struct {
	Schema              string    `json:"schema"`
	RequestID           string    `json:"request_id"`
	CustomerID          uuid.UUID `json:"customer_id"`
	Action              string    `json:"action"`
	InstallationID      uuid.UUID `json:"installation_id"`
	AuthorizationID     uuid.UUID `json:"authorization_id"`
	TokenID             uuid.UUID `json:"token_id"`
	IdentityGeneration  uint64    `json:"identity_generation"`
	PluginID            string    `json:"plugin_id"`
	PluginVersion       string    `json:"plugin_version"`
	ManifestSHA256      string    `json:"manifest_sha256"`
	VerificationID      uuid.UUID `json:"verification_id"`
	AttestationID       uuid.UUID `json:"attestation_id"`
	AttestationRevision uint64    `json:"attestation_revision"`
	ApprovalReceiptID   uuid.UUID `json:"approval_receipt_id"`
	ApprovalRevision    uint64    `json:"approval_revision"`
	CapabilityKind      string    `json:"capability_kind"`
	CapabilityCode      string    `json:"capability_code"`
	Decision            string    `json:"decision"`
	StableReasonCode    string    `json:"stable_reason_code"`
	EvaluatedAt         time.Time `json:"evaluated_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Algorithm           string    `json:"algorithm"`
	KeyID               string    `json:"key_id"`
	Signature           string    `json:"signature,omitempty"`
}

func (fixture *providerFixture) signDecision(request requestBody, now time.Time, mode responseMode) testDecision {
	decision := testDecision{Schema: "cdnca.plugin-runtime-authorization/v2", RequestID: request.RequestID,
		CustomerID: uuid.MustParse("99999999-9999-4999-8999-999999999999"), Action: request.Action,
		InstallationID: fixture.installationID, AuthorizationID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		TokenID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), IdentityGeneration: 7,
		PluginID: "acme.runtime", PluginVersion: "1.2.3", ManifestSHA256: request.ManifestSHA256,
		VerificationID: request.VerificationID, AttestationID: request.AttestationID,
		AttestationRevision: request.AttestationRevision, ApprovalReceiptID: uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		ApprovalRevision: request.KnownApprovalRevision, CapabilityKind: request.CapabilityKind,
		CapabilityCode: request.CapabilityCode, Decision: "allow", StableReasonCode: "authorized",
		EvaluatedAt: now, ExpiresAt: now.Add(time.Minute), Algorithm: "Ed25519", KeyID: fixture.signingKeyID}
	if mode == responseDeny || mode == responseRateLimited {
		decision.Decision, decision.StableReasonCode = "deny", "identity_revoked"
		if mode == responseRateLimited {
			decision.StableReasonCode = "runtime_rate_limited"
		}
		decision.ApprovalReceiptID, decision.ApprovalRevision = uuid.Nil, 0
		decision.ExpiresAt = now.Add(15 * time.Second)
	}
	payload, _ := json.Marshal(decision)
	decision.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.signingPrivate,
		lengthPrefixed("cdnca-plugin-runtime-authorization/v2", payload)))
	return decision
}

func providerTestPKI(t *testing.T) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	wallNow := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "provider-test-ca"},
		NotBefore: wallNow.Add(-time.Hour), NotAfter: wallNow.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, commonName string, usages []x509.ExtKeyUsage, ip net.IP, uri *url.URL) tls.Certificate {
		public, private, generateErr := ed25519.GenerateKey(rand.Reader)
		if generateErr != nil {
			t.Fatal(generateErr)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
			NotBefore: wallNow.Add(-time.Hour), NotAfter: wallNow.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
		if ip != nil {
			leaf.IPAddresses = []net.IP{ip}
		}
		if uri != nil {
			leaf.URIs = []*url.URL{uri}
		}
		der, createErr := x509.CreateCertificate(rand.Reader, leaf, ca, public, caPrivate)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: private}
	}
	clientURI, _ := url.Parse("spiffe://cdnca.test/control-installation/11111111-1111-4111-8111-111111111111")
	server := issue(2, "provider-test-server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, net.ParseIP("127.0.0.1"), nil)
	client := issue(3, "provider-test-client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, clientURI)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return server, client, roots
}
