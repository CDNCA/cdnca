package plugininstallation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestActivationClientCanonicalProofSignedResponseAndBinding(t *testing.T) {
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	installationPublic, installationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	licensePublic, licensePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	installationID, verificationID := uuid.New(), uuid.New()
	doer := activationDoerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() !=
			"https://license.example/installation/v1/plugin-installation-activation-facts:resolve" ||
			request.Header.Get("Authorization") != "" || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request method=%s url=%s headers=%v", request.Method, request.URL, request.Header)
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		var wire activationRequestWireForTest
		if json.Unmarshal(body, &wire) != nil {
			t.Fatalf("request body=%s", body)
		}
		canonical, _ := json.Marshal(wire)
		if !bytes.Equal(canonical, body) || wire.Schema != activationRequestSchema || wire.InstallationID != installationID ||
			wire.VerificationID != verificationID || wire.Action != ActivationInstall || wire.KnownLifecycleRevision != 0 ||
			len(wire.RequestedScopes) != 1 || wire.RequestedScopes[0] != "plugin.read" || wire.RequestedAt != now {
			t.Fatalf("noncanonical request=%s", body)
		}
		proof, proofErr := base64.RawURLEncoding.DecodeString(wire.Proof)
		payload, _ := json.Marshal(activationRequestPayloadForTest{Schema: wire.Schema, RequestID: wire.RequestID,
			IdempotencyKey: wire.IdempotencyKey, InstallationID: wire.InstallationID,
			VerificationID: wire.VerificationID, Action: wire.Action,
			KnownLifecycleRevision: wire.KnownLifecycleRevision, RequestedScopes: wire.RequestedScopes,
			RequestedAt: wire.RequestedAt})
		if proofErr != nil || !ed25519.Verify(installationPublic, framedForTest(activationRequestDomain, payload), proof) {
			t.Fatal("installation request proof invalid")
		}
		responseBody := signedActivationResponseForTest(t, body, licensePrivate, wire)
		if !bytes.HasSuffix(responseBody, []byte("\n")) || bytes.HasSuffix(responseBody, []byte("\n\n")) {
			t.Fatalf("activation response does not have exactly one newline: %q", responseBody)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(bytes.NewReader(responseBody))}, nil
	})
	client, err := NewActivationClient(ActivationClientConfig{BaseURL: "https://license.example", HTTP: doer,
		InstallationID: installationID, PrivateKey: installationPrivate,
		Trust: activationTrustForTest{keyID: "license-plugin-key-1", public: licensePublic}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	result, err := client.Resolve(context.Background(), ActivationResolveRequest{RequestID: "activation-request-1",
		IdempotencyKey: "activation-idempotency-1", VerificationID: verificationID, Action: ActivationInstall,
		RequestedScopes: []string{"plugin.read"}})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.Candidate.InstallationID != installationID || result.Candidate.VerificationID != verificationID ||
		result.Candidate.PluginID != "acme.example" || result.Candidate.Version != "1.2.0" ||
		len(result.Candidate.ManifestScopes) != 3 || result.Candidate.ManifestScopes[2] != "plugin.zebra" ||
		result.LifecycleStatus != "authorized" || result.LifecycleRevision != 7 ||
		len(result.NewScopes) != 1 || result.NewScopes[0] != "plugin.write" || !result.verified {
		t.Fatalf("result=%+v", result)
	}
	if err := result.Verifier().VerifyCandidate(context.Background(), result.Candidate, nil); err != nil {
		t.Fatalf("verified result rejected: %v", err)
	}
	tampered := result.Candidate
	tampered.ManifestSHA256 = digest("f")
	if err := result.Verifier().VerifyCandidate(context.Background(), tampered, nil); err != ErrFactDenied {
		t.Fatalf("tampered candidate error=%v", err)
	}
}

func TestActivationClientRejectsTamperAndMapsStableFailures(t *testing.T) {
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	_, installationPrivate, _ := ed25519.GenerateKey(rand.Reader)
	licensePublic, licensePrivate, _ := ed25519.GenerateKey(rand.Reader)
	installationID, verificationID := uuid.New(), uuid.New()
	status := http.StatusOK
	code := ""
	tamper := false
	responseFraming := "canonical"
	doer := activationDoerFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		if status != http.StatusOK {
			errorBody, _ := json.Marshal(struct {
				Code      string `json:"code"`
				RequestID string `json:"request_id"`
			}{Code: code, RequestID: "activation-request-2"})
			errorBody = append(errorBody, '\n')
			return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(bytes.NewReader(errorBody))}, nil
		}
		var wire activationRequestWireForTest
		_ = json.Unmarshal(body, &wire)
		responseBody := signedActivationResponseForTest(t, body, licensePrivate, wire)
		if tamper {
			responseBody = bytes.Replace(responseBody, []byte(`"plugin_version":"1.2.0"`), []byte(`"plugin_version":"1.2.1"`), 1)
		}
		switch responseFraming {
		case "missing-newline":
			responseBody = bytes.TrimSuffix(responseBody, []byte("\n"))
		case "multiple-newlines":
			responseBody = append(responseBody, '\n')
		case "trailing-bytes":
			responseBody = append(responseBody, 'x')
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(bytes.NewReader(responseBody))}, nil
	})
	client, err := NewActivationClient(ActivationClientConfig{BaseURL: "https://license.example", HTTP: doer,
		InstallationID: installationID, PrivateKey: installationPrivate,
		Trust: activationTrustForTest{keyID: "license-plugin-key-1", public: licensePublic}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	input := ActivationResolveRequest{RequestID: "activation-request-2", IdempotencyKey: "activation-idempotency-2",
		VerificationID: verificationID, Action: ActivationUpgrade, KnownLifecycleRevision: 7,
		RequestedScopes: []string{"plugin.read"}}
	for _, invalidFraming := range []string{"missing-newline", "multiple-newlines", "trailing-bytes"} {
		responseFraming = invalidFraming
		if _, err := client.Resolve(context.Background(), input); err != ErrActivationInvalid {
			t.Fatalf("%s response error=%v", invalidFraming, err)
		}
	}
	responseFraming = "canonical"
	tamper = true
	if _, err := client.Resolve(context.Background(), input); err != ErrActivationInvalid {
		t.Fatalf("tampered response error=%v", err)
	}
	tamper = false
	status, code = http.StatusConflict, "lifecycle_stale"
	if _, err := client.Resolve(context.Background(), input); err != ErrRevisionConflict {
		t.Fatalf("stale error=%v", err)
	}
	status, code = http.StatusConflict, "idempotency_conflict"
	if _, err := client.Resolve(context.Background(), input); err != ErrIdempotencyConflict {
		t.Fatalf("idempotency error=%v", err)
	}
	status, code = http.StatusUnprocessableEntity, "activation_denied"
	if _, err := client.Resolve(context.Background(), input); err != ErrFactDenied {
		t.Fatalf("denied error=%v", err)
	}
}

func TestActivationClientDiscoversLocalTenantCandidateAndReportsVersionedLifecycle(t *testing.T) {
	now := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	installationPublic, installationPrivate, _ := ed25519.GenerateKey(rand.Reader)
	licensePublic, licensePrivate, _ := ed25519.GenerateKey(rand.Reader)
	tenantID, installationID, authorizationID, verificationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	requests := 0
	doer := activationDoerFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		body, _ := io.ReadAll(request.Body)
		var envelope struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			t.Fatalf("invalid request body: %s", body)
		}
		var responseBody []byte
		switch envelope.Schema {
		case candidateSyncRequestSchema:
			var wire candidateSyncRequestWire
			if json.Unmarshal(body, &wire) != nil || wire.InstallationID != installationID || wire.Cursor != nil {
				t.Fatalf("candidate request=%s", body)
			}
			canonical, _ := json.Marshal(wire.candidateSyncRequestPayload)
			proof, _ := base64.RawURLEncoding.DecodeString(wire.Proof)
			if !ed25519.Verify(installationPublic, framed(candidateSyncRequestDomain, canonical), proof) {
				t.Fatal("candidate request proof invalid")
			}
			requestDigest := sha256.Sum256(framed("cdnca-plugin-installation-candidate-sync-idempotency/v1",
				append(canonical, proof...)))
			batch := candidateSyncBatchWire{Schema: candidateSyncBatchSchema, RequestID: wire.RequestID,
				RequestDigest: hex.EncodeToString(requestDigest[:]), CustomerID: uuid.New(), InstallationID: installationID,
				Candidates: []candidateSyncCandidateWire{{AuthorizationID: authorizationID,
					VerificationID: verificationID, PluginID: "acme.example", PluginVersion: "1.2.0", ResourceScope: "tenant", EntrypointType: "external_https",
					ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("b"),
					ManifestScopes: []string{"plugin.read"}, ApprovedScopes: []string{"plugin.read"},
					SensitiveScopes: []string{}, NewScopes: []string{}, Status: "authorized", Revision: 2,
					UpdatedAt: now}}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Algorithm: "Ed25519",
				KeyID: "license-plugin-key-1"}
			unsigned, _ := json.Marshal(batch)
			batch.Signature = base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(licensePrivate, framed(candidateSyncBatchDomain, unsigned)))
			responseBody, _ = json.Marshal(batch)
		case lifecycleReceiptRequestSchema:
			var wire lifecycleReportRequestWire
			if json.Unmarshal(body, &wire) != nil || wire.Action != "installed" ||
				wire.ControlFromRevision != 0 || wire.ControlToRevision != 1 {
				t.Fatalf("lifecycle request=%s", body)
			}
			canonical, _ := json.Marshal(wire.lifecycleReportRequestPayload)
			proof, _ := base64.RawURLEncoding.DecodeString(wire.Proof)
			if !ed25519.Verify(installationPublic, framed(lifecycleReceiptRequestDomain, canonical), proof) {
				t.Fatal("lifecycle request proof invalid")
			}
			digest := sha256.Sum256(framed("cdnca-plugin-installation-lifecycle-idempotency/v1",
				append(canonical, proof...)))
			result := lifecycleReportResponseWire{Schema: lifecycleReceiptSchema, RequestID: wire.RequestID,
				RequestDigest: hex.EncodeToString(digest[:]), InstallationID: installationID,
				AuthorizationID: authorizationID, VerificationID: verificationID, Action: wire.Action,
				Status: StatusEnabled, LifecycleRevision: 4, IdentityGeneration: 2, IssuedAt: now,
				Algorithm: "Ed25519", KeyID: "license-plugin-key-1"}
			unsigned, _ := json.Marshal(result)
			result.Signature = base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(licensePrivate, framed(lifecycleReceiptDomain, unsigned)))
			responseBody, _ = json.Marshal(result)
		default:
			t.Fatalf("unexpected schema %q", envelope.Schema)
		}
		responseBody = append(responseBody, '\n')
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(responseBody))}, nil
	})
	client, err := NewActivationClient(ActivationClientConfig{BaseURL: "https://license.example", HTTP: doer,
		InstallationID: installationID, PrivateKey: installationPrivate,
		Trust: activationTrustForTest{keyID: "license-plugin-key-1", public: licensePublic},
		Now:   func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Discover(context.Background(), CandidateDiscoveryRequest{
		RequestID: "candidate-sync-1", TenantID: tenantID, Limit: 50, PluginID: "acme.example"})
	if err != nil || len(page.Items) != 1 || page.Items[0].Installation.TenantID != tenantID ||
		page.Items[0].Installation.AuthorizationID != authorizationID {
		t.Fatalf("candidate page=%+v err=%v", page, err)
	}
	result, err := client.ReportLifecycle(context.Background(), LifecycleReportRequest{Receipt: Receipt{
		ID: uuid.New(), AuthorizationID: authorizationID, RequestID: "lifecycle-1", IdempotencyKey: "lifecycle-1",
		FromRevision: 0, ToRevision: 1, Result: ReceiptInstalled, OccurredAt: now,
		Snapshot: Installation{InstallationID: installationID, VerificationID: verificationID, Status: StatusEnabled}}})
	if err != nil || result.AuthorizationID != authorizationID || result.LifecycleRevision != 4 || requests != 2 {
		t.Fatalf("lifecycle result=%+v requests=%d err=%v", result, requests, err)
	}
}

type activationDoerFunc func(*http.Request) (*http.Response, error)

func (function activationDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

type activationTrustForTest struct {
	keyID  string
	public ed25519.PublicKey
}

func (trust activationTrustForTest) VerifyDetached(keyID string, payload, signature []byte,
	_, _ time.Time) error {
	if keyID != trust.keyID || !ed25519.Verify(trust.public, payload, signature) {
		return ErrActivationInvalid
	}
	return nil
}

type activationRequestPayloadForTest struct {
	Schema                 string    `json:"schema"`
	RequestID              string    `json:"request_id"`
	IdempotencyKey         string    `json:"idempotency_key"`
	InstallationID         uuid.UUID `json:"installation_id"`
	VerificationID         uuid.UUID `json:"verification_id"`
	Action                 string    `json:"action"`
	KnownLifecycleRevision uint64    `json:"known_lifecycle_revision"`
	RequestedScopes        []string  `json:"requested_scopes"`
	RequestedAt            time.Time `json:"requested_at"`
}

type activationRequestWireForTest struct {
	Schema                 string    `json:"schema"`
	RequestID              string    `json:"request_id"`
	IdempotencyKey         string    `json:"idempotency_key"`
	InstallationID         uuid.UUID `json:"installation_id"`
	VerificationID         uuid.UUID `json:"verification_id"`
	Action                 string    `json:"action"`
	KnownLifecycleRevision uint64    `json:"known_lifecycle_revision"`
	RequestedScopes        []string  `json:"requested_scopes"`
	RequestedAt            time.Time `json:"requested_at"`
	Proof                  string    `json:"proof"`
}

type activationFactForTest struct {
	Schema           string `json:"schema"`
	Scope            string `json:"scope"`
	Decision         string `json:"decision"`
	StableReasonCode string `json:"stable_reason_code"`
	Signature        string `json:"signature"`
}

type activationFactUnsignedForTest struct {
	Schema           string `json:"schema"`
	Scope            string `json:"scope"`
	Decision         string `json:"decision"`
	StableReasonCode string `json:"stable_reason_code"`
}

type activationSharedForTest struct {
	Schema                    string    `json:"schema"`
	RequestID                 string    `json:"request_id"`
	RequestDigest             string    `json:"request_digest"`
	CustomerID                uuid.UUID `json:"customer_id"`
	InstallationID            uuid.UUID `json:"installation_id"`
	AuthorizationID           uuid.UUID `json:"authorization_id"`
	VerificationID            uuid.UUID `json:"verification_id"`
	PluginID                  string    `json:"plugin_id"`
	PluginVersion             string    `json:"plugin_version"`
	ResourceScope             string    `json:"resource_scope"`
	EntrypointType            string    `json:"entrypoint_type"`
	ManifestSHA256            string    `json:"manifest_sha256"`
	ConfigurationSchemaSHA256 string    `json:"configuration_schema_sha256"`
	ManifestScopes            []string  `json:"manifest_scopes"`
	Action                    string    `json:"action"`
	ApprovedScopes            []string  `json:"approved_scopes"`
	RequestedScopes           []string  `json:"requested_scopes"`
	SensitiveScopes           []string  `json:"sensitive_scopes"`
	NewScopes                 []string  `json:"new_scopes"`
	LifecycleStatus           string    `json:"lifecycle_status"`
	LifecycleRevision         uint64    `json:"lifecycle_revision"`
	IdentityGeneration        uint64    `json:"identity_generation"`
	SourceReceiptID           uuid.UUID `json:"source_receipt_id"`
	Decision                  string    `json:"decision"`
	StableReasonCode          string    `json:"stable_reason_code"`
	IssuedAt                  time.Time `json:"issued_at"`
	ExpiresAt                 time.Time `json:"expires_at"`
	Algorithm                 string    `json:"algorithm"`
	KeyID                     string    `json:"key_id"`
}

type activationBatchPayloadForTest struct {
	activationSharedForTest
	Facts []activationFactUnsignedForTest `json:"facts"`
}

type activationFactPayloadForTest struct {
	activationSharedForTest
	FactSchema           string `json:"fact_schema"`
	Scope                string `json:"scope"`
	FactDecision         string `json:"fact_decision"`
	FactStableReasonCode string `json:"fact_stable_reason_code"`
}

type activationBatchWireForTest struct {
	activationSharedForTest
	Signature string                  `json:"signature"`
	Facts     []activationFactForTest `json:"facts"`
}

func signedActivationResponseForTest(t *testing.T, requestBody []byte, private ed25519.PrivateKey,
	request activationRequestWireForTest) []byte {
	t.Helper()
	// Same digest as license-service PluginInstallationActivationRequestDigest: framed canonical payload + proof.
	unsigned := request
	unsigned.Proof = ""
	canonical, err := json.Marshal(struct {
		Schema                 string    `json:"schema"`
		RequestID              string    `json:"request_id"`
		IdempotencyKey         string    `json:"idempotency_key"`
		InstallationID         uuid.UUID `json:"installation_id"`
		VerificationID         uuid.UUID `json:"verification_id"`
		Action                 string    `json:"action"`
		KnownLifecycleRevision uint64    `json:"known_lifecycle_revision"`
		RequestedScopes        []string  `json:"requested_scopes"`
		RequestedAt            time.Time `json:"requested_at"`
	}{unsigned.Schema, unsigned.RequestID, unsigned.IdempotencyKey, unsigned.InstallationID, unsigned.VerificationID,
		unsigned.Action, unsigned.KnownLifecycleRevision, unsigned.RequestedScopes, unsigned.RequestedAt})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := base64.RawURLEncoding.DecodeString(request.Proof)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(framed("cdnca-plugin-installation-activation-idempotency/v1",
		append(canonical, proof...)))
	_ = requestBody
	shared := activationSharedForTest{Schema: activationBatchSchema, RequestID: request.RequestID,
		RequestDigest: hex.EncodeToString(requestDigest[:]), CustomerID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		InstallationID: request.InstallationID, AuthorizationID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		VerificationID: request.VerificationID, PluginID: "acme.example", PluginVersion: "1.2.0", ResourceScope: "tenant", EntrypointType: "external_https",
		ManifestSHA256: digest("a"), ConfigurationSchemaSHA256: digest("1"),
		ManifestScopes: []string{"plugin.read", "plugin.write", "plugin.zebra"}, Action: request.Action,
		ApprovedScopes: []string{"plugin.read", "plugin.write"}, RequestedScopes: request.RequestedScopes,
		SensitiveScopes: []string{"plugin.write"}, NewScopes: []string{"plugin.write"},
		LifecycleStatus:   map[bool]string{true: "authorized", false: "enabled"}[request.Action == ActivationInstall],
		LifecycleRevision: 7, IdentityGeneration: 3,
		SourceReceiptID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Decision: "allow",
		StableReasonCode: "authorized", IssuedAt: request.RequestedAt, ExpiresAt: request.RequestedAt.Add(time.Minute),
		Algorithm: "Ed25519", KeyID: "license-plugin-key-1"}
	unsignedFacts := make([]activationFactUnsignedForTest, len(request.RequestedScopes))
	facts := make([]activationFactForTest, len(request.RequestedScopes))
	for index, scope := range request.RequestedScopes {
		unsignedFacts[index] = activationFactUnsignedForTest{Schema: activationFactSchema, Scope: scope,
			Decision: "allow", StableReasonCode: "authorized"}
		factPayload, _ := json.Marshal(activationFactPayloadForTest{activationSharedForTest: shared,
			FactSchema: activationFactSchema, Scope: scope, FactDecision: "allow", FactStableReasonCode: "authorized"})
		facts[index] = activationFactForTest{Schema: activationFactSchema, Scope: scope, Decision: "allow",
			StableReasonCode: "authorized", Signature: base64.RawURLEncoding.EncodeToString(
				ed25519.Sign(private, framedForTest(activationFactDomain, factPayload)))}
	}
	batchPayload, _ := json.Marshal(activationBatchPayloadForTest{activationSharedForTest: shared, Facts: unsignedFacts})
	wire := activationBatchWireForTest{activationSharedForTest: shared,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, framedForTest(activationBatchDomain, batchPayload))),
		Facts:     facts}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func framedForTest(domain string, payload []byte) []byte {
	result := make([]byte, 0, 8+len(domain)+len(payload))
	for _, value := range [][]byte{[]byte(domain), payload} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		result = append(result, length[:]...)
		result = append(result, value...)
	}
	return result
}
