package pluginruntimeauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
)

type testIdentityWire struct {
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
	Signature          string    `json:"signature"`
}

type testIdentityPayload struct {
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
	IssuedAt           string    `json:"issued_at"`
	ExpiresAt          string    `json:"expires_at"`
}

type testDecisionWire struct {
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
	Signature           string    `json:"signature"`
}

type testDecisionPayload struct {
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
	EvaluatedAt         string    `json:"evaluated_at"`
	ExpiresAt           string    `json:"expires_at"`
	Algorithm           string    `json:"algorithm"`
	KeyID               string    `json:"key_id"`
}

type testFixture struct {
	now             time.Time
	identity        testIdentityWire
	decision        testDecisionWire
	identityPrivate ed25519.PrivateKey
	decisionPrivate ed25519.PrivateKey
}

type trustCall struct {
	keyID           string
	payload         []byte
	signature       []byte
	signedAt, nowAt time.Time
}

type testTrust struct {
	keys  map[string]ed25519.PublicKey
	err   error
	calls []trustCall
}

func (trust *testTrust) VerifyDetached(keyID string, payload, signature []byte,
	signedAt, now time.Time) error {
	trust.calls = append(trust.calls, trustCall{keyID: keyID, payload: append([]byte(nil), payload...),
		signature: append([]byte(nil), signature...), signedAt: signedAt, nowAt: now})
	if trust.err != nil {
		return trust.err
	}
	key, ok := trust.keys[keyID]
	if !ok {
		return entitlement.ErrUnknownKey
	}
	if !ed25519.Verify(key, payload, signature) {
		return entitlement.ErrInvalidSignature
	}
	return nil
}

func TestAuthorizeAcceptsFrozenCanonicalWires(t *testing.T) {
	fixture := newTestFixture()
	identityJSON, decisionJSON, trust := fixture.encoded(t)
	verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
	got, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected())
	if err != nil {
		t.Fatal(err)
	}
	want := Authorization{
		RequestID: fixture.decision.RequestID, CustomerID: fixture.decision.CustomerID,
		Action: fixture.decision.Action, InstallationID: fixture.identity.InstallationID,
		AuthorizationID: fixture.identity.AuthorizationID, TokenID: fixture.identity.TokenID,
		IdentityGeneration: fixture.identity.IdentityGeneration, PluginID: fixture.identity.PluginID,
		PluginVersion: fixture.identity.PluginVersion, ManifestSHA256: fixture.decision.ManifestSHA256,
		VerificationID: fixture.decision.VerificationID, AttestationID: fixture.decision.AttestationID,
		AttestationRevision: fixture.decision.AttestationRevision, ApprovalReceiptID: fixture.decision.ApprovalReceiptID,
		ApprovalRevision: fixture.decision.ApprovalRevision, CapabilityKind: fixture.decision.CapabilityKind,
		CapabilityCode: fixture.decision.CapabilityCode, EvaluatedAt: fixture.decision.EvaluatedAt,
		ExpiresAt: fixture.decision.ExpiresAt,
	}
	if got != want {
		t.Fatalf("authorization=%#v want %#v", got, want)
	}
	if len(trust.calls) != 2 || trust.calls[0].keyID != fixture.identity.KeyID ||
		trust.calls[1].keyID != fixture.decision.KeyID || trust.calls[0].signedAt != fixture.identity.IssuedAt ||
		trust.calls[1].signedAt != fixture.decision.EvaluatedAt || trust.calls[0].nowAt != fixture.now ||
		trust.calls[1].nowAt != fixture.now {
		t.Fatalf("trust calls=%#v", trust.calls)
	}
}

func TestAuthorizeFrozenCanonicalPayloadsAndDomains(t *testing.T) {
	fixture := newTestFixture()
	identityPayload := fixture.identityPayload(t)
	wantIdentity := `{"schema":"cdnca.plugin-service-identity/v1","algorithm":"Ed25519","key_id":"identity-key-1","token_id":"22222222-2222-4222-8222-222222222222","authorization_id":"33333333-3333-4333-8333-333333333333","installation_id":"11111111-1111-4111-8111-111111111111","plugin_id":"acme.runtime","plugin_version":"1.2.3","identity_generation":7,"scopes":["plugin.read","plugin.write"],"issued_at":"2026-08-07T03:59:00Z","expires_at":"2026-08-07T04:10:00Z"}`
	if string(identityPayload) != wantIdentity {
		t.Fatalf("identity payload=%s", identityPayload)
	}
	decisionPayload := fixture.decisionPayload(t)
	wantDecision := `{"schema":"cdnca.plugin-runtime-authorization/v2","request_id":"runtime-request-1","customer_id":"99999999-9999-4999-8999-999999999999","action":"plugin.read","installation_id":"11111111-1111-4111-8111-111111111111","authorization_id":"33333333-3333-4333-8333-333333333333","token_id":"22222222-2222-4222-8222-222222222222","identity_generation":7,"plugin_id":"acme.runtime","plugin_version":"1.2.3","manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verification_id":"44444444-4444-4444-8444-444444444444","attestation_id":"55555555-5555-4555-8555-555555555555","attestation_revision":9,"approval_receipt_id":"66666666-6666-4666-8666-666666666666","approval_revision":4,"capability_kind":"scope","capability_code":"plugin.read","decision":"allow","stable_reason_code":"authorized","evaluated_at":"2026-08-07T04:00:00Z","expires_at":"2026-08-07T04:01:00Z","algorithm":"Ed25519","key_id":"decision-key-1"}`
	if string(decisionPayload) != wantDecision {
		t.Fatalf("decision payload=%s", decisionPayload)
	}
	identityJSON, decisionJSON, trust := fixture.encoded(t)
	verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
	if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(trust.calls[0].payload, lengthPrefixedForTest("cdnca-plugin-service-identity/v1", identityPayload)) ||
		!bytes.Equal(trust.calls[1].payload, lengthPrefixedForTest("cdnca-plugin-runtime-authorization/v2", decisionPayload)) {
		t.Fatalf("wrong signing messages: %#v", trust.calls)
	}
}

func TestAuthorizeRejectsNonCanonicalRawJSON(t *testing.T) {
	fixture := newTestFixture()
	identityJSON, decisionJSON, _ := fixture.encoded(t)
	unknown := func(encoded []byte) []byte {
		return append(append([]byte(nil), encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)
	}
	cases := []struct {
		name                       string
		identityJSON, decisionJSON []byte
	}{
		{name: "identity whitespace", identityJSON: append([]byte(" "), identityJSON...), decisionJSON: decisionJSON},
		{name: "identity duplicate", identityJSON: bytes.Replace(identityJSON, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1), decisionJSON: decisionJSON},
		{name: "identity unknown", identityJSON: unknown(identityJSON), decisionJSON: decisionJSON},
		{name: "identity trailing", identityJSON: append(append([]byte(nil), identityJSON...), []byte(`{}`)...), decisionJSON: decisionJSON},
		{name: "identity null", identityJSON: bytes.Replace(identityJSON, []byte(`"plugin_id":"acme.runtime"`), []byte(`"plugin_id":null`), 1), decisionJSON: decisionJSON},
		{name: "identity type", identityJSON: bytes.Replace(identityJSON, []byte(`"identity_generation":7`), []byte(`"identity_generation":"7"`), 1), decisionJSON: decisionJSON},
		{name: "decision whitespace", identityJSON: identityJSON, decisionJSON: append([]byte("\n"), decisionJSON...)},
		{name: "decision duplicate", identityJSON: identityJSON, decisionJSON: bytes.Replace(decisionJSON, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1)},
		{name: "decision unknown", identityJSON: identityJSON, decisionJSON: unknown(decisionJSON)},
		{name: "decision trailing", identityJSON: identityJSON, decisionJSON: append(append([]byte(nil), decisionJSON...), []byte(`[]`)...)},
		{name: "decision null", identityJSON: identityJSON, decisionJSON: bytes.Replace(decisionJSON, []byte(`"manifest_sha256":"`+strings.Repeat("a", 64)+`"`), []byte(`"manifest_sha256":null`), 1)},
		{name: "decision type", identityJSON: identityJSON, decisionJSON: bytes.Replace(decisionJSON, []byte(`"approval_revision":4`), []byte(`"approval_revision":"4"`), 1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, _, trust := fixture.encoded(t)
			verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
			if _, err := verifier.Authorize(test.identityJSON, test.decisionJSON, fixture.expected()); err != ErrInvalid {
				t.Fatalf("error=%v want ErrInvalid", err)
			}
		})
	}
}

func TestAuthorizeIdentityValidationAndWindow(t *testing.T) {
	invalid := []struct {
		name string
		edit func(*testIdentityWire)
	}{
		{name: "schema", edit: func(value *testIdentityWire) { value.Schema = "unknown" }},
		{name: "algorithm", edit: func(value *testIdentityWire) { value.Algorithm = "none" }},
		{name: "key id", edit: func(value *testIdentityWire) { value.KeyID = "bad key" }},
		{name: "token", edit: func(value *testIdentityWire) { value.TokenID = uuid.Nil }},
		{name: "authorization", edit: func(value *testIdentityWire) { value.AuthorizationID = uuid.Nil }},
		{name: "installation", edit: func(value *testIdentityWire) { value.InstallationID = uuid.Nil }},
		{name: "plugin", edit: func(value *testIdentityWire) { value.PluginID = "Invalid" }},
		{name: "version", edit: func(value *testIdentityWire) { value.PluginVersion = "1.02.3" }},
		{name: "generation", edit: func(value *testIdentityWire) { value.IdentityGeneration = 0 }},
		{name: "scope order", edit: func(value *testIdentityWire) { value.Scopes = []string{"plugin.write", "plugin.read"} }},
		{name: "scope duplicate", edit: func(value *testIdentityWire) { value.Scopes = []string{"plugin.read", "plugin.read"} }},
		{name: "fractional issued", edit: func(value *testIdentityWire) { value.IssuedAt = value.IssuedAt.Add(time.Nanosecond) }},
		{name: "fractional expiry", edit: func(value *testIdentityWire) { value.ExpiresAt = value.ExpiresAt.Add(time.Nanosecond) }},
		{name: "nonpositive ttl", edit: func(value *testIdentityWire) { value.ExpiresAt = value.IssuedAt }},
		{name: "short ttl", edit: func(value *testIdentityWire) { value.ExpiresAt = value.IssuedAt.Add(time.Minute - time.Second) }},
		{name: "long ttl", edit: func(value *testIdentityWire) { value.ExpiresAt = value.IssuedAt.Add(15*time.Minute + time.Second) }},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture()
			test.edit(&fixture.identity)
			identityJSON, decisionJSON, trust := fixture.encoded(t)
			verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
			if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrInvalid {
				t.Fatalf("error=%v want ErrInvalid", err)
			}
		})
	}

	for _, test := range []struct {
		name string
		edit func(*testFixture)
	}{
		{name: "future", edit: func(value *testFixture) {
			value.identity.IssuedAt = value.now.Add(time.Second)
			value.identity.ExpiresAt = value.identity.IssuedAt.Add(time.Minute)
		}},
		{name: "expired", edit: func(value *testFixture) {
			value.identity.IssuedAt = value.now.Add(-time.Minute)
			value.identity.ExpiresAt = value.now
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture()
			test.edit(&fixture)
			identityJSON, decisionJSON, trust := fixture.encoded(t)
			verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
			if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrDenied {
				t.Fatalf("error=%v want ErrDenied", err)
			}
		})
	}
}

func TestAuthorizeDecisionValidationAndWindow(t *testing.T) {
	invalid := []struct {
		name string
		edit func(*testDecisionWire)
	}{
		{name: "schema", edit: func(value *testDecisionWire) { value.Schema = "unknown" }},
		{name: "request", edit: func(value *testDecisionWire) { value.RequestID = "bad request" }},
		{name: "customer", edit: func(value *testDecisionWire) { value.CustomerID = uuid.Nil }},
		{name: "action", edit: func(value *testDecisionWire) { value.Action = "plugin.write" }},
		{name: "installation", edit: func(value *testDecisionWire) { value.InstallationID = uuid.Nil }},
		{name: "authorization", edit: func(value *testDecisionWire) { value.AuthorizationID = uuid.Nil }},
		{name: "token", edit: func(value *testDecisionWire) { value.TokenID = uuid.Nil }},
		{name: "generation", edit: func(value *testDecisionWire) { value.IdentityGeneration = 0 }},
		{name: "plugin", edit: func(value *testDecisionWire) { value.PluginID = "Invalid" }},
		{name: "version", edit: func(value *testDecisionWire) { value.PluginVersion = "1.02.3" }},
		{name: "manifest", edit: func(value *testDecisionWire) { value.ManifestSHA256 = strings.Repeat("A", 64) }},
		{name: "verification", edit: func(value *testDecisionWire) { value.VerificationID = uuid.Nil }},
		{name: "attestation id", edit: func(value *testDecisionWire) { value.AttestationID = uuid.Nil }},
		{name: "attestation revision", edit: func(value *testDecisionWire) { value.AttestationRevision = 0 }},
		{name: "approval id", edit: func(value *testDecisionWire) { value.ApprovalReceiptID = uuid.Nil }},
		{name: "approval revision", edit: func(value *testDecisionWire) { value.ApprovalRevision = 0 }},
		{name: "kind", edit: func(value *testDecisionWire) { value.CapabilityKind = "unknown" }},
		{name: "code", edit: func(value *testDecisionWire) { value.CapabilityCode = "INVALID" }},
		{name: "decision", edit: func(value *testDecisionWire) { value.Decision = "unknown" }},
		{name: "reason", edit: func(value *testDecisionWire) { value.StableReasonCode = "" }},
		{name: "allow reason", edit: func(value *testDecisionWire) { value.StableReasonCode = "approval_missing" }},
		{name: "algorithm", edit: func(value *testDecisionWire) { value.Algorithm = "none" }},
		{name: "key id", edit: func(value *testDecisionWire) { value.KeyID = "bad key" }},
		{name: "fractional evaluated", edit: func(value *testDecisionWire) { value.EvaluatedAt = value.EvaluatedAt.Add(time.Nanosecond) }},
		{name: "fractional expiry", edit: func(value *testDecisionWire) { value.ExpiresAt = value.ExpiresAt.Add(time.Nanosecond) }},
		{name: "nonpositive window", edit: func(value *testDecisionWire) { value.ExpiresAt = value.EvaluatedAt }},
		{name: "allow too long", edit: func(value *testDecisionWire) { value.ExpiresAt = value.EvaluatedAt.Add(time.Minute + time.Second) }},
		{name: "deny authorized", edit: func(value *testDecisionWire) {
			value.Decision = "deny"
			value.ExpiresAt = value.EvaluatedAt.Add(15 * time.Second)
		}},
		{name: "deny too long", edit: func(value *testDecisionWire) {
			value.Decision = "deny"
			value.StableReasonCode = "approval_missing"
			value.ExpiresAt = value.EvaluatedAt.Add(16 * time.Second)
		}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture()
			test.edit(&fixture.decision)
			identityJSON, decisionJSON, trust := fixture.encoded(t)
			verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
			if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrInvalid {
				t.Fatalf("error=%v want ErrInvalid", err)
			}
		})
	}

	for _, test := range []struct {
		name string
		edit func(*testFixture)
	}{
		{name: "deny", edit: func(value *testFixture) {
			value.decision.Decision = "deny"
			value.decision.StableReasonCode = "approval_missing"
			value.decision.ApprovalReceiptID = uuid.Nil
			value.decision.ApprovalRevision = 0
			value.decision.ExpiresAt = value.decision.EvaluatedAt.Add(15 * time.Second)
		}},
		{name: "future", edit: func(value *testFixture) {
			value.decision.EvaluatedAt = value.now.Add(time.Second)
			value.decision.ExpiresAt = value.decision.EvaluatedAt.Add(time.Minute)
		}},
		{name: "expired", edit: func(value *testFixture) {
			value.decision.EvaluatedAt = value.now.Add(-time.Minute)
			value.decision.ExpiresAt = value.now
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture()
			test.edit(&fixture)
			identityJSON, decisionJSON, trust := fixture.encoded(t)
			verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
			if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrDenied {
				t.Fatalf("error=%v want ErrDenied", err)
			}
		})
	}
}

func TestAuthorizeBindsIdentityDecisionAndExpectedAction(t *testing.T) {
	cases := []struct {
		name     string
		edit     func(*testFixture)
		expected func(*ExpectedAction)
	}{
		{name: "installation", edit: func(value *testFixture) {
			value.decision.InstallationID = uuid.MustParse("99999999-9999-4999-8999-999999999999")
		}},
		{name: "request", expected: func(value *ExpectedAction) { value.RequestID = "other-request" }},
		{name: "customer", expected: func(value *ExpectedAction) {
			value.CustomerID = uuid.MustParse("88888888-8888-4888-8888-888888888888")
		}},
		{name: "authorization", edit: func(value *testFixture) {
			value.decision.AuthorizationID = uuid.MustParse("99999999-9999-4999-8999-999999999999")
		}},
		{name: "token", edit: func(value *testFixture) {
			value.decision.TokenID = uuid.MustParse("99999999-9999-4999-8999-999999999999")
		}},
		{name: "generation", edit: func(value *testFixture) { value.decision.IdentityGeneration++ }},
		{name: "plugin", edit: func(value *testFixture) { value.decision.PluginID = "other.runtime" }},
		{name: "version", edit: func(value *testFixture) { value.decision.PluginVersion = "1.2.4" }},
		{name: "kind", expected: func(value *ExpectedAction) {
			value.CapabilityKind, value.CapabilityCode, value.Action = "webhook", "plugin.callback", "plugin.webhook.deliver"
		}},
		{name: "code", expected: func(value *ExpectedAction) {
			value.CapabilityCode, value.Action = "plugin.write", "plugin.write"
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture()
			if test.edit != nil {
				test.edit(&fixture)
			}
			expected := fixture.expected()
			if test.expected != nil {
				test.expected(&expected)
			}
			identityJSON, decisionJSON, trust := fixture.encoded(t)
			verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
			if _, err := verifier.Authorize(identityJSON, decisionJSON, expected); err != ErrDenied {
				t.Fatalf("error=%v want ErrDenied", err)
			}
		})
	}
}

func TestAuthorizeReturnsStableRateLimitOnlyAfterExactBinding(t *testing.T) {
	fixture := newTestFixture()
	fixture.decision.Decision = "deny"
	fixture.decision.StableReasonCode = "runtime_rate_limited"
	fixture.decision.ApprovalReceiptID = uuid.Nil
	fixture.decision.ApprovalRevision = 0
	fixture.decision.ExpiresAt = fixture.now.Add(15 * time.Second)
	identityJSON, decisionJSON, trust := fixture.encoded(t)
	verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
	if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrRateLimited {
		t.Fatalf("error=%v want ErrRateLimited", err)
	}
	mismatch := fixture.expected()
	mismatch.CustomerID = uuid.MustParse("88888888-8888-4888-8888-888888888888")
	if _, err := verifier.Authorize(identityJSON, decisionJSON, mismatch); err != ErrDenied {
		t.Fatalf("mismatched binding error=%v want ErrDenied", err)
	}
}

func TestAuthorizeStableTrustAndSignatureErrors(t *testing.T) {
	fixture := newTestFixture()
	identityJSON, decisionJSON, trust := fixture.encoded(t)
	for name, verifier := range map[string]Verifier{
		"default":  {},
		"nil now":  {Trust: trust},
		"zero now": {Trust: trust, Now: func() time.Time { return time.Time{} }},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrTrustUnavailable {
				t.Fatalf("error=%v", err)
			}
		})
	}

	t.Run("unknown trust", func(t *testing.T) {
		unknown := &testTrust{keys: map[string]ed25519.PublicKey{}}
		verifier := Verifier{Trust: unknown, Now: func() time.Time { return fixture.now }}
		if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrTrustUnavailable {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("trust failure", func(t *testing.T) {
		failed := &testTrust{err: errors.New("trust backend secret")}
		verifier := Verifier{Trust: failed, Now: func() time.Time { return fixture.now }}
		if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrInvalid ||
			strings.Contains(err.Error(), "secret") {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("identity signature", func(t *testing.T) {
		broken := fixture
		broken.identity.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		identityJSON, err := json.Marshal(broken.identity)
		if err != nil {
			t.Fatal(err)
		}
		_, decisionJSON, trust := fixture.encoded(t)
		verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
		if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrInvalid {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("decision signature", func(t *testing.T) {
		broken := fixture
		broken.decision.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		decisionJSON, err := json.Marshal(broken.decision)
		if err != nil {
			t.Fatal(err)
		}
		identityJSON, _, trust := fixture.encoded(t)
		verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
		if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrInvalid {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("invalid expected", func(t *testing.T) {
		verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
		if _, err := verifier.Authorize(identityJSON, decisionJSON, ExpectedAction{}); err != ErrInvalid {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestAuthorizeTimeBoundaries(t *testing.T) {
	fixture := newTestFixture()
	fixture.identity.IssuedAt = fixture.now
	fixture.identity.ExpiresAt = fixture.now.Add(time.Minute)
	identityJSON, decisionJSON, trust := fixture.encoded(t)
	verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
	if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != nil {
		t.Fatalf("inclusive lower boundary rejected: %v", err)
	}

	fixture = newTestFixture()
	identityJSON, decisionJSON, trust = fixture.encoded(t)
	verifier = Verifier{Trust: trust, Now: func() time.Time { return fixture.decision.ExpiresAt }}
	if _, err := verifier.Authorize(identityJSON, decisionJSON, fixture.expected()); err != ErrDenied {
		t.Fatalf("exclusive decision expiry error=%v", err)
	}
}

func newTestFixture() testFixture {
	now := time.Date(2026, 8, 7, 4, 0, 0, 0, time.UTC)
	identityPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, ed25519.SeedSize))
	decisionPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, ed25519.SeedSize))
	return testFixture{
		now: now, identityPrivate: identityPrivate, decisionPrivate: decisionPrivate,
		identity: testIdentityWire{
			Schema: "cdnca.plugin-service-identity/v1", Algorithm: "Ed25519", KeyID: "identity-key-1",
			TokenID:         uuid.MustParse("22222222-2222-4222-8222-222222222222"),
			AuthorizationID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
			InstallationID:  uuid.MustParse("11111111-1111-4111-8111-111111111111"),
			PluginID:        "acme.runtime", PluginVersion: "1.2.3", IdentityGeneration: 7,
			Scopes: []string{"plugin.read", "plugin.write"}, IssuedAt: now.Add(-time.Minute),
			ExpiresAt: now.Add(10 * time.Minute),
		},
		decision: testDecisionWire{
			Schema: "cdnca.plugin-runtime-authorization/v2", RequestID: "runtime-request-1",
			CustomerID: uuid.MustParse("99999999-9999-4999-8999-999999999999"), Action: "plugin.read",
			InstallationID:  uuid.MustParse("11111111-1111-4111-8111-111111111111"),
			AuthorizationID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
			TokenID:         uuid.MustParse("22222222-2222-4222-8222-222222222222"), IdentityGeneration: 7,
			PluginID: "acme.runtime", PluginVersion: "1.2.3", ManifestSHA256: strings.Repeat("a", 64),
			VerificationID: uuid.MustParse("44444444-4444-4444-8444-444444444444"),
			AttestationID:  uuid.MustParse("55555555-5555-4555-8555-555555555555"), AttestationRevision: 9,
			ApprovalReceiptID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), ApprovalRevision: 4,
			CapabilityKind: "scope", CapabilityCode: "plugin.read", Decision: "allow",
			StableReasonCode: "authorized", EvaluatedAt: now, ExpiresAt: now.Add(time.Minute),
			Algorithm: "Ed25519", KeyID: "decision-key-1",
		},
	}
}

func (fixture testFixture) expected() ExpectedAction {
	return ExpectedAction{CustomerID: fixture.decision.CustomerID, InstallationID: fixture.identity.InstallationID,
		RequestID: fixture.decision.RequestID, CapabilityKind: fixture.decision.CapabilityKind,
		CapabilityCode: fixture.decision.CapabilityCode, Action: fixture.decision.Action}
}

func (fixture *testFixture) encoded(t *testing.T) ([]byte, []byte, *testTrust) {
	t.Helper()
	identityPayload := fixture.identityPayload(t)
	fixture.identity.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.identityPrivate,
		lengthPrefixedForTest("cdnca-plugin-service-identity/v1", identityPayload)))
	identityJSON, err := json.Marshal(fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	decisionPayload := fixture.decisionPayload(t)
	fixture.decision.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.decisionPrivate,
		lengthPrefixedForTest("cdnca-plugin-runtime-authorization/v2", decisionPayload)))
	decisionJSON, err := json.Marshal(fixture.decision)
	if err != nil {
		t.Fatal(err)
	}
	return identityJSON, decisionJSON, &testTrust{keys: map[string]ed25519.PublicKey{
		fixture.identity.KeyID: fixture.identityPrivate.Public().(ed25519.PublicKey),
		fixture.decision.KeyID: fixture.decisionPrivate.Public().(ed25519.PublicKey),
	}}
}

func (fixture testFixture) identityPayload(t *testing.T) []byte {
	t.Helper()
	payload, err := json.Marshal(testIdentityPayload{
		Schema: fixture.identity.Schema, Algorithm: fixture.identity.Algorithm, KeyID: fixture.identity.KeyID,
		TokenID: fixture.identity.TokenID, AuthorizationID: fixture.identity.AuthorizationID,
		InstallationID: fixture.identity.InstallationID, PluginID: fixture.identity.PluginID,
		PluginVersion: fixture.identity.PluginVersion, IdentityGeneration: fixture.identity.IdentityGeneration,
		Scopes:    append([]string(nil), fixture.identity.Scopes...),
		IssuedAt:  fixture.identity.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: fixture.identity.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func (fixture testFixture) decisionPayload(t *testing.T) []byte {
	t.Helper()
	payload, err := json.Marshal(testDecisionPayload{
		Schema: fixture.decision.Schema, RequestID: fixture.decision.RequestID,
		CustomerID: fixture.decision.CustomerID, Action: fixture.decision.Action,
		InstallationID: fixture.decision.InstallationID, AuthorizationID: fixture.decision.AuthorizationID,
		TokenID: fixture.decision.TokenID, IdentityGeneration: fixture.decision.IdentityGeneration,
		PluginID: fixture.decision.PluginID, PluginVersion: fixture.decision.PluginVersion,
		ManifestSHA256: fixture.decision.ManifestSHA256, VerificationID: fixture.decision.VerificationID,
		AttestationID: fixture.decision.AttestationID, AttestationRevision: fixture.decision.AttestationRevision,
		ApprovalReceiptID: fixture.decision.ApprovalReceiptID, ApprovalRevision: fixture.decision.ApprovalRevision,
		CapabilityKind: fixture.decision.CapabilityKind, CapabilityCode: fixture.decision.CapabilityCode,
		Decision: fixture.decision.Decision, StableReasonCode: fixture.decision.StableReasonCode,
		EvaluatedAt: fixture.decision.EvaluatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:   fixture.decision.ExpiresAt.UTC().Format(time.RFC3339),
		Algorithm:   fixture.decision.Algorithm, KeyID: fixture.decision.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func lengthPrefixedForTest(domain string, payload []byte) []byte {
	result := make([]byte, 0, len(domain)+len(payload)+8)
	for _, field := range [][]byte{[]byte(domain), payload} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		result = append(result, size[:]...)
		result = append(result, field...)
	}
	return result
}

func TestAuthorizeWithoutExpectedCustomerBindsTheInstallation(t *testing.T) {
	fixture := newTestFixture()
	identityJSON, decisionJSON, trust := fixture.encoded(t)
	verifier := Verifier{Trust: trust, Now: func() time.Time { return fixture.now }}
	expected := fixture.expected()
	expected.CustomerID = uuid.Nil
	authorization, err := verifier.Authorize(identityJSON, decisionJSON, expected)
	if err != nil || authorization.CustomerID != fixture.decision.CustomerID {
		t.Fatalf("installation-bound authorization=%+v err=%v", authorization, err)
	}
	expected.InstallationID = uuid.MustParse("88888888-8888-4888-8888-888888888888")
	if _, err := verifier.Authorize(identityJSON, decisionJSON, expected); err != ErrDenied {
		t.Fatalf("other installation error=%v want ErrDenied", err)
	}
}
