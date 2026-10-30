package platformpolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

type contractFixture struct {
	Schema                   string `json:"schema"`
	PlatformSigningPublicKey string `json:"platform_signing_public_key"`
	InstallationPublicKey    string `json:"installation_public_key"`
	CanonicalPolicy          string `json:"canonical_policy"`
	PolicySHA256             string `json:"policy_sha256"`
	CanonicalEnvelope        string `json:"canonical_envelope"`
	Signature                string `json:"signature"`
	SignedTarget             string `json:"signed_target"`
	Resolve                  struct {
		Request      json.RawMessage `json:"request"`
		ProofMessage string          `json:"proof_message"`
		Proof        string          `json:"proof"`
	} `json:"resolve"`
	Acknowledgement struct {
		Request      json.RawMessage `json:"request"`
		ProofMessage string          `json:"proof_message"`
		Proof        string          `json:"proof"`
	} `json:"acknowledgement"`
}

func TestPlatformPolicyV1ContractFixture(t *testing.T) {
	fixture := loadContractFixture(t)
	if fixture.Schema != "cdnca-platform-policy-contract/v1" {
		t.Fatalf("fixture schema = %q", fixture.Schema)
	}
	platformKey := ed25519.PublicKey(decodeFixtureBase64(t, fixture.PlatformSigningPublicKey))
	installationKey := ed25519.PublicKey(decodeFixtureBase64(t, fixture.InstallationPublicKey))
	if len(platformKey) != ed25519.PublicKeySize || len(installationKey) != ed25519.PublicKeySize ||
		bytes.Equal(platformKey, installationKey) {
		t.Fatalf("fixture trust domains are invalid: platform=%d installation=%d equal=%t",
			len(platformKey), len(installationKey), bytes.Equal(platformKey, installationKey))
	}
	wire := decodeFixtureBase64(t, fixture.SignedTarget)
	signed, err := Decode(wire)
	if err != nil {
		t.Fatalf("Decode(fixture) error = %v", err)
	}
	policyBytes, err := CanonicalPolicy(signed.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if expected := decodeFixtureBase64(t, fixture.CanonicalPolicy); !bytes.Equal(policyBytes, expected) {
		t.Fatalf("canonical policy mismatch\n got: %s\nwant: %s", policyBytes, expected)
	}
	digest := sha256.Sum256(policyBytes)
	if actual := base64.RawURLEncoding.EncodeToString(digest[:]); actual != fixture.PolicySHA256 {
		t.Fatalf("policy digest = %q, want %q", actual, fixture.PolicySHA256)
	}
	envelopeBytes, err := CanonicalEnvelope(signed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	if expected := decodeFixtureBase64(t, fixture.CanonicalEnvelope); !bytes.Equal(envelopeBytes, expected) {
		t.Fatalf("canonical envelope mismatch\n got: %s\nwant: %s", envelopeBytes, expected)
	}
	signature := decodeFixtureBase64(t, fixture.Signature)
	if signed.Signature != fixture.Signature || !ed25519.Verify(platformKey, envelopeBytes, signature) {
		t.Fatal("fixture target signature did not verify")
	}
	if ed25519.Verify(installationKey, envelopeBytes, signature) {
		t.Fatal("installation key incorrectly verified platform target signature")
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signed.Envelope.KeyID, PublicKey: platformKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	installationID := uuid.MustParse(*signed.Envelope.InstallationID)
	if _, err := Verify(signed, trust, VerifyOptions{
		Now: time.Unix(signed.Envelope.ValidFrom+60, 0), InstallationID: installationID,
		ControlVersion: "1.4.0", ProtocolVersion: 1, DeliveredByResolve: true,
	}); err != nil {
		t.Fatalf("Verify(fixture) error = %v", err)
	}

	var resolve ResolveRequest
	if err := json.Unmarshal(fixture.Resolve.Request, &resolve); err != nil {
		t.Fatal(err)
	}
	assertProofFixture(t, installationKey, platformKey, ResolveProofMessage(resolve),
		fixture.Resolve.ProofMessage, fixture.Resolve.Proof)
	resolveResponse, err := json.Marshal(struct {
		Schema         string            `json:"schema"`
		RequestID      string            `json:"request_id"`
		InstallationID string            `json:"installation_id"`
		ResolvedAt     int64             `json:"resolved_at"`
		Cursor         string            `json:"cursor"`
		ETag           string            `json:"etag"`
		NotModified    bool              `json:"not_modified"`
		Targets        []json.RawMessage `json:"targets"`
	}{ResolveResponseSchema, resolve.RequestID, resolve.InstallationID, resolve.RequestedAt + 1,
		"fixture-cursor", "fixture-etag", false, []json.RawMessage{wire}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := decodeResolveResponse(resolveResponse, resolve.RequestID, installationID)
	if err != nil || len(resolved.Targets) != 1 ||
		resolved.Targets[0].Signed.Envelope.TargetRevisionID != signed.Envelope.TargetRevisionID {
		t.Fatalf("shared target resolve wire = (%#v, %v)", resolved, err)
	}
	var acknowledgement AckRequest
	if err := json.Unmarshal(fixture.Acknowledgement.Request, &acknowledgement); err != nil {
		t.Fatal(err)
	}
	assertProofFixture(t, installationKey, platformKey, AckProofMessage(acknowledgement),
		fixture.Acknowledgement.ProofMessage, fixture.Acknowledgement.Proof)
}

func TestVerifyPreservesEmptyPolicyArrays(t *testing.T) {
	now := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	signed.Policy.BlockedControlVersions = []string{}
	signed.Policy.PluginMarket.TrustedCatalogIDs = []string{}
	canonicalPolicy, err := CanonicalPolicy(signed.Policy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonicalPolicy)
	signed.Envelope.CanonicalPolicySHA256 = base64.RawURLEncoding.EncodeToString(digest[:])
	resignTestPolicy(t, &signed, privateKey)

	verified, err := Verify(signed, testPolicyTrust(t, publicKey), VerifyOptions{
		Now: now, InstallationID: installationID, ControlVersion: "1.4.0",
		ProtocolVersion: 1, DeliveredByResolve: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Signed.Policy.BlockedControlVersions == nil ||
		verified.Signed.Policy.PluginMarket.TrustedCatalogIDs == nil {
		t.Fatal("Verify() changed signed empty arrays to null slices")
	}
	clonedPolicy, err := CanonicalPolicy(verified.Signed.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clonedPolicy, canonicalPolicy) {
		t.Fatalf("cloned canonical policy = %s, want %s", clonedPolicy, canonicalPolicy)
	}
	originalJSON, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	clonedJSON, err := json.Marshal(verified.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clonedJSON, originalJSON) {
		t.Fatalf("verified signed policy changed\n got: %s\nwant: %s", clonedJSON, originalJSON)
	}
}

func TestCanonicalPolicyOrdersSchemaBeforeCCSystemRules(t *testing.T) {
	policy := &Policy{
		Schema:                 PolicySchema,
		MinimumControlVersion:  "1.4.0",
		BlockedControlVersions: []string{},
		AllowedReleaseChannels: []string{"stable"},
		PluginMarket:           PluginMarket{Enabled: false, TrustedCatalogIDs: []string{}},
		CCSystemRules: []CCSystemRule{{
			ID: "10002", Key: "cc.system.00000", Name: "关闭", Sort: 1,
			Filter: &CCSystemFilter{Type: "off", Parameters: map[string]any{}},
		}},
	}
	canonical, err := CanonicalPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	schemaAt := bytes.Index(canonical, []byte(`"schema"`))
	rulesAt := bytes.Index(canonical, []byte(`"cc_system_rules"`))
	if schemaAt < 0 || rulesAt < 0 || schemaAt > rulesAt {
		t.Fatalf("canonical policy key order schema=%d cc_system_rules=%d: %s", schemaAt, rulesAt, canonical)
	}
}

func TestDecodeRejectsNonStrictJSON(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	_, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey)
	wire, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"unknown field": bytes.Replace(wire, []byte(`{"envelope":`), []byte(`{"unknown":true,"envelope":`), 1),
		"duplicate key": bytes.Replace(wire, []byte(`{"envelope":`), []byte(`{"envelope":null,"envelope":`), 1),
		"duplicate envelope key": bytes.Replace(wire, []byte(`"domain":`),
			[]byte(`"domain":"cdnca-platform-policy-signature/v1","domain":`), 1),
		"duplicate policy key": bytes.Replace(wire, []byte(`"minimum_control_version":`),
			[]byte(`"minimum_control_version":"1.4.0","minimum_control_version":`), 1),
		"duplicate nested key": bytes.Replace(wire, []byte(`"plugin_market":{"enabled":`),
			[]byte(`"plugin_market":{"enabled":true,"enabled":`), 1),
		"trailing value": append(append([]byte(nil), wire...), []byte(` {}`)...),
		"invalid utf8":   append(append([]byte(nil), wire...), 0xff),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(encoded); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}
}

func TestCanonicalPolicyRejectsNonCanonicalInput(t *testing.T) {
	base := Policy{
		Schema: PolicySchema, MinimumControlVersion: "1.4.0",
		BlockedControlVersions: []string{"1.4.1", "1.4.2"},
		AllowedReleaseChannels: []string{"lts", "stable"},
		PluginMarket: PluginMarket{Enabled: true,
			TrustedCatalogIDs: []string{"cdnca-official", "partner-cn"}},
	}
	tests := map[string]func(*Policy){
		"schema whitespace": func(policy *Policy) { policy.Schema = " " + PolicySchema },
		"schema case":       func(policy *Policy) { policy.Schema = "Platform-policy/v1" },
		"semver whitespace": func(policy *Policy) { policy.MinimumControlVersion = " 1.4.0" },
		"semver v prefix":   func(policy *Policy) { policy.MinimumControlVersion = "v1.4.0" },
		"semver build":      func(policy *Policy) { policy.MinimumControlVersion = "1.4.0+build" },
		"blocked unsorted": func(policy *Policy) {
			policy.BlockedControlVersions = []string{"1.4.2", "1.4.1"}
		},
		"blocked duplicate": func(policy *Policy) {
			policy.BlockedControlVersions = []string{"1.4.1", "1.4.1"}
		},
		"channel uppercase":  func(policy *Policy) { policy.AllowedReleaseChannels = []string{"Stable"} },
		"channel whitespace": func(policy *Policy) { policy.AllowedReleaseChannels = []string{"stable "} },
		"channel unsorted": func(policy *Policy) {
			policy.AllowedReleaseChannels = []string{"stable", "lts"}
		},
		"channel duplicate": func(policy *Policy) {
			policy.AllowedReleaseChannels = []string{"stable", "stable"}
		},
		"catalog uppercase": func(policy *Policy) {
			policy.PluginMarket.TrustedCatalogIDs = []string{"CDNCA"}
		},
		"catalog whitespace": func(policy *Policy) {
			policy.PluginMarket.TrustedCatalogIDs = []string{"cdnca-official "}
		},
		"catalog unsorted": func(policy *Policy) {
			policy.PluginMarket.TrustedCatalogIDs = []string{"partner-cn", "cdnca-official"}
		},
		"catalog duplicate": func(policy *Policy) {
			policy.PluginMarket.TrustedCatalogIDs = []string{"cdnca-official", "cdnca-official"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := clonePolicy(base)
			mutate(&policy)
			if _, err := CanonicalPolicy(&policy); err == nil {
				t.Fatal("CanonicalPolicy() accepted non-canonical input")
			}
		})
	}
}

func TestCanonicalEnvelopeRejectsNonCanonicalIdentifiers(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	_, privateKey := testPolicyKey()
	base := testSignedPolicy(t, now, installationID, ScopeInstallation, 1, "", ActionApply, privateKey).Envelope
	tests := map[string]func(*Envelope){
		"domain whitespace": func(envelope *Envelope) { envelope.Domain += " " },
		"schema case":       func(envelope *Envelope) { envelope.Schema = "Platform-policy/v1" },
		"scope case":        func(envelope *Envelope) { envelope.ScopeKind = "Installation" },
		"target uppercase": func(envelope *Envelope) {
			envelope.TargetRevisionID = strings.ToUpper(envelope.TargetRevisionID)
		},
		"installation uppercase": func(envelope *Envelope) {
			value := strings.ToUpper(*envelope.InstallationID)
			envelope.InstallationID = &value
		},
		"target whitespace": func(envelope *Envelope) { envelope.TargetRevisionID += " " },
		"digest padding":    func(envelope *Envelope) { envelope.CanonicalPolicySHA256 += "=" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := base
			envelope.InstallationID = cloneString(base.InstallationID)
			mutate(&envelope)
			if _, err := CanonicalEnvelope(envelope); err == nil {
				t.Fatal("CanonicalEnvelope() accepted non-canonical input")
			}
		})
	}
}

func TestVerifyPolicyValidationAndRevisionRules(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	trust := testPolicyTrust(t, publicKey)
	base := testSignedPolicy(t, now, installationID, ScopeInstallation, 4, uuid.NewString(), ActionApply, privateKey)
	baseOptions := VerifyOptions{
		Now: now, InstallationID: installationID, ControlVersion: "1.4.0",
		ProtocolVersion: 1, DeliveredByResolve: true,
	}

	tests := []struct {
		name   string
		mutate func(*SignedPlatformPolicy, *VerifyOptions)
		want   error
	}{
		{name: "valid resolve gap"},
		{name: "signed at clock skew boundary", mutate: func(signed *SignedPlatformPolicy, _ *VerifyOptions) {
			signed.Envelope.SignedAt = now.Add(maxSigningClockSkew).Unix()
			resignTestPolicy(t, signed, privateKey)
		}},
		{name: "signed at beyond clock skew", mutate: func(signed *SignedPlatformPolicy, _ *VerifyOptions) {
			signed.Envelope.SignedAt = now.Add(maxSigningClockSkew + time.Second).Unix()
			resignTestPolicy(t, signed, privateKey)
		}, want: ErrInvalidEnvelope},
		{name: "signed at expiration", mutate: func(signed *SignedPlatformPolicy, _ *VerifyOptions) {
			signed.Envelope.SignedAt = signed.Envelope.ExpiresAt
		}, want: ErrInvalidEnvelope},
		{name: "gap outside resolve", mutate: func(_ *SignedPlatformPolicy, options *VerifyOptions) {
			options.DeliveredByResolve = false
		}, want: ErrRevisionOutOfOrder},
		{name: "wrong direct predecessor", mutate: func(signed *SignedPlatformPolicy, options *VerifyOptions) {
			options.Head = &ScopeHead{TargetRevisionID: uuid.NewString(), ScopeRevision: 3}
		}, want: ErrSupersedesMismatch},
		{name: "target mismatch", mutate: func(_ *SignedPlatformPolicy, options *VerifyOptions) {
			options.InstallationID = uuid.New()
		}, want: ErrTargetMismatch},
		{name: "not yet valid", mutate: func(_ *SignedPlatformPolicy, options *VerifyOptions) {
			options.Now = now.Add(-2 * time.Minute)
		}, want: ErrNotYetValid},
		{name: "expired", mutate: func(_ *SignedPlatformPolicy, options *VerifyOptions) {
			options.Now = now.Add(2 * time.Hour)
		}, want: ErrExpired},
		{name: "control too old", mutate: func(_ *SignedPlatformPolicy, options *VerifyOptions) {
			options.ControlVersion = "1.3.9"
		}, want: ErrControlVersionTooOld},
		{name: "control blocked", mutate: func(_ *SignedPlatformPolicy, options *VerifyOptions) {
			options.ControlVersion = "1.4.1"
		}, want: ErrControlVersionBlocked},
		{name: "protocol incompatible", mutate: func(_ *SignedPlatformPolicy, options *VerifyOptions) {
			options.ProtocolVersion = 2
		}, want: ErrProtocolIncompatible},
		{name: "digest mismatch", mutate: func(signed *SignedPlatformPolicy, _ *VerifyOptions) {
			signed.Policy.AllowedReleaseChannels = []string{"stable"}
		}, want: ErrPolicyDigestMismatch},
		{name: "invalid signature", mutate: func(signed *SignedPlatformPolicy, _ *VerifyOptions) {
			signature := decodeFixtureBase64(t, signed.Signature)
			signature[0] ^= 0x80
			signed.Signature = base64.RawURLEncoding.EncodeToString(signature)
		}, want: ErrInvalidSignature},
		{name: "unknown schema", mutate: func(signed *SignedPlatformPolicy, _ *VerifyOptions) {
			signed.Policy.Schema = "platform-policy/v2"
		}, want: ErrUnknownSchema},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signed := cloneSigned(base)
			options := baseOptions
			if test.mutate != nil {
				test.mutate(&signed, &options)
			}
			_, err := Verify(signed, trust, options)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyRecognizesOnlyExactDuplicate(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	head := &ScopeHead{TargetRevisionID: signed.Envelope.TargetRevisionID,
		ScopeRevision: signed.Envelope.ScopeRevision, CanonicalPolicySHA256: signed.Envelope.CanonicalPolicySHA256,
		Signature: signed.Signature}
	verified, err := Verify(signed, testPolicyTrust(t, publicKey), VerifyOptions{
		Now: now, InstallationID: installationID, ControlVersion: "1.4.0", ProtocolVersion: 1,
		Head: head, DeliveredByResolve: true,
	})
	if err != nil || !verified.Duplicate {
		t.Fatalf("Verify(duplicate) = (%t, %v)", verified.Duplicate, err)
	}
	head.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := Verify(signed, testPolicyTrust(t, publicKey), VerifyOptions{
		Now: now, InstallationID: installationID, ControlVersion: "1.4.0", ProtocolVersion: 1,
		Head: head, DeliveredByResolve: true,
	}); !errors.Is(err, ErrRevisionOutOfOrder) {
		t.Fatalf("Verify(conflicting replay) error = %v", err)
	}
}

func TestVerifyUsesSignedAtAndRequiresKeyCoverageThroughExpiration(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	installationID := uuid.New()
	publicKey, privateKey := testPolicyKey()
	signed := testSignedPolicy(t, now, installationID, ScopeGlobal, 1, "", ActionApply, privateKey)
	signedAt := time.Unix(signed.Envelope.SignedAt, 0).UTC()
	expiresAt := time.Unix(signed.Envelope.ExpiresAt, 0).UTC()
	signUntil := signedAt.Add(time.Second)
	verifyUntil := expiresAt
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signed.Envelope.KeyID, PublicKey: publicKey, NotBefore: signedAt.Add(-time.Second),
		SignUntil: &signUntil, VerifyUntil: &verifyUntil,
	}})
	if err != nil {
		t.Fatal(err)
	}
	options := VerifyOptions{Now: now, InstallationID: installationID,
		ControlVersion: "1.4.0", ProtocolVersion: 1, DeliveredByResolve: true}
	if _, err := Verify(signed, trust, options); err != nil {
		t.Fatalf("Verify(key covers expiration) error = %v", err)
	}
	verifyUntil = expiresAt.Add(-time.Second)
	trust, err = entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signed.Envelope.KeyID, PublicKey: publicKey, NotBefore: signedAt.Add(-time.Second),
		SignUntil: &signUntil, VerifyUntil: &verifyUntil,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, trust, options); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Verify(key ends before expiration) error = %v", err)
	}
}

func TestValidControlVersionRequiresCanonicalSemver(t *testing.T) {
	for value, want := range map[string]bool{
		"0.0.0": true, "1.4.0": true, "1.4.0-rc.1": true,
		"": false, "v1.4.0": false, "1.04.0": false, "1.4": false, "1.4.0+build": false,
	} {
		if got := ValidControlVersion(value); got != want {
			t.Errorf("ValidControlVersion(%q) = %t, want %t", value, got, want)
		}
	}
}

func loadContractFixture(t *testing.T) contractFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "tests", "contracts", "platform-policy-v1.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture contractFixture
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func decodeFixtureBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func assertProofFixture(t *testing.T, installationKey, wrongPlatformKey ed25519.PublicKey,
	actual []byte, encodedMessage, encodedProof string) {
	t.Helper()
	expected := decodeFixtureBase64(t, encodedMessage)
	if !bytes.Equal(actual, expected) {
		t.Fatalf("proof message mismatch: got %x want %x", actual, expected)
	}
	proof := decodeFixtureBase64(t, encodedProof)
	if !ed25519.Verify(installationKey, actual, proof) {
		t.Fatal("fixture proof signature did not verify")
	}
	if ed25519.Verify(wrongPlatformKey, actual, proof) {
		t.Fatal("platform signing key incorrectly verified installation proof")
	}
}

func testPolicyKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("cdnca-platform-policy-consumer-tests-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func testPolicyTrust(t *testing.T, publicKey ed25519.PublicKey) *entitlementguard.TrustStore {
	t.Helper()
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "platform-policy-test-key", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func testSignedPolicy(t *testing.T, now time.Time, installationID uuid.UUID, scope string,
	revision int64, supersedes, action string, privateKey ed25519.PrivateKey) SignedPlatformPolicy {
	t.Helper()
	var policy *Policy
	if action == ActionApply {
		policy = &Policy{
			Schema: PolicySchema, MinimumControlVersion: "1.4.0",
			BlockedControlVersions: []string{"1.4.1"}, AllowedReleaseChannels: []string{"lts", "stable"},
			PluginMarket: PluginMarket{Enabled: true, TrustedCatalogIDs: []string{"cdnca-official"}},
		}
	}
	policyBytes, err := CanonicalPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(policyBytes)
	envelope := Envelope{
		Domain: SignatureDomain, TargetRevisionID: uuid.NewString(), Action: action, Schema: PolicySchema,
		ScopeKind: scope, ScopeRevision: revision, SignedAt: now.Add(-2 * time.Minute).Unix(),
		ValidFrom: now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), ControlProtocolMin: 1, ControlProtocolMax: 1,
		CanonicalPolicySHA256: base64.RawURLEncoding.EncodeToString(digest[:]), KeyID: "platform-policy-test-key",
	}
	if scope == ScopeInstallation {
		value := installationID.String()
		envelope.InstallationID = &value
	}
	if revision > 1 {
		envelope.Supersedes = &supersedes
	}
	envelopeBytes, err := CanonicalEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return SignedPlatformPolicy{Envelope: envelope, Policy: policy,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, envelopeBytes))}
}

func resignTestPolicy(t *testing.T, signed *SignedPlatformPolicy, privateKey ed25519.PrivateKey) {
	t.Helper()
	envelopeBytes, err := CanonicalEnvelope(signed.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, envelopeBytes))
}
