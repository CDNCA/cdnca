package pluginruntimeauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
)

const (
	serviceIdentitySchema        = "cdnca.plugin-service-identity/v1"
	serviceIdentitySigningDomain = "cdnca-plugin-service-identity/v1"
	runtimeAuthorizationSchema   = "cdnca.plugin-runtime-authorization/v2"
	runtimeAuthorizationDomain   = "cdnca-plugin-runtime-authorization/v2"
	maximumWireBytes             = 64 << 10
)

var (
	ErrDenied           = errors.New("plugin runtime authorization denied")
	ErrRateLimited      = errors.New("plugin runtime authorization rate limited")
	ErrInvalid          = errors.New("plugin runtime authorization invalid")
	ErrTrustUnavailable = errors.New("plugin runtime authorization trust unavailable")

	pluginSlugPattern   = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	semverPattern       = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)
	permissionPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,7}$`)
	subscriptionPattern = regexp.MustCompile(`^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$`)
	hexDigestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type DetachedVerifier interface {
	VerifyDetached(keyID string, payload, signature []byte, signedAt, now time.Time) error
}

type Verifier struct {
	Trust DetachedVerifier
	Now   func() time.Time
}

type ExpectedAction struct {
	// CustomerID is the platform license customer. The license service derives it from the control installation,
	// which already binds the decision (InstallationID); control tenants are a different ID space. A zero value
	// accepts the installation-bound customer, a non-zero value must match exactly.
	CustomerID     uuid.UUID
	InstallationID uuid.UUID
	RequestID      string
	CapabilityKind string
	CapabilityCode string
	Action         string
}

type Authorization struct {
	RequestID           string
	CustomerID          uuid.UUID
	Action              string
	InstallationID      uuid.UUID
	AuthorizationID     uuid.UUID
	TokenID             uuid.UUID
	IdentityGeneration  uint64
	PluginID            string
	PluginVersion       string
	ManifestSHA256      string
	VerificationID      uuid.UUID
	AttestationID       uuid.UUID
	AttestationRevision uint64
	ApprovalReceiptID   uuid.UUID
	ApprovalRevision    uint64
	CapabilityKind      string
	CapabilityCode      string
	EvaluatedAt         time.Time
	ExpiresAt           time.Time
}

type serviceIdentity struct {
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

type serviceIdentityPayload struct {
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

type runtimeAuthorization struct {
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

type runtimeAuthorizationPayload struct {
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

func (verifier Verifier) Authorize(identityJSON, decisionJSON []byte,
	expected ExpectedAction) (Authorization, error) {
	if verifier.Trust == nil || verifier.Now == nil {
		return Authorization{}, ErrTrustUnavailable
	}
	now := verifier.Now()
	if now.IsZero() {
		return Authorization{}, ErrTrustUnavailable
	}
	if !validExpectedAction(expected) {
		return Authorization{}, ErrInvalid
	}
	identity, identityPayload, identitySignature, err := decodeServiceIdentity(identityJSON)
	if err != nil {
		return Authorization{}, ErrInvalid
	}
	decision, decisionPayload, decisionSignature, err := decodeRuntimeAuthorization(decisionJSON)
	if err != nil {
		return Authorization{}, ErrInvalid
	}
	if err := verifyDetached(verifier.Trust, identity.KeyID,
		lengthPrefixed(serviceIdentitySigningDomain, identityPayload), identitySignature, identity.IssuedAt, now); err != nil {
		return Authorization{}, err
	}
	if err := verifyDetached(verifier.Trust, decision.KeyID,
		lengthPrefixed(runtimeAuthorizationDomain, decisionPayload), decisionSignature, decision.EvaluatedAt, now); err != nil {
		return Authorization{}, err
	}
	if now.Before(identity.IssuedAt) || !now.Before(identity.ExpiresAt) ||
		now.Before(decision.EvaluatedAt) || !now.Before(decision.ExpiresAt) {
		return Authorization{}, ErrDenied
	}
	if decision.CustomerID == uuid.Nil || expected.CustomerID != uuid.Nil && decision.CustomerID != expected.CustomerID ||
		decision.Action != expected.Action ||
		identity.InstallationID != expected.InstallationID || decision.InstallationID != expected.InstallationID ||
		decision.RequestID != expected.RequestID || decision.AuthorizationID != identity.AuthorizationID ||
		decision.TokenID != identity.TokenID || decision.IdentityGeneration != identity.IdentityGeneration ||
		decision.PluginID != identity.PluginID || decision.PluginVersion != identity.PluginVersion ||
		decision.CapabilityKind != expected.CapabilityKind || decision.CapabilityCode != expected.CapabilityCode {
		return Authorization{}, ErrDenied
	}
	if decision.Decision != "allow" {
		if decision.StableReasonCode == "runtime_rate_limited" {
			return Authorization{}, ErrRateLimited
		}
		return Authorization{}, ErrDenied
	}
	return Authorization{
		RequestID: decision.RequestID, CustomerID: decision.CustomerID, Action: decision.Action,
		InstallationID:  decision.InstallationID,
		AuthorizationID: decision.AuthorizationID, TokenID: decision.TokenID,
		IdentityGeneration: decision.IdentityGeneration, PluginID: decision.PluginID,
		PluginVersion: decision.PluginVersion, ManifestSHA256: decision.ManifestSHA256,
		VerificationID: decision.VerificationID, AttestationID: decision.AttestationID,
		AttestationRevision: decision.AttestationRevision, ApprovalReceiptID: decision.ApprovalReceiptID,
		ApprovalRevision: decision.ApprovalRevision, CapabilityKind: decision.CapabilityKind,
		CapabilityCode: decision.CapabilityCode, EvaluatedAt: decision.EvaluatedAt, ExpiresAt: decision.ExpiresAt,
	}, nil
}

func decodeServiceIdentity(encoded []byte) (serviceIdentity, []byte, []byte, error) {
	var identity serviceIdentity
	if !decodeCanonicalWire(encoded, &identity) || !validServiceIdentity(identity) {
		return serviceIdentity{}, nil, nil, ErrInvalid
	}
	signature, ok := decodeSignature(identity.Signature)
	if !ok {
		return serviceIdentity{}, nil, nil, ErrInvalid
	}
	payload, err := json.Marshal(serviceIdentityPayload{
		Schema: identity.Schema, Algorithm: identity.Algorithm, KeyID: identity.KeyID,
		TokenID: identity.TokenID, AuthorizationID: identity.AuthorizationID,
		InstallationID: identity.InstallationID, PluginID: identity.PluginID,
		PluginVersion: identity.PluginVersion, IdentityGeneration: identity.IdentityGeneration,
		Scopes:    append([]string(nil), identity.Scopes...),
		IssuedAt:  identity.IssuedAt.UTC().Format(time.RFC3339),
		ExpiresAt: identity.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return serviceIdentity{}, nil, nil, ErrInvalid
	}
	return identity, payload, signature, nil
}

func decodeRuntimeAuthorization(encoded []byte) (runtimeAuthorization, []byte, []byte, error) {
	var decision runtimeAuthorization
	if !decodeCanonicalWire(encoded, &decision) || !validRuntimeAuthorization(decision) {
		return runtimeAuthorization{}, nil, nil, ErrInvalid
	}
	signature, ok := decodeSignature(decision.Signature)
	if !ok {
		return runtimeAuthorization{}, nil, nil, ErrInvalid
	}
	payload, err := json.Marshal(runtimeAuthorizationPayload{
		Schema: decision.Schema, RequestID: decision.RequestID, CustomerID: decision.CustomerID,
		Action: decision.Action, InstallationID: decision.InstallationID,
		AuthorizationID: decision.AuthorizationID, TokenID: decision.TokenID,
		IdentityGeneration: decision.IdentityGeneration, PluginID: decision.PluginID,
		PluginVersion: decision.PluginVersion, ManifestSHA256: decision.ManifestSHA256,
		VerificationID: decision.VerificationID, AttestationID: decision.AttestationID,
		AttestationRevision: decision.AttestationRevision, ApprovalReceiptID: decision.ApprovalReceiptID,
		ApprovalRevision: decision.ApprovalRevision, CapabilityKind: decision.CapabilityKind,
		CapabilityCode: decision.CapabilityCode, Decision: decision.Decision,
		StableReasonCode: decision.StableReasonCode,
		EvaluatedAt:      decision.EvaluatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:        decision.ExpiresAt.UTC().Format(time.RFC3339), Algorithm: decision.Algorithm, KeyID: decision.KeyID,
	})
	if err != nil {
		return runtimeAuthorization{}, nil, nil, ErrInvalid
	}
	return decision, payload, signature, nil
}

func decodeCanonicalWire[T any](encoded []byte, destination *T) bool {
	if len(encoded) == 0 || len(encoded) > maximumWireBytes || json.Unmarshal(encoded, destination) != nil {
		return false
	}
	canonical, err := json.Marshal(destination)
	return err == nil && bytes.Equal(canonical, encoded)
}

func validServiceIdentity(identity serviceIdentity) bool {
	if identity.Schema != serviceIdentitySchema || identity.Algorithm != "Ed25519" ||
		entitlement.ValidateKeyID(identity.KeyID) != nil || identity.TokenID == uuid.Nil ||
		identity.AuthorizationID == uuid.Nil || identity.InstallationID == uuid.Nil ||
		!validPluginSlug(identity.PluginID) || !validSemver(identity.PluginVersion) ||
		identity.IdentityGeneration == 0 || !validScopes(identity.Scopes) || identity.IssuedAt.IsZero() ||
		identity.ExpiresAt.IsZero() || !secondPrecision(identity.IssuedAt) || !secondPrecision(identity.ExpiresAt) ||
		!identity.ExpiresAt.After(identity.IssuedAt) {
		return false
	}
	ttl := identity.ExpiresAt.Sub(identity.IssuedAt)
	return ttl >= time.Minute && ttl <= 15*time.Minute
}

func validRuntimeAuthorization(decision runtimeAuthorization) bool {
	if decision.Schema != runtimeAuthorizationSchema || !validRequestID(decision.RequestID) ||
		decision.CustomerID == uuid.Nil || decision.InstallationID == uuid.Nil || decision.AuthorizationID == uuid.Nil ||
		decision.TokenID == uuid.Nil || !validRuntimeAction(decision.CapabilityKind, decision.CapabilityCode, decision.Action) ||
		decision.IdentityGeneration == 0 || !validPluginSlug(decision.PluginID) ||
		!validSemver(decision.PluginVersion) || !hexDigestPattern.MatchString(decision.ManifestSHA256) ||
		decision.VerificationID == uuid.Nil || decision.AttestationID == uuid.Nil || decision.AttestationRevision == 0 ||
		!validCapability(decision.CapabilityKind, decision.CapabilityCode) ||
		(decision.Decision != "allow" && decision.Decision != "deny") || decision.StableReasonCode == "" ||
		decision.Algorithm != "Ed25519" || entitlement.ValidateKeyID(decision.KeyID) != nil ||
		decision.EvaluatedAt.IsZero() || !secondPrecision(decision.EvaluatedAt) || !secondPrecision(decision.ExpiresAt) ||
		!decision.ExpiresAt.After(decision.EvaluatedAt) {
		return false
	}
	if decision.Decision == "allow" {
		return decision.ApprovalReceiptID != uuid.Nil && decision.ApprovalRevision > 0 &&
			decision.StableReasonCode == "authorized" && !decision.ExpiresAt.After(decision.EvaluatedAt.Add(time.Minute))
	}
	return decision.StableReasonCode != "authorized" &&
		!decision.ExpiresAt.After(decision.EvaluatedAt.Add(15*time.Second))
}

func validExpectedAction(expected ExpectedAction) bool {
	return expected.InstallationID != uuid.Nil && validRequestID(expected.RequestID) &&
		validCapability(expected.CapabilityKind, expected.CapabilityCode) &&
		validRuntimeAction(expected.CapabilityKind, expected.CapabilityCode, expected.Action)
}

func validRuntimeAction(kind, code, action string) bool {
	if !permissionPattern.MatchString(action) {
		return false
	}
	switch kind {
	case "scope":
		return action == code
	case "event":
		return action == "plugin.event.consume"
	case "webhook":
		return action == "plugin.webhook.deliver"
	default:
		return false
	}
}

func validRequestID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validPluginSlug(value string) bool {
	return len(value) >= 3 && len(value) <= 128 && pluginSlugPattern.MatchString(value)
}

func validSemver(value string) bool {
	if len(value) < 5 || len(value) > 128 || !semverPattern.MatchString(value) {
		return false
	}
	withoutBuild := strings.SplitN(value, "+", 2)[0]
	parts := strings.SplitN(withoutBuild, "-", 2)
	if len(parts) != 2 {
		return true
	}
	for _, identifier := range strings.Split(parts[1], ".") {
		if len(identifier) > 1 && identifier[0] == '0' {
			numeric := true
			for index := range len(identifier) {
				if identifier[index] < '0' || identifier[index] > '9' {
					numeric = false
					break
				}
			}
			if numeric {
				return false
			}
		}
	}
	return true
}

func validScopes(scopes []string) bool {
	if len(scopes) > 64 {
		return false
	}
	for index, scope := range scopes {
		if len(scope) > 128 || !permissionPattern.MatchString(scope) ||
			(index > 0 && scopes[index-1] >= scope) {
			return false
		}
	}
	return true
}

func validCapability(kind, code string) bool {
	switch kind {
	case "scope", "webhook":
		return permissionPattern.MatchString(code)
	case "event":
		return subscriptionPattern.MatchString(code)
	default:
		return false
	}
}

func secondPrecision(value time.Time) bool {
	return value.Equal(value.UTC().Truncate(time.Second))
}

func decodeSignature(value string) ([]byte, bool) {
	signature, err := base64.RawURLEncoding.DecodeString(value)
	return signature, err == nil && len(signature) == ed25519.SignatureSize &&
		base64.RawURLEncoding.EncodeToString(signature) == value
}

func lengthPrefixed(domain string, payload []byte) []byte {
	result := make([]byte, 0, len(domain)+len(payload)+8)
	for _, field := range [][]byte{[]byte(domain), payload} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		result = append(result, size[:]...)
		result = append(result, field...)
	}
	return result
}

func verifyDetached(trust DetachedVerifier, keyID string, payload, signature []byte,
	signedAt, now time.Time) error {
	if err := trust.VerifyDetached(keyID, payload, signature, signedAt, now); err != nil {
		if errors.Is(err, entitlement.ErrUnknownKey) || errors.Is(err, entitlementguard.ErrTrustUnavailable) {
			return ErrTrustUnavailable
		}
		return ErrInvalid
	}
	return nil
}
