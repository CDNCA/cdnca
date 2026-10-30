package platformpolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

const (
	PolicySchema            = "platform-policy/v1"
	SignatureDomain         = "cdnca-platform-policy-signature/v1"
	ResolveRequestSchema    = "platform-policy.resolve-request/v1"
	ResolveResponseSchema   = "platform-policy.resolve-response/v1"
	AckRequestSchema        = "platform-policy.ack-request/v1"
	AckResponseSchema       = "platform-policy.ack-response/v1"
	ResolveProofDomain      = "cdnca-platform-policy-resolve-proof/v1"
	AckProofDomain          = "cdnca-platform-policy-ack-proof/v1"
	ScopeGlobal             = "global"
	ScopeInstallation       = "installation"
	ActionApply             = "apply"
	ActionWithdraw          = "withdraw"
	AckFetched              = "fetched"
	AckValidated            = "validated"
	AckApplied              = "applied"
	AckRejected             = "rejected"
	AckRolledBack           = "rolled_back"
	maxSignedPolicyBytes    = 128 * 1024
	maxCanonicalPolicyBytes = 64 * 1024
	maxSafeRevision         = int64(9007199254740991)
	maxUnixTimestamp        = int64(253402300799)
	maxSigningClockSkew     = 5 * time.Minute
	maxWAFRuleLibraries     = 64
	maxWAFRulesPerLibrary   = 100
)

var (
	ErrInvalidEnvelope       = errors.New("invalid platform policy envelope")
	ErrPolicyDigestMismatch  = errors.New("platform policy digest mismatch")
	ErrUnknownSigningKey     = errors.New("platform policy signing key is unknown")
	ErrInvalidSignature      = errors.New("invalid platform policy signature")
	ErrUnknownSchema         = errors.New("unknown platform policy schema")
	ErrTargetMismatch        = errors.New("platform policy target mismatch")
	ErrNotYetValid           = errors.New("platform policy is not yet valid")
	ErrExpired               = errors.New("platform policy is expired")
	ErrRevisionOutOfOrder    = errors.New("platform policy revision is out of order")
	ErrSupersedesMismatch    = errors.New("platform policy supersedes mismatch")
	ErrControlVersionTooOld  = errors.New("control version is below platform policy minimum")
	ErrControlVersionBlocked = errors.New("control version is blocked by platform policy")
	ErrProtocolIncompatible  = errors.New("control protocol is incompatible with platform policy")
	ErrLocalValidation       = errors.New("platform policy failed local validation")
	ErrSignerRevoked         = errors.New("platform policy signing key is revoked")
)

var (
	codePattern           = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
	keyIDPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	ccSystemRuleIDPattern = regexp.MustCompile(`^[0-9]{1,32}$`)
	headerPattern         = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]{1,128}$`)
)

type PluginMarket struct {
	Enabled           bool     `json:"enabled"`
	TrustedCatalogIDs []string `json:"trusted_catalog_ids"`
}

type Policy struct {
	Schema                 string           `json:"schema"`
	MinimumControlVersion  string           `json:"minimum_control_version"`
	BlockedControlVersions []string         `json:"blocked_control_versions"`
	AllowedReleaseChannels []string         `json:"allowed_release_channels"`
	PluginMarket           PluginMarket     `json:"plugin_market"`
	CCProtection           *CCProtection    `json:"cc_protection,omitempty"`
	CCSystemRules          []CCSystemRule   `json:"cc_system_rules,omitempty"`
	WAFRuleLibraries       []WAFRuleLibrary `json:"waf_rule_libraries"`
}

type CCProtection struct {
	CCEnable           bool         `json:"cc_enable"`
	BlockTime          int          `json:"block_time"`
	WhiteTime          int          `json:"white_time"`
	TmpWhiteTotalLimit int          `json:"tmp_white_total_limit"`
	TmpWhitePerLimit   int          `json:"tmp_white_per_limit"`
	DefaultPageRule    string       `json:"default_page_rule"`
	AutoSwitch         CCAutoSwitch `json:"auto_switch"`
	Templates          CCTemplates  `json:"templates"`
}

type CCAutoSwitch struct {
	Enable   bool   `json:"enable"`
	QPS50x   int    `json:"qps_50x"`
	QPSTotal int    `json:"qps_total"`
	Rule     string `json:"rule"`
	Seconds  int    `json:"seconds"`
}

type CCTemplates struct {
	SliderHTML     string `json:"slider_html"`
	CaptchaHTML    string `json:"captcha_html"`
	ClickHTML      string `json:"click_html"`
	DelayJumpHTML  string `json:"delay_jump_html"`
	RotateHTML     string `json:"rotate_html"`
	EasyClickHTML  string `json:"easy_click_html"`
	EasySliderHTML string `json:"easy_slider_html"`
}

type CCSystemRule struct {
	ID      string           `json:"id"`
	Key     string           `json:"key"`
	Name    string           `json:"name"`
	Sort    int              `json:"sort"`
	Matcher *CCSystemMatcher `json:"matcher,omitempty"`
	Filter  *CCSystemFilter  `json:"filter,omitempty"`
}

type CCSystemMatcher struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Key      string   `json:"key,omitempty"`
	Values   []string `json:"values"`
}

type WAFRuleLibrary struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Revision    int64     `json:"revision"`
	Enabled     bool      `json:"enabled"`
	Rules       []WAFRule `json:"rules"`
}

type WAFRule struct {
	ID         uuid.UUID          `json:"id"`
	Name       string             `json:"name"`
	Priority   int                `json:"priority"`
	Enabled    bool               `json:"enabled"`
	Conditions []WAFRuleCondition `json:"conditions"`
	Action     string             `json:"action"`
	Flow       string             `json:"flow"`
}

type WAFRuleCondition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Key      string   `json:"key,omitempty"`
	Values   []string `json:"values"`
}

type CCSystemFilter struct {
	Type       string         `json:"type"`
	Parameters map[string]any `json:"parameters"`
}
type Envelope struct {
	Domain                string  `json:"domain"`
	TargetRevisionID      string  `json:"target_revision_id"`
	Action                string  `json:"action"`
	Schema                string  `json:"schema"`
	ScopeKind             string  `json:"scope_kind"`
	InstallationID        *string `json:"installation_id"`
	ScopeRevision         int64   `json:"scope_revision"`
	SignedAt              int64   `json:"signed_at"`
	ValidFrom             int64   `json:"valid_from"`
	ExpiresAt             int64   `json:"expires_at"`
	ControlProtocolMin    int     `json:"control_protocol_min"`
	ControlProtocolMax    int     `json:"control_protocol_max"`
	CanonicalPolicySHA256 string  `json:"canonical_policy_sha256"`
	Supersedes            *string `json:"supersedes"`
	RollbackOf            *string `json:"rollback_of"`
	KeyID                 string  `json:"key_id"`
}

type SignedPlatformPolicy struct {
	Envelope  Envelope `json:"envelope"`
	Policy    *Policy  `json:"policy"`
	Signature string   `json:"signature"`
}

type ScopeHead struct {
	TargetRevisionID      string
	ScopeRevision         int64
	CanonicalPolicySHA256 string
	Signature             string
}

type VerifyOptions struct {
	Now                 time.Time
	InstallationID      uuid.UUID
	ControlVersion      string
	ProtocolVersion     int
	Head                *ScopeHead
	DeliveredByResolve  bool
	AllowExpiredApplied bool
}

type DetachedVerifier interface {
	VerifyDetached(keyID string, payload, signature []byte, signedAt, now time.Time) error
}

type VerifiedPolicy struct {
	Signed            SignedPlatformPolicy
	CanonicalPolicy   []byte
	CanonicalEnvelope []byte
	Digest            [sha256.Size]byte
	Signature         []byte
	Duplicate         bool
}

func Decode(encoded []byte) (SignedPlatformPolicy, error) {
	if len(encoded) == 0 || len(encoded) > maxSignedPolicyBytes || !json.Valid(encoded) || rejectDuplicateKeys(encoded) != nil {
		return SignedPlatformPolicy{}, ErrInvalidEnvelope
	}
	var signed SignedPlatformPolicy
	if err := decodeStrict(encoded, &signed); err != nil || validateSignedShape(signed) != nil {
		return SignedPlatformPolicy{}, ErrInvalidEnvelope
	}
	return signed, nil
}

func Verify(signed SignedPlatformPolicy, trust DetachedVerifier, options VerifyOptions) (VerifiedPolicy, error) {
	if trust == nil || options.Now.IsZero() || options.InstallationID == uuid.Nil || options.ProtocolVersion < 1 ||
		!validSemver(options.ControlVersion) {
		return VerifiedPolicy{}, ErrInvalidEnvelope
	}
	if err := validateSignedShape(signed); err != nil {
		return VerifiedPolicy{}, err
	}
	policyBytes, err := CanonicalPolicy(signed.Policy)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	digest := sha256.Sum256(policyBytes)
	if signed.Envelope.CanonicalPolicySHA256 != base64.RawURLEncoding.EncodeToString(digest[:]) {
		return VerifiedPolicy{}, ErrPolicyDigestMismatch
	}
	envelopeBytes, err := CanonicalEnvelope(signed.Envelope)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(signed.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedPolicy{}, ErrInvalidEnvelope
	}
	signedAt := time.Unix(signed.Envelope.SignedAt, 0).UTC()
	if signedAt.After(options.Now.UTC().Add(maxSigningClockSkew)) {
		return VerifiedPolicy{}, ErrInvalidEnvelope
	}
	verifyThrough := time.Unix(signed.Envelope.ExpiresAt, 0).UTC().Add(-time.Nanosecond)
	if err := verifyDetached(trust, signed.Envelope.KeyID, envelopeBytes, signature, signedAt, verifyThrough); err != nil {
		return VerifiedPolicy{}, err
	}
	if signed.Envelope.ScopeKind == ScopeInstallation &&
		(signed.Envelope.InstallationID == nil || *signed.Envelope.InstallationID != options.InstallationID.String()) {
		return VerifiedPolicy{}, ErrTargetMismatch
	}
	now := options.Now.UTC().Unix()
	if now < signed.Envelope.ValidFrom {
		return VerifiedPolicy{}, ErrNotYetValid
	}
	if now >= signed.Envelope.ExpiresAt && !options.AllowExpiredApplied {
		return VerifiedPolicy{}, ErrExpired
	}
	if options.ProtocolVersion < signed.Envelope.ControlProtocolMin || options.ProtocolVersion > signed.Envelope.ControlProtocolMax {
		return VerifiedPolicy{}, ErrProtocolIncompatible
	}
	if signed.Policy != nil {
		if semver.Compare("v"+options.ControlVersion, "v"+signed.Policy.MinimumControlVersion) < 0 {
			return VerifiedPolicy{}, ErrControlVersionTooOld
		}
		for _, blocked := range signed.Policy.BlockedControlVersions {
			if blocked == options.ControlVersion {
				return VerifiedPolicy{}, ErrControlVersionBlocked
			}
		}
	}
	duplicate, err := verifyRevision(signed, options.Head, options.DeliveredByResolve)
	if err != nil {
		return VerifiedPolicy{}, err
	}
	return VerifiedPolicy{Signed: cloneSigned(signed), CanonicalPolicy: policyBytes,
		CanonicalEnvelope: envelopeBytes, Digest: digest, Signature: append([]byte(nil), signature...), Duplicate: duplicate}, nil
}

func CanonicalPolicy(policy *Policy) ([]byte, error) {
	if policy == nil {
		return []byte("null"), nil
	}
	if err := validatePolicy(*policy); err != nil {
		return nil, err
	}
	// Fields are declared in RFC 8785 lexicographic key order. All v1 strings
	// are constrained to ASCII, so encoding/json produces the exact JCS bytes.
	canonical := struct {
		AllowedReleaseChannels []string      `json:"allowed_release_channels"`
		BlockedControlVersions []string      `json:"blocked_control_versions"`
		CCProtection           *CCProtection `json:"cc_protection,omitempty"`
		MinimumControlVersion  string        `json:"minimum_control_version"`
		PluginMarket           struct {
			Enabled           bool     `json:"enabled"`
			TrustedCatalogIDs []string `json:"trusted_catalog_ids"`
		} `json:"plugin_market"`
		Schema           string                    `json:"schema"`
		WAFRuleLibraries []canonicalWAFRuleLibrary `json:"waf_rule_libraries,omitempty"`
		CCSystemRules    *[]CCSystemRule           `json:"cc_system_rules,omitempty"`
	}{
		AllowedReleaseChannels: policy.AllowedReleaseChannels,
		BlockedControlVersions: policy.BlockedControlVersions,
		CCProtection:           policy.CCProtection,
		MinimumControlVersion:  policy.MinimumControlVersion,
		Schema:                 policy.Schema,
		WAFRuleLibraries:       canonicalWAFRuleLibraries(policy.WAFRuleLibraries),
	}
	canonical.PluginMarket.Enabled = policy.PluginMarket.Enabled
	canonical.PluginMarket.TrustedCatalogIDs = policy.PluginMarket.TrustedCatalogIDs
	if policy.CCSystemRules != nil {
		canonical.CCSystemRules = &policy.CCSystemRules
	}
	encoded, err := json.Marshal(canonical)
	if err != nil || len(encoded) > maxCanonicalPolicyBytes {
		return nil, ErrInvalidEnvelope
	}
	return encoded, nil
}

func CanonicalEnvelope(envelope Envelope) ([]byte, error) {
	if err := validateEnvelope(envelope); err != nil {
		return nil, err
	}
	canonical := struct {
		Action                string  `json:"action"`
		CanonicalPolicySHA256 string  `json:"canonical_policy_sha256"`
		ControlProtocolMax    int     `json:"control_protocol_max"`
		ControlProtocolMin    int     `json:"control_protocol_min"`
		Domain                string  `json:"domain"`
		ExpiresAt             int64   `json:"expires_at"`
		InstallationID        *string `json:"installation_id"`
		KeyID                 string  `json:"key_id"`
		RollbackOf            *string `json:"rollback_of"`
		Schema                string  `json:"schema"`
		ScopeKind             string  `json:"scope_kind"`
		ScopeRevision         int64   `json:"scope_revision"`
		SignedAt              int64   `json:"signed_at"`
		Supersedes            *string `json:"supersedes"`
		TargetRevisionID      string  `json:"target_revision_id"`
		ValidFrom             int64   `json:"valid_from"`
	}{
		Action: envelope.Action, CanonicalPolicySHA256: envelope.CanonicalPolicySHA256,
		ControlProtocolMax: envelope.ControlProtocolMax, ControlProtocolMin: envelope.ControlProtocolMin,
		Domain: envelope.Domain, ExpiresAt: envelope.ExpiresAt, InstallationID: cloneString(envelope.InstallationID),
		KeyID: envelope.KeyID, RollbackOf: cloneString(envelope.RollbackOf), Schema: envelope.Schema,
		ScopeKind: envelope.ScopeKind, ScopeRevision: envelope.ScopeRevision,
		SignedAt:   envelope.SignedAt,
		Supersedes: cloneString(envelope.Supersedes), TargetRevisionID: envelope.TargetRevisionID,
		ValidFrom: envelope.ValidFrom,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil || len(encoded) > maxCanonicalPolicyBytes {
		return nil, ErrInvalidEnvelope
	}
	return encoded, nil
}

func RejectionCode(err error) string {
	switch {
	case errors.Is(err, ErrPolicyDigestMismatch):
		return "policy_digest_mismatch"
	case errors.Is(err, ErrUnknownSigningKey), errors.Is(err, ErrSignerRevoked):
		// license-service accepts a fixed acknowledgement vocabulary; a revoked
		// signer is reported as an untrusted key. Local logs keep the precise reason.
		return "unknown_signing_key"
	case errors.Is(err, ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, ErrUnknownSchema):
		return "unknown_schema"
	case errors.Is(err, ErrTargetMismatch):
		return "target_mismatch"
	case errors.Is(err, ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrRevisionOutOfOrder):
		return "revision_out_of_order"
	case errors.Is(err, ErrSupersedesMismatch):
		return "supersedes_mismatch"
	case errors.Is(err, ErrControlVersionTooOld):
		return "control_version_too_old"
	case errors.Is(err, ErrControlVersionBlocked):
		return "control_version_blocked"
	case errors.Is(err, ErrProtocolIncompatible):
		return "protocol_incompatible"
	case errors.Is(err, ErrLocalValidation):
		return "local_validation_failed"
	default:
		return "invalid_envelope"
	}
}

func ValidControlVersion(value string) bool { return validSemver(value) }

func validateSignedShape(signed SignedPlatformPolicy) error {
	if err := validateEnvelope(signed.Envelope); err != nil {
		return err
	}
	if _, err := base64.RawURLEncoding.DecodeString(signed.Signature); err != nil || len(signed.Signature) != 86 {
		return ErrInvalidEnvelope
	}
	if signed.Envelope.Action == ActionApply {
		if signed.Policy == nil {
			return ErrInvalidEnvelope
		}
		return validatePolicy(*signed.Policy)
	}
	if signed.Policy != nil || signed.Envelope.RollbackOf != nil {
		return ErrInvalidEnvelope
	}
	return nil
}

func validateEnvelope(envelope Envelope) error {
	if envelope.Domain != SignatureDomain || envelope.Schema != PolicySchema {
		if envelope.Schema != PolicySchema {
			return ErrUnknownSchema
		}
		return ErrInvalidEnvelope
	}
	if !validUUID(envelope.TargetRevisionID) || !keyIDPattern.MatchString(envelope.KeyID) ||
		(envelope.Action != ActionApply && envelope.Action != ActionWithdraw) ||
		envelope.ScopeRevision < 1 || envelope.ScopeRevision > maxSafeRevision ||
		envelope.SignedAt < 1 || envelope.SignedAt > maxUnixTimestamp ||
		envelope.ValidFrom < 1 || envelope.ValidFrom > maxUnixTimestamp ||
		envelope.ExpiresAt <= envelope.ValidFrom || envelope.ExpiresAt <= envelope.SignedAt ||
		envelope.ExpiresAt > maxUnixTimestamp ||
		envelope.ControlProtocolMin < 1 || envelope.ControlProtocolMax < envelope.ControlProtocolMin {
		return ErrInvalidEnvelope
	}
	digest, err := base64.RawURLEncoding.DecodeString(envelope.CanonicalPolicySHA256)
	if err != nil || len(digest) != sha256.Size || len(envelope.CanonicalPolicySHA256) != 43 {
		return ErrInvalidEnvelope
	}
	if envelope.ScopeKind == ScopeGlobal {
		if envelope.InstallationID != nil {
			return ErrInvalidEnvelope
		}
	} else if envelope.ScopeKind == ScopeInstallation {
		if envelope.InstallationID == nil || !validUUID(*envelope.InstallationID) {
			return ErrInvalidEnvelope
		}
	} else {
		return ErrInvalidEnvelope
	}
	if envelope.ScopeRevision == 1 {
		if envelope.Supersedes != nil {
			return ErrInvalidEnvelope
		}
	} else if envelope.Supersedes == nil || !validUUID(*envelope.Supersedes) {
		return ErrInvalidEnvelope
	}
	if envelope.RollbackOf != nil && (!validUUID(*envelope.RollbackOf) || envelope.Action != ActionApply) {
		return ErrInvalidEnvelope
	}
	return nil
}

func verifyDetached(trust DetachedVerifier, keyID string, payload, signature []byte, signedAt, now time.Time) error {
	if err := trust.VerifyDetached(keyID, payload, signature, signedAt, now); err != nil {
		switch {
		case errors.Is(err, entitlement.ErrUnknownKey):
			return ErrUnknownSigningKey
		case errors.Is(err, entitlement.ErrInvalidSignature):
			return ErrInvalidSignature
		case errors.Is(err, entitlementguard.ErrKeyOutsideWindow):
			return ErrInvalidEnvelope
		default:
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func validatePolicy(policy Policy) error {
	if policy.Schema != PolicySchema {
		return ErrUnknownSchema
	}
	if !validSemver(policy.MinimumControlVersion) || len(policy.BlockedControlVersions) > 256 ||
		len(policy.AllowedReleaseChannels) > 32 || len(policy.PluginMarket.TrustedCatalogIDs) > 256 ||
		(!policy.PluginMarket.Enabled && len(policy.PluginMarket.TrustedCatalogIDs) != 0) ||
		!validCCProtection(policy.CCProtection) {
		return ErrInvalidEnvelope
	}
	if !strictSorted(policy.BlockedControlVersions, validSemver) ||
		!strictSorted(policy.AllowedReleaseChannels, func(value string) bool { return codePattern.MatchString(value) }) ||
		!strictSorted(policy.PluginMarket.TrustedCatalogIDs, func(value string) bool { return codePattern.MatchString(value) }) ||
		!validWAFRuleLibraries(policy.WAFRuleLibraries) {
		return ErrInvalidEnvelope
	}
	if policy.CCSystemRules != nil {
		if len(policy.CCSystemRules) > 32 {
			return ErrInvalidEnvelope
		}
		for index, rule := range policy.CCSystemRules {
			if !ccSystemRuleIDPattern.MatchString(rule.ID) || !codePattern.MatchString(rule.Key) || len(rule.Name) < 1 || len(rule.Name) > 128 || rule.Sort < 1 || rule.Sort > 10000 ||
				(index > 0 && policy.CCSystemRules[index-1].Key >= rule.Key) ||
				((rule.Matcher == nil) == (rule.Filter == nil)) {
				return ErrInvalidEnvelope
			}
			if rule.Matcher != nil {
				if len(rule.Matcher.Field) < 1 || len(rule.Matcher.Field) > 128 || len(rule.Matcher.Operator) < 1 || len(rule.Matcher.Operator) > 128 ||
					len(rule.Matcher.Key) > 128 || len(rule.Matcher.Values) > 100 {
					return ErrInvalidEnvelope
				}
				for _, value := range rule.Matcher.Values {
					if len(value) > 4096 {
						return ErrInvalidEnvelope
					}
				}
			}
			if rule.Filter != nil {
				if !ccSystemFilterTypes[rule.Filter.Type] || rule.Filter.Parameters == nil {
					return ErrInvalidEnvelope
				}
			}
		}
	}
	return nil
}

func validCCProtection(value *CCProtection) bool {
	if value == nil {
		return true
	}
	return value.BlockTime >= 0 && value.WhiteTime >= 600 &&
		value.TmpWhiteTotalLimit >= 0 && value.TmpWhitePerLimit >= 0 &&
		len(value.DefaultPageRule) <= 128 && value.AutoSwitch.QPS50x >= 0 &&
		value.AutoSwitch.QPSTotal >= 0 && value.AutoSwitch.Seconds >= 0 &&
		len(value.AutoSwitch.Rule) <= 128 && len(value.Templates.SliderHTML) <= 8192 &&
		len(value.Templates.CaptchaHTML) <= 8192 && len(value.Templates.ClickHTML) <= 8192 &&
		len(value.Templates.DelayJumpHTML) <= 8192 && len(value.Templates.RotateHTML) <= 8192 &&
		len(value.Templates.EasyClickHTML) <= 8192 && len(value.Templates.EasySliderHTML) <= 8192
}

var ccSystemFilterTypes = map[string]bool{
	"off": true, "relaxed": true, "js": true, "five_second": true, "click": true, "slider": true, "captcha": true,
	"rotate_image": true, "simple_click": true, "simple_slider": true,
}

type canonicalWAFRuleLibrary struct {
	Description string             `json:"description"`
	Enabled     bool               `json:"enabled"`
	ID          uuid.UUID          `json:"id"`
	Name        string             `json:"name"`
	Revision    int64              `json:"revision"`
	Rules       []canonicalWAFRule `json:"rules"`
}

type canonicalWAFRule struct {
	Action     string                      `json:"action"`
	Conditions []canonicalWAFRuleCondition `json:"conditions"`
	Enabled    bool                        `json:"enabled"`
	Flow       string                      `json:"flow"`
	ID         uuid.UUID                   `json:"id"`
	Name       string                      `json:"name"`
	Priority   int                         `json:"priority"`
}

type canonicalWAFRuleCondition struct {
	Field    string   `json:"field"`
	Key      string   `json:"key,omitempty"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

func canonicalWAFRuleLibraries(libraries []WAFRuleLibrary) []canonicalWAFRuleLibrary {
	if len(libraries) == 0 {
		return nil
	}
	result := make([]canonicalWAFRuleLibrary, len(libraries))
	for libraryIndex, library := range libraries {
		rules := make([]canonicalWAFRule, len(library.Rules))
		for ruleIndex, rule := range library.Rules {
			conditions := make([]canonicalWAFRuleCondition, len(rule.Conditions))
			for conditionIndex, condition := range rule.Conditions {
				conditions[conditionIndex] = canonicalWAFRuleCondition{
					Field: condition.Field, Key: condition.Key, Operator: condition.Operator,
					Values: cloneStrings(condition.Values),
				}
			}
			rules[ruleIndex] = canonicalWAFRule{Action: rule.Action, Conditions: conditions,
				Enabled: rule.Enabled, Flow: rule.Flow, ID: rule.ID, Name: rule.Name, Priority: rule.Priority}
		}
		result[libraryIndex] = canonicalWAFRuleLibrary{Description: library.Description, Enabled: library.Enabled,
			ID: library.ID, Name: library.Name, Revision: library.Revision, Rules: rules}
	}
	return result
}

func validWAFRuleLibraries(libraries []WAFRuleLibrary) bool {
	if len(libraries) > maxWAFRuleLibraries {
		return false
	}
	seenIDs := make(map[uuid.UUID]struct{}, len(libraries))
	seenNames := make(map[string]struct{}, len(libraries))
	for index, library := range libraries {
		if library.ID == uuid.Nil || library.Revision < 1 || library.Revision > maxSafeRevision ||
			!validPolicyText(library.Name, 1, 128) || !validPolicyText(library.Description, 0, 1000) ||
			len(library.Rules) < 1 || len(library.Rules) > maxWAFRulesPerLibrary ||
			index > 0 && bytes.Compare(libraries[index-1].ID[:], library.ID[:]) >= 0 {
			return false
		}
		if _, exists := seenIDs[library.ID]; exists {
			return false
		}
		if _, exists := seenNames[library.Name]; exists {
			return false
		}
		seenIDs[library.ID], seenNames[library.Name] = struct{}{}, struct{}{}
		if !validWAFRules(library.Rules) {
			return false
		}
	}
	return true
}

func validWAFRules(rules []WAFRule) bool {
	seenIDs := make(map[uuid.UUID]struct{}, len(rules))
	seenNames := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		if rule.ID == uuid.Nil || !validPolicyText(rule.Name, 1, 128) || rule.Priority < 1 || rule.Priority > 1_000_000 ||
			len(rule.Conditions) < 1 || len(rule.Conditions) > 4 ||
			(rule.Action != "allow" && rule.Action != "block" && rule.Action != "log") ||
			(rule.Flow != "continue" && rule.Flow != "stop") ||
			index > 0 && (rules[index-1].Priority > rule.Priority ||
				rules[index-1].Priority == rule.Priority && bytes.Compare(rules[index-1].ID[:], rule.ID[:]) >= 0) {
			return false
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return false
		}
		if _, exists := seenNames[rule.Name]; exists {
			return false
		}
		seenIDs[rule.ID], seenNames[rule.Name] = struct{}{}, struct{}{}
		if !validWAFRuleConditions(rule.Conditions) {
			return false
		}
	}
	return true
}

func validWAFRuleConditions(conditions []WAFRuleCondition) bool {
	seenFields := make(map[string]struct{}, len(conditions))
	for index, condition := range conditions {
		if index > 0 && conditions[index-1].Field >= condition.Field || !validWAFRuleCondition(condition) {
			return false
		}
		if _, exists := seenFields[condition.Field]; exists {
			return false
		}
		seenFields[condition.Field] = struct{}{}
	}
	return true
}

func validWAFRuleCondition(condition WAFRuleCondition) bool {
	operators := map[string][]string{
		"client_ip": {"ip_in_cidr"},
		"header":    {"equals"},
		"method":    {"equals"},
		"path":      {"equals", "prefix"},
		"port":      {"number_eq"},
	}
	allowed, exists := operators[condition.Field]
	if !exists || !slices.Contains(allowed, condition.Operator) || len(condition.Values) < 1 || len(condition.Values) > 64 ||
		(condition.Field == "header") != headerPattern.MatchString(condition.Key) ||
		condition.Field == "header" && strings.ToLower(condition.Key) != condition.Key ||
		condition.Field != "header" && condition.Key != "" || condition.Operator == "number_eq" && len(condition.Values) != 1 {
		return false
	}
	for index, value := range condition.Values {
		if !validWAFRuleConditionValue(condition.Field, condition.Operator, value) ||
			index > 0 && condition.Values[index-1] >= value {
			return false
		}
	}
	return true
}

func validWAFRuleConditionValue(field, operator, value string) bool {
	if !validPolicyText(value, 1, 256) {
		return false
	}
	switch field {
	case "client_ip":
		prefix, err := netip.ParsePrefix(value)
		return err == nil && prefix == prefix.Masked() && prefix.String() == value && operator == "ip_in_cidr"
	case "method":
		return len(value) <= 16 && strings.IndexFunc(value, func(char rune) bool { return char < 'A' || char > 'Z' }) < 0
	case "port":
		port, err := strconv.ParseUint(value, 10, 16)
		return err == nil && port > 0 && strconv.FormatUint(port, 10) == value
	default:
		return true
	}
}

func validPolicyText(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		utf8.RuneCountInString(value) >= minimum && utf8.RuneCountInString(value) <= maximum
}
func verifyRevision(signed SignedPlatformPolicy, head *ScopeHead, delivered bool) (bool, error) {
	if head == nil {
		if signed.Envelope.ScopeRevision > 1 && !delivered {
			return false, ErrRevisionOutOfOrder
		}
		return false, nil
	}
	if signed.Envelope.ScopeRevision < head.ScopeRevision {
		return false, ErrRevisionOutOfOrder
	}
	if signed.Envelope.ScopeRevision == head.ScopeRevision {
		if signed.Envelope.TargetRevisionID == head.TargetRevisionID &&
			signed.Envelope.CanonicalPolicySHA256 == head.CanonicalPolicySHA256 && signed.Signature == head.Signature {
			return true, nil
		}
		return false, ErrRevisionOutOfOrder
	}
	if !delivered {
		return false, ErrRevisionOutOfOrder
	}
	if signed.Envelope.ScopeRevision == head.ScopeRevision+1 &&
		(signed.Envelope.Supersedes == nil || *signed.Envelope.Supersedes != head.TargetRevisionID) {
		return false, ErrSupersedesMismatch
	}
	return false, nil
}

func strictSorted(values []string, valid func(string) bool) bool {
	return sort.SliceIsSorted(values, func(i, j int) bool { return values[i] < values[j] }) &&
		func() bool {
			for index, value := range values {
				if !valid(value) || (index > 0 && values[index-1] >= value) {
					return false
				}
			}
			return true
		}()
}

func validSemver(value string) bool {
	if value == "" || strings.HasPrefix(value, "v") || strings.Contains(value, "+") {
		return false
	}
	withPrefix := "v" + value
	return semver.IsValid(withPrefix) && strings.TrimPrefix(semver.Canonical(withPrefix), "v") == value
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func decodeStrict(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidEnvelope
	}
	return nil
}

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidEnvelope
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidEnvelope
			}
			if _, exists := seen[key]; exists {
				return ErrInvalidEnvelope
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidEnvelope
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim(map[json.Delim]json.Delim{'{': '}', '[': ']'}[delimiter]) {
		return fmt.Errorf("invalid JSON delimiter")
	}
	return nil
}

func cloneSigned(signed SignedPlatformPolicy) SignedPlatformPolicy {
	result := signed
	result.Envelope.InstallationID = cloneString(signed.Envelope.InstallationID)
	result.Envelope.Supersedes = cloneString(signed.Envelope.Supersedes)
	result.Envelope.RollbackOf = cloneString(signed.Envelope.RollbackOf)
	if signed.Policy != nil {
		policy := *signed.Policy
		policy.BlockedControlVersions = cloneStrings(signed.Policy.BlockedControlVersions)
		policy.AllowedReleaseChannels = cloneStrings(signed.Policy.AllowedReleaseChannels)
		policy.PluginMarket.TrustedCatalogIDs = cloneStrings(signed.Policy.PluginMarket.TrustedCatalogIDs)
		if signed.Policy.CCProtection != nil {
			cc := *signed.Policy.CCProtection
			policy.CCProtection = &cc
		}
		if signed.Policy.CCSystemRules != nil {
			policy.CCSystemRules = cloneCCSystemRules(signed.Policy.CCSystemRules)
		}
		policy.WAFRuleLibraries = cloneWAFRuleLibraries(signed.Policy.WAFRuleLibraries)
		result.Policy = &policy
	}
	return result
}

func cloneCCSystemRules(value []CCSystemRule) []CCSystemRule {
	if value == nil {
		return nil
	}
	result := make([]CCSystemRule, len(value))
	for index, rule := range value {
		result[index] = rule
		if rule.Matcher != nil {
			matcher := *rule.Matcher
			matcher.Values = cloneStrings(rule.Matcher.Values)
			result[index].Matcher = &matcher
		}
		if rule.Filter != nil {
			filter := *rule.Filter
			filter.Parameters = make(map[string]any, len(rule.Filter.Parameters))
			for key, item := range rule.Filter.Parameters {
				filter.Parameters[key] = item
			}
			result[index].Filter = &filter
		}
	}
	return result
}

func cloneWAFRuleLibraries(value []WAFRuleLibrary) []WAFRuleLibrary {
	if value == nil {
		return nil
	}
	result := make([]WAFRuleLibrary, len(value))
	for libraryIndex, library := range value {
		result[libraryIndex] = library
		result[libraryIndex].Rules = make([]WAFRule, len(library.Rules))
		for ruleIndex, rule := range library.Rules {
			result[libraryIndex].Rules[ruleIndex] = rule
			result[libraryIndex].Rules[ruleIndex].Conditions = make([]WAFRuleCondition, len(rule.Conditions))
			for conditionIndex, condition := range rule.Conditions {
				result[libraryIndex].Rules[ruleIndex].Conditions[conditionIndex] = condition
				result[libraryIndex].Rules[ruleIndex].Conditions[conditionIndex].Values = cloneStrings(condition.Values)
			}
		}
	}
	return result
}

func cloneStrings(value []string) []string {
	if value == nil {
		return nil
	}
	return append([]string{}, value...)
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
