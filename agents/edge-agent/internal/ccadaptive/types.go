package ccadaptive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	SchemaVersion      = "cdnca.edge.cc-adaptive/v1"
	MaxPolicyBytes     = 1 << 20
	MaxRevision        = 1<<53 - 1
	MaxTimestampMicros = 1<<53 - 1
	MaxRatePerSecond   = 1_000_000
	MaxBurst           = 1_000_000
	MaxAdaptiveSample  = MaxTimestampMicros / 1_000_000
)

var ErrInvalidPolicy = errors.New("invalid CC adaptive policy")

type Outcome string

const (
	OutcomeAllow    Outcome = "allow"
	OutcomeDeny     Outcome = "deny"
	OutcomeFallback Outcome = "fallback"
)

type ReasonCode string

const (
	ReasonBaselineLimitApplied        ReasonCode = "baseline_limit_applied"
	ReasonGCRALimitApplied            ReasonCode = "gcra_limit_applied"
	ReasonAdaptiveShadowOnly          ReasonCode = "adaptive_shadow_only"
	ReasonAdaptiveInsufficientSamples ReasonCode = "adaptive_insufficient_samples"
	ReasonAdaptiveBaselineStale       ReasonCode = "adaptive_baseline_stale"
	ReasonAdaptiveChangeCapped        ReasonCode = "adaptive_change_capped"
	ReasonManualThresholdFrozen       ReasonCode = "manual_threshold_frozen"
	ReasonLimiterStateUnavailable     ReasonCode = "limiter_state_unavailable"
	ReasonClockRegression             ReasonCode = "clock_regression"
	ReasonArithmeticOverflow          ReasonCode = "arithmetic_overflow"
	ReasonInvalidInput                ReasonCode = "invalid_input"
)

type FactKind string

const (
	FactBaseline         FactKind = "baseline"
	FactStaticAllow      FactKind = "static_allow"
	FactStaticDeny       FactKind = "static_deny"
	FactShadowSuggestion FactKind = "shadow_suggestion"
	FactAutoClamped      FactKind = "auto_clamped"
	FactFallback         FactKind = "fallback"
)

type Key struct {
	tenantID string
	siteID   string
	ruleID   string
	scope    string
	revision uint64
	digest   string
	storage  string
}

func NewKey(tenantID, siteID, ruleID, scope string, revision uint64, rawIdentity []byte) Key {
	hashed := sha256.Sum256(rawIdentity)
	key := Key{
		tenantID: tenantID,
		siteID:   siteID,
		ruleID:   ruleID,
		scope:    scope,
		revision: revision,
		digest:   hex.EncodeToString(hashed[:]),
	}
	key.storage = encodeStorageKey(key)
	return key
}

func NewDigestKey(tenantID, siteID, ruleID, scope string, revision uint64, digest string) (Key, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return Key{}, fmt.Errorf("invalid SHA-256 key digest")
	}
	key := Key{tenantID: tenantID, siteID: siteID, ruleID: ruleID, scope: scope, revision: revision, digest: hex.EncodeToString(decoded)}
	key.storage = encodeStorageKey(key)
	return key, nil
}

func (key Key) valid() bool {
	return validIdentifier(key.tenantID) && validIdentifier(key.siteID) &&
		validIdentifier(key.ruleID) && validIdentifier(key.scope) && key.revision >= 1 &&
		key.revision <= MaxRevision && len(key.digest) == sha256.Size*2 && key.storage != ""
}

func (key Key) Digest() string { return key.digest }

func (key Key) storageKey() string { return key.storage }

func encodeStorageKey(key Key) string {
	var encoded strings.Builder
	encoded.WriteString("ccadaptive:gcra:")
	for _, field := range []string{
		strconv.FormatUint(key.revision, 10), key.tenantID, key.siteID, key.ruleID, key.scope, key.digest,
	} {
		encoded.WriteString(strconv.Itoa(len(field)))
		encoded.WriteByte(':')
		encoded.WriteString(field)
	}
	return encoded.String()
}

type Limit struct {
	RatePerSecond uint64 `json:"rate_per_second"`
	Burst         uint64 `json:"burst"`
}

func (limit Limit) valid() bool {
	return limit.RatePerSecond >= 1 && limit.RatePerSecond <= MaxRatePerSecond &&
		limit.Burst >= 1 && limit.Burst <= MaxBurst
}

type Request struct {
	Key       Key
	Limit     Limit
	Cost      uint64
	NowMicros int64
}

type DecisionFact struct {
	Kind           FactKind   `json:"kind"`
	Reason         ReasonCode `json:"reason"`
	TenantID       string     `json:"tenant_id"`
	SiteID         string     `json:"site_id"`
	RuleID         string     `json:"rule_id"`
	KeyScope       string     `json:"key_scope"`
	KeyDigest      string     `json:"key_digest"`
	PolicyRevision uint64     `json:"policy_revision"`
	Allowed        bool       `json:"allowed"`
}

func (fact DecisionFact) Contains(value string) bool {
	return strings.Contains(string(fact.Kind), value) || strings.Contains(string(fact.Reason), value) ||
		strings.Contains(fact.TenantID, value) || strings.Contains(fact.SiteID, value) ||
		strings.Contains(fact.RuleID, value) || strings.Contains(fact.KeyScope, value) ||
		strings.Contains(fact.KeyDigest, value) || strings.Contains(strconv.FormatUint(fact.PolicyRevision, 10), value)
}

type Decision struct {
	Outcome            Outcome
	Reason             ReasonCode
	RetryAfterMicros   int64
	Remaining          uint64
	NextEligibleMicros int64
	Fact               DecisionFact
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	if first := value[0]; !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') ||
		(first >= '0' && first <= '9')) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._:-", rune(character)) {
			continue
		}
		return false
	}
	return true
}
