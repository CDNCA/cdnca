package originauth

import (
	"errors"
	"net/http"
	"time"
)

const (
	SchemaVersion     = "cdnca.edge.originauth/v1"
	CredentialVersion = "cdnca.edge.originauth.credential/v1"

	ProviderS3  = "s3"
	ProviderOSS = "oss"
	ProviderCOS = "cos"

	AlgorithmS3  = "aws4-hmac-sha256"
	AlgorithmOSS = "oss4-hmac-sha256"
	AlgorithmCOS = "cos-hmac-sha1"
)

const (
	MaxPolicyBytes     = 1 << 20
	MaxRules           = 128
	MaxCredentialBytes = 16 << 10
)

var ErrRejected = errors.New("origin authentication rejected")

type Rejection struct {
	Code string
}

func (r *Rejection) Error() string { return ErrRejected.Error() + ": " + r.Code }
func (r *Rejection) Unwrap() error { return ErrRejected }

func reject(code string) error { return &Rejection{Code: code} }

type Policy struct {
	SchemaVersion string `json:"schema_version"`
	PolicyVersion uint64 `json:"policy_version"`
	Rules         []Rule `json:"rules"`
}

type Rule struct {
	RuleID                string  `json:"rule_id"`
	Provider              string  `json:"provider"`
	Algorithm             string  `json:"algorithm"`
	Endpoint              string  `json:"endpoint"`
	Bucket                string  `json:"bucket"`
	PathPrefix            string  `json:"path_prefix"`
	Region                string  `json:"region"`
	Service               string  `json:"service"`
	SignatureTTLSeconds   uint32  `json:"signature_ttl_seconds"`
	CurrentKey            KeyRef  `json:"current_key"`
	PreviousKey           *KeyRef `json:"previous_key,omitempty"`
	ActivateCurrentAtUnix int64   `json:"activate_current_at_unix"`
}

type KeyRef struct {
	KeyID      string `json:"key_id"`
	SecretFile string `json:"secret_file"`
}

type CompiledPolicy struct {
	SchemaVersion string         `json:"schema_version"`
	PolicyVersion uint64         `json:"policy_version"`
	Rules         []CompiledRule `json:"rules"`
}

type CompiledRule struct {
	RuleID                string       `json:"rule_id"`
	Provider              string       `json:"provider"`
	Algorithm             string       `json:"algorithm"`
	Endpoint              Endpoint     `json:"endpoint"`
	Bucket                string       `json:"bucket"`
	PathPrefix            string       `json:"path_prefix"`
	Region                string       `json:"region"`
	Service               string       `json:"service"`
	SignatureTTLSeconds   uint32       `json:"signature_ttl_seconds"`
	CurrentKey            CompiledKey  `json:"current_key"`
	PreviousKey           *CompiledKey `json:"previous_key,omitempty"`
	ActivateCurrentAtUnix int64        `json:"activate_current_at_unix"`
}

type Endpoint struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
}

type CompiledKey struct {
	KeyID      string `json:"key_id"`
	SecretFile string `json:"secret_file"`
	SHA256     string `json:"sha256"`
}

type Credential struct {
	SchemaVersion   string `json:"schema_version"`
	Provider        string `json:"provider"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	NotBeforeUnix   int64  `json:"not_before_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
}

type Clock func() time.Time

type Signer struct {
	rules map[string]CompiledRule
	now   Clock
}

func NewSigner(policy *CompiledPolicy, now Clock) (*Signer, error) {
	if policy == nil || policy.SchemaVersion != SchemaVersion || len(policy.Rules) == 0 || now == nil {
		return nil, reject("SIGNER_CONFIG_INVALID")
	}
	rules := make(map[string]CompiledRule, len(policy.Rules))
	for _, rule := range policy.Rules {
		if _, exists := rules[rule.RuleID]; exists {
			return nil, reject("SIGNER_CONFIG_INVALID")
		}
		rules[rule.RuleID] = rule
	}
	return &Signer{rules: rules, now: now}, nil
}

func (s *Signer) Sign(ruleID string, request *http.Request) error {
	rule, ok := s.rules[ruleID]
	if !ok {
		return reject("RULE_UNKNOWN")
	}
	return signRequest(rule, request, s.now().UTC())
}
