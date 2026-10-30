package securitypolicy

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid security policy input")
	ErrPermissionDenied    = errors.New("security policy permission denied")
	ErrNotFound            = errors.New("security policy not found")
	ErrConflict            = errors.New("security policy conflict")
	ErrRevisionConflict    = errors.New("security policy revision conflict")
	ErrIdempotencyConflict = errors.New("security policy idempotency conflict")
	// ErrInUse: the policy still runs on a site (an active binding version
	// that is enabled, or an activation in flight); deleting it would leave
	// nodes enforcing rules nobody can manage (D3).
	ErrInUse = errors.New("security policy is in use by a site")
)

const licensedWAFDescriptionPrefix = "platform-waf-library:"

const (
	KindWAF = "waf"
	KindCC  = "cc"
	KindACL = "acl"

	ActionAllow     = "allow"
	ActionBlock     = "block"
	ActionRateLimit = "rate_limit"
	ActionChallenge = "challenge"
	ActionLog       = "log"
	// ActionManagedWAF runs system catalog WAF rule sets (OWASP CRS on
	// libmodsecurity) for the whole site; at most one per WAF policy and it
	// has no conditions.
	ActionManagedWAF = "managed_waf"

	FlowContinue = "continue"
	FlowStop     = "stop"
)

type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

type OwnerReference struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
}

type Condition struct {
	Field    string   `json:"field"`
	Operator string   `json:"operator"`
	Key      string   `json:"key,omitempty"`
	Values   []string `json:"values"`
	// Filters (WAF content fields only) transform the request value before
	// the operator compares it, in order: lowercase, base64_decode,
	// unicode_decode, html_unescape, length (last; turns the value into its
	// byte length for a number_* operator). edgeconfig.WAFInspect.
	Filters []string `json:"filters,omitempty"`
	// BodyOverflow (WAF body fields only): "match" makes the condition hold
	// for a request body longer than the 64 KiB inspection limit (the rule's
	// action applies to the uninspectable body); "" inspects the first bytes.
	BodyOverflow string `json:"body_overflow,omitempty"`
}

type RateLimitConfig struct {
	WindowSeconds  int                      `json:"window_seconds,omitempty"`
	MaxRequests    int                      `json:"max_requests,omitempty"`
	MaxPerURI      int                      `json:"max_requests_per_uri,omitempty"`
	Algorithm      string                   `json:"algorithm,omitempty"`
	RatePerSecond  int                      `json:"rate_per_second,omitempty"`
	Burst          int                      `json:"burst,omitempty"`
	ResponseAction string                   `json:"response_action,omitempty"`
	BanSeconds     int                      `json:"ban_seconds,omitempty"`
	Adaptive       *AdaptiveRateLimitConfig `json:"adaptive,omitempty"`
}

type AdaptiveRateLimitConfig struct {
	Profile                string `json:"profile"`
	Enforcement            string `json:"enforcement"`
	AutoApproved           bool   `json:"auto_approved,omitempty"`
	Frozen                 bool   `json:"frozen,omitempty"`
	Fallback               string `json:"fallback,omitempty"`
	MinSamples             int    `json:"min_samples,omitempty"`
	MaxSamples             int    `json:"max_samples,omitempty"`
	SampleFreshnessSeconds int    `json:"sample_freshness_seconds,omitempty"`
	EWMAAlphaPermille      int    `json:"ewma_alpha_permille,omitempty"`
	MADMultiplierMilli     int    `json:"mad_multiplier_milli,omitempty"`
	MinRatePerSecond       int    `json:"min_rate_per_second,omitempty"`
	MaxRatePerSecond       int    `json:"max_rate_per_second,omitempty"`
	MinBurst               int    `json:"min_burst,omitempty"`
	MaxBurst               int    `json:"max_burst,omitempty"`
	MaxStepPermille        int    `json:"max_step_permille,omitempty"`
	HysteresisPermille     int    `json:"hysteresis_permille,omitempty"`
	CooldownSeconds        int    `json:"cooldown_seconds,omitempty"`
	MaxGroups              int    `json:"max_groups,omitempty"`
}

// ChallengeConfig drives the node verification page of a CC rule. Every
// value comes from the catalog filter (ExpandCCRuleGroup) or the operator;
// nothing is defaulted downstream.
//
//   - FailureWindowSeconds / MaxFailures: more than MaxFailures unpassed pages
//     or failed proofs within the window -> ban BanSeconds (LogOnly: record).
//   - PassSeconds: pass cookie lifetime; PowBits: SHA-256 proof-of-work
//     difficulty (leading zero bits, 0 only for redirect); DelaySeconds:
//     minimum wait (five_second only); ChallengeSeconds: page lifetime.
//   - BindIPv4Prefix / BindIPv6Prefix: the pass is valid only from the same
//     client network; KeyRotateSeconds: signing key period (>= PassSeconds).
//   - Trigger*: challenge only after the client exceeded trigger_max_requests
//     within trigger_window_seconds; omitted means every unpassed request.
//   - Pass*: rate limit applied to clients that already passed; exceeding it
//     revokes the pass and challenges again.
type ChallengeConfig struct {
	Type                  string `json:"type"`
	FailureWindowSeconds  int    `json:"failure_window_seconds,omitempty"`
	MaxFailures           int    `json:"max_failures,omitempty"`
	PassSeconds           int    `json:"pass_seconds,omitempty"`
	BanSeconds            int    `json:"ban_seconds,omitempty"`
	LogOnly               bool   `json:"log_only,omitempty"`
	PowBits               int    `json:"pow_bits,omitempty"`
	DelaySeconds          int    `json:"delay_seconds,omitempty"`
	ChallengeSeconds      int    `json:"challenge_seconds,omitempty"`
	BindIPv4Prefix        int    `json:"bind_ipv4_prefix,omitempty"`
	BindIPv6Prefix        int    `json:"bind_ipv6_prefix,omitempty"`
	KeyRotateSeconds      int    `json:"key_rotate_seconds,omitempty"`
	TriggerWindowSeconds  int    `json:"trigger_window_seconds,omitempty"`
	TriggerMaxRequests    int    `json:"trigger_max_requests,omitempty"`
	PassWindowSeconds     int    `json:"pass_window_seconds,omitempty"`
	PassMaxRequests       int    `json:"pass_max_requests,omitempty"`
	PassMaxRequestsPerURI int    `json:"pass_max_requests_per_uri,omitempty"`
}

type ActionConfig struct {
	RateLimit  *RateLimitConfig  `json:"rate_limit,omitempty"`
	Challenge  *ChallengeConfig  `json:"challenge,omitempty"`
	ManagedWAF *ManagedWAFConfig `json:"managed_waf,omitempty"`
	// WAFBan / WAFChallenge: WAF rule actions ban and challenge (waf_settings.go).
	WAFBan       *WAFBanConfig       `json:"waf_ban,omitempty"`
	WAFChallenge *WAFChallengeAction `json:"waf_challenge,omitempty"`
}

// ManagedWAFConfig is the managed WAF (OWASP CRS) of a WAF policy: the CRS
// profile pack it runs (Profile, a system/crs-<level> pack ID; the version
// is the control plane's downloaded one at publication), the scoring rule
// IDs (from the profile's exports) its sites do not evaluate, and the
// engine limits. A site may replace the profile and the exclusions
// (site_crs_overrides). InspectionLimitAction ("" = "log", or "block")
// decides what an inspection limit hit does (edgeconfig.ManagedWAF).
type ManagedWAFConfig struct {
	RequestBodyLimit        int    `json:"request_body_limit"`
	RequestBodyNoFilesLimit int    `json:"request_body_no_files_limit"`
	RequestBodyLimitAction  string `json:"request_body_limit_action"`
	ArgumentsLimit          int    `json:"arguments_limit"`
	JSONDepthLimit          int    `json:"json_depth_limit"`
	PCREMatchLimit          int    `json:"pcre_match_limit"`
	InspectionLimitAction   string `json:"inspection_limit_action,omitempty"`
	Profile                 string `json:"profile"`
	Exclusions              []int  `json:"exclusions,omitempty"`
}

type Rule struct {
	ID           uuid.UUID    `json:"id"`
	Name         string       `json:"name"`
	Priority     int          `json:"priority"`
	Enabled      bool         `json:"enabled"`
	Comment      string       `json:"comment,omitempty"`
	ExpiresAt    string       `json:"expires_at,omitempty"`
	Conditions   []Condition  `json:"conditions"`
	Action       string       `json:"action"`
	Flow         string       `json:"flow"`
	ActionConfig ActionConfig `json:"action_config"`
	// CountBy (CC only) is what the rule counts requests by: one or two keys
	// (count_by.go). Absent means the client IP, the only key before CC v4.
	CountBy []CountKey `json:"count_by,omitempty"`
	// ActionTarget (CC temporary_ban with CountBy only): "count_key" bans the
	// whole counted bucket (e.g. a TLS fingerprint); absent bans the client.
	ActionTarget string `json:"action_target,omitempty"`
}

type Policy struct {
	ID            uuid.UUID       `json:"id"`
	ScopeID       uuid.UUID       `json:"scope_id"`
	Owner         *OwnerReference `json:"owner,omitempty"`
	Kind          string          `json:"kind"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Enabled       bool            `json:"enabled"`
	DefaultAction string          `json:"default_action"`
	Rules         []Rule          `json:"rules"`
	CCSettings    *CCSettings     `json:"cc_settings,omitempty"`
	// QuickBlock (WAF only): the quick block switches whose system-managed
	// rules lead Rules (quick_block.go); absent when never configured.
	QuickBlock *QuickBlock `json:"quick_block,omitempty"`
	// WAFSettings (WAF only): observe mode and auto block (waf_settings.go).
	WAFSettings *WAFSettings `json:"waf_settings,omitempty"`
	Revision    int64        `json:"version"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	Origin      string       `json:"origin"`
	Protected   bool         `json:"protected"`
	// LibraryID (subscribed WAF copies): the platform rule library the copy
	// was made from, so clients pair copy and library by ID, not name.
	LibraryID string `json:"library_id,omitempty"`
	ownerID   uuid.UUID
}

type LicensedWAFDefinition struct {
	LibraryID     string
	Revision      int64
	Name          string
	Description   string
	Enabled       bool
	DefaultAction string
	Rules         []Rule
}

type LicensedWAFMetadata struct {
	LibraryID   string `json:"library_id"`
	Revision    int64  `json:"revision"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type LicensedWAFSubscription struct {
	PolicyID uuid.UUID
	Revision int64
	Metadata LicensedWAFMetadata
}

type PolicyFields struct {
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Enabled       bool   `json:"enabled"`
	DefaultAction string `json:"default_action"`
	Rules         []Rule `json:"rules"`
	ACLImport     string `json:"acl_import,omitempty"`
	// CCSettings (CC only): site-level durations and auto switch.
	CCSettings *CCSettings `json:"cc_settings,omitempty"`
	// WAFSettings (WAF only): observe mode and auto block.
	WAFSettings *WAFSettings `json:"waf_settings,omitempty"`
}

type CreateRequest struct {
	TargetScopeID  uuid.UUID
	OwnerUserID    uuid.UUID
	Fields         PolicyFields
	IdempotencyKey string
	RequestID      string
}

type UpdateRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	Fields           PolicyFields
	IdempotencyKey   string
	RequestID        string
	AllowProtected   bool
}

// QuickBlockRequest replaces a WAF policy's quick block switches (and the
// system-managed rules they expand to).
type QuickBlockRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	QuickBlock       QuickBlock
	IdempotencyKey   string
	RequestID        string
}

type DeleteRequest struct {
	ID               uuid.UUID
	ExpectedRevision int64
	IdempotencyKey   string
	RequestID        string
	AllowProtected   bool
}

type ListFilter struct {
	Page   int
	Limit  int
	Kind   string
	Status string
	Name   string
	ID     uuid.UUID
	Owner  string
	// Scope (SEC-ACCOUNT-04, WAF only): system = platform rule library copies;
	// site = own libraries a site is bound to; global = own libraries no site
	// is bound to (usable by every site of the tenant).
	Scope string
}

const (
	ScopeGlobal = "global"
	ScopeSite   = "site"
	ScopeSystem = "system"
)

// ListCounts are the policies under the list's filters except status (规则组胶囊
// 显示/禁用 cover every page, not the current one).
type ListCounts struct {
	All      int64 `json:"all"`
	Enabled  int64 `json:"enabled"`
	Disabled int64 `json:"disabled"`
}

type ListResult struct {
	Items  []Policy   `json:"items"`
	Total  int64      `json:"total"`
	Page   int        `json:"page"`
	Limit  int        `json:"limit"`
	Counts ListCounts `json:"counts"`
}

type WriteResult struct {
	Policy   Policy
	Replayed bool
}

type DeleteResult struct {
	ID       uuid.UUID `json:"id"`
	Deleted  bool      `json:"deleted"`
	Revision int64     `json:"version"`
	Replayed bool      `json:"-"`
}

type RequestFacts struct {
	ClientIP           string       `json:"client_ip"`
	Host               string       `json:"host"`
	Path               string       `json:"path"`
	Method             string       `json:"method"`
	Headers            HeaderValues `json:"headers"`
	Country            string       `json:"country"`
	ASN                uint32       `json:"asn"`
	JA4                string       `json:"ja4"`
	Port               uint16       `json:"port"`
	DistinctUserAgents uint32       `json:"distinct_user_agents"`
	Status404Count     uint32       `json:"status_404_count"`
}

type HeaderValues map[string][]string

func (values *HeaderValues) UnmarshalJSON(raw []byte) error {
	var encoded map[string]json.RawMessage
	if string(raw) == "null" || json.Unmarshal(raw, &encoded) != nil {
		return errors.New("invalid preview headers")
	}
	result := make(HeaderValues, len(encoded))
	for name, value := range encoded {
		var multiple []string
		if err := json.Unmarshal(value, &multiple); err == nil {
			result[name] = multiple
			continue
		}
		var single string
		if err := json.Unmarshal(value, &single); err != nil {
			return errors.New("invalid preview header values")
		}
		result[name] = []string{single}
	}
	*values = result
	return nil
}

type Evaluation struct {
	PolicyID       uuid.UUID   `json:"policy_id"`
	PolicyRevision int64       `json:"policy_version"`
	Action         string      `json:"action"`
	MatchedRuleIDs []uuid.UUID `json:"matched_rule_ids"`
	TerminalRuleID *uuid.UUID  `json:"terminal_rule_id,omitempty"`
	UsedDefault    bool        `json:"used_default"`
	ExpiredRuleIDs []uuid.UUID `json:"expired_rule_ids,omitempty"`
}
