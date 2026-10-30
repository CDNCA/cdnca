package httppolicy

import (
	"crypto/sha256"
	"errors"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	SchemaVersion        = "cdnca.edge.http-policy/v1"
	MaxPolicyBytes       = 1 << 20
	MaxPolicyVersion     = 1<<53 - 1
	MaxSites             = 128
	MaxHeaderActions     = 64
	MaxHeaderValues      = 16
	MaxHeaderBytes       = 1024
	MaxRules             = 128
	MaxPathBytes         = 2048
	MaxUploadBytes       = 1 << 30
	MaxOrigins           = 64
	MaxRefererDomains    = 64
	MaxRefererExtensions = 32
)

var ErrInvalidPolicy = errors.New("invalid HTTP policy")

type HeaderActionKind string

const (
	HeaderAdd    HeaderActionKind = "add"
	HeaderSet    HeaderActionKind = "set"
	HeaderDelete HeaderActionKind = "delete"
)

type MatchKind string

const (
	MatchExact  MatchKind = "exact"
	MatchPrefix MatchKind = "prefix"
	// MatchRegex: an anchored ("^/") RE2 pattern whose target names its
	// capture groups $1..$9.
	MatchRegex MatchKind = "regex"
)

// MaxRegexBytes bounds a regex match pattern.
const MaxRegexBytes = 512

type Policy struct {
	SchemaVersion string       `json:"schema_version"`
	PolicyVersion uint64       `json:"policy_version"`
	Sites         []SitePolicy `json:"sites"`
}

type SitePolicy struct {
	SiteID               string              `json:"site_id"`
	MaxUploadBytes       int64               `json:"max_upload_bytes"`
	RequestHeaders       []HeaderAction      `json:"request_headers"`
	ResponseHeaders      []HeaderAction      `json:"response_headers"`
	Rewrites             []RewriteRule       `json:"rewrites"`
	RedirectAllowedHosts []string            `json:"redirect_allowed_hosts"`
	Redirects            []RedirectRule      `json:"redirects"`
	CORS                 *CORSPolicy         `json:"cors"`
	RefererCheck         *RefererCheckPolicy `json:"referer_check"`
}

// Header names are case-insensitive and canonicalized to lowercase. Values
// keep their declared order: add appends fields, set replaces all fields, and
// delete requires an empty values array.
//
// AllowDuplicate (add only): true appends to an existing header, false adds
// only when the header is absent. Values may reference
// edgeconfig.HeaderVariables as $name (expanded by engine.lua).
type HeaderAction struct {
	Kind           HeaderActionKind `json:"kind"`
	Name           string           `json:"name"`
	Values         []string         `json:"values"`
	AllowDuplicate bool             `json:"allow_duplicate,omitempty"`
}

type RewriteRule struct {
	RuleID         string    `json:"rule_id"`
	Priority       uint32    `json:"priority"`
	MatchKind      MatchKind `json:"match_kind"`
	MatchPath      string    `json:"match_path"`
	TargetPath     string    `json:"target_path"`
	PreserveQuery  bool      `json:"preserve_query"`
	PreserveCookie bool      `json:"preserve_cookie"`
	// Conditions: 高级条件, all must match (nil = always).
	Conditions []edgeconfig.RuleCondition `json:"conditions,omitempty"`
}

type RedirectRule struct {
	RuleID        string    `json:"rule_id"`
	Priority      uint32    `json:"priority"`
	MatchKind     MatchKind `json:"match_kind"`
	MatchPath     string    `json:"match_path"`
	Status        uint16    `json:"status"`
	TargetURL     string    `json:"target_url"`
	PreserveQuery bool      `json:"preserve_query"`
	// PreservePath (prefix rules) appends the path after match_path to the
	// target directory.
	PreservePath bool `json:"preserve_path"`
	// Conditions: 高级条件, all must match (nil = always).
	Conditions []edgeconfig.RuleCondition `json:"conditions,omitempty"`
}

type CORSPolicy struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	ExposedHeaders   []string `json:"exposed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAgeSeconds    uint32   `json:"max_age_seconds"`
}

// RefererCheckPolicy is hotlink protection (control
// httppolicycontrol.RefererCheckPolicy; engine.lua check_referer).
type RefererCheckPolicy struct {
	AllowEmpty      bool     `json:"allow_empty"`
	AllowSameDomain bool     `json:"allow_same_domain"`
	AllowedDomains  []string `json:"allowed_domains"`
	DeniedDomains   []string `json:"denied_domains"`
	CheckOrigin     bool     `json:"check_origin"`
	Extensions      []string `json:"extensions"`
}

type Artifact struct {
	PolicyVersion uint64
	Canonical     []byte
	Digest        [sha256.Size]byte
}

type Publication struct {
	PolicyVersion       uint64
	Digest              [sha256.Size]byte
	CommitPath          string
	VersionPath         string
	Changed             bool
	DurabilityConfirmed bool
}
