package httppolicycontrol

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	PermissionRead   = "http_policies.read"
	PermissionManage = "http_policies.manage"

	EdgeSchemaVersion = "cdnca.edge.http-policy/v1"
	DocumentSchema    = "cdnca.control.http-policy/v1"
	MaxPolicyBytes    = 1 << 20
	MaxPolicyVersion  = 1<<53 - 1
	MaxSites          = 128
	MaxHeaderActions  = 64
	MaxHeaderValues   = 16
	MaxHeaderBytes    = 1024
	MaxRules          = 128
	MaxPathBytes      = 2048
	MaxUploadBytes    = 1 << 30
	MaxOrigins        = 64
	// MaxRefererDomains bounds each hotlink domain list; MaxRefererExtensions
	// the extension filter.
	MaxRefererDomains    = 64
	MaxRefererExtensions = 32
	MaxRewriteHops       = 16
	maxCursorBytes       = 1024
	maxRequestBytes      = 1 << 20
	maxResponseBytes     = 2 << 20

	HeaderAdd    = "add"
	HeaderSet    = "set"
	HeaderDelete = "delete"

	MatchExact  = "exact"
	MatchPrefix = "prefix"
	// MatchRegex matches the request path against an anchored ("^/") RE2
	// pattern; the target may name its capture groups $1..$9.
	MatchRegex = "regex"

	// MaxRegexBytes bounds a regex match pattern.
	MaxRegexBytes = 512

	CredentialKindSession = "session"
	CredentialKindAPIKey  = "api_key"
)

var (
	ErrUnauthenticated        = errors.New("HTTP policy authentication required")
	ErrInvalidInput           = errors.New("invalid HTTP policy input")
	ErrValidation             = errors.New("HTTP policy validation failed")
	ErrPermissionDenied       = errors.New("HTTP policy permission denied")
	ErrNotFound               = errors.New("HTTP policy not found")
	ErrConflict               = errors.New("HTTP policy conflict")
	ErrSiteLocked             = errors.New("site is locked by a platform administrator")
	ErrRevisionConflict       = errors.New("HTTP policy revision conflict")
	ErrIdempotencyConflict    = errors.New("HTTP policy idempotency conflict")
	ErrPreconditionRequired   = errors.New("HTTP policy revision precondition required")
	ErrEntitlementDenied      = errors.New("HTTP policy entitlement denied")
	ErrEntitlementUnavailable = errors.New("HTTP policy entitlement unavailable")
	ErrUnavailable            = errors.New("HTTP policy storage unavailable")
	ErrInvalidStoreConfig     = errors.New("invalid HTTP policy store configuration")
	ErrInvalidHandlerConfig   = errors.New("invalid HTTP policy handler configuration")
)

type CredentialReference struct {
	Kind string
	ID   uuid.UUID
}

type Actor struct {
	UserID      uuid.UUID
	ScopeID     uuid.UUID
	ScopeKind   string
	Permissions []string
	Credential  CredentialReference
	rawSession  string
	tenantID    *uuid.UUID
}

type HeaderAction struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	Values []string `json:"values"`
	// AllowDuplicate (add only, 允许重复): true appends the
	// values to a header of that name; false adds them only when the header
	// is absent ("不存在时添加"). Values may reference
	// edgeconfig.HeaderVariables as $name.
	AllowDuplicate bool `json:"allow_duplicate,omitempty"`
}

type RewriteRule struct {
	RuleID         string `json:"rule_id"`
	Priority       uint32 `json:"priority"`
	MatchKind      string `json:"match_kind"`
	MatchPath      string `json:"match_path"`
	TargetPath     string `json:"target_path"`
	PreserveQuery  bool   `json:"preserve_query"`
	PreserveCookie bool   `json:"preserve_cookie"`
	// Conditions (高级条件): all must match; nil = always.
	Conditions []edgeconfig.RuleCondition `json:"conditions,omitempty"`
}

type RedirectRule struct {
	RuleID        string `json:"rule_id"`
	Priority      uint32 `json:"priority"`
	MatchKind     string `json:"match_kind"`
	MatchPath     string `json:"match_path"`
	Status        uint16 `json:"status"`
	TargetURL     string `json:"target_url"`
	PreserveQuery bool   `json:"preserve_query"`
	// PreservePath (prefix rules only) appends the path after match_path to
	// target_url, whose path then ends with "/".
	PreservePath bool `json:"preserve_path"`
	// Conditions (高级条件): as RewriteRule.Conditions.
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

// RefererCheckPolicy is the site's hotlink protection (防盗链, ge-waf
// S8). The node reads Referer (Origin instead when
// Referer is absent and CheckOrigin is set):
//   - absent or empty: AllowEmpty decides;
//   - unparsable: rejected;
//   - host in DeniedDomains: rejected (deny wins);
//   - host equal to the request host (AllowSameDomain) or in AllowedDomains: allowed;
//   - otherwise rejected when AllowSameDomain or AllowedDomains restrict the
//     sources, allowed when only DeniedDomains is set.
//
// Domains are a host name or "*.example.com" (any subdomain). Extensions,
// when set, limit the check to request paths with those file extensions
// (images, video...) so pages stay reachable from search results.
type RefererCheckPolicy struct {
	AllowEmpty      bool     `json:"allow_empty"`
	AllowSameDomain bool     `json:"allow_same_domain"`
	AllowedDomains  []string `json:"allowed_domains"`
	DeniedDomains   []string `json:"denied_domains"`
	CheckOrigin     bool     `json:"check_origin"`
	Extensions      []string `json:"extensions"`
}

type Config struct {
	MaxUploadBytes       int64               `json:"max_upload_bytes"`
	RequestHeaders       []HeaderAction      `json:"request_headers"`
	ResponseHeaders      []HeaderAction      `json:"response_headers"`
	Rewrites             []RewriteRule       `json:"rewrites"`
	RedirectAllowedHosts []string            `json:"redirect_allowed_hosts"`
	Redirects            []RedirectRule      `json:"redirects"`
	CORS                 *CORSPolicy         `json:"cors"`
	RefererCheck         *RefererCheckPolicy `json:"referer_check"`
}

type Policy struct {
	ID                   uuid.UUID           `json:"id"`
	TenantScopeID        uuid.UUID           `json:"tenant_scope_id"`
	SiteID               uuid.UUID           `json:"site_id"`
	SiteOwnerUserID      uuid.UUID           `json:"site_owner_user_id"`
	MaxUploadBytes       int64               `json:"max_upload_bytes"`
	RequestHeaders       []HeaderAction      `json:"request_headers"`
	ResponseHeaders      []HeaderAction      `json:"response_headers"`
	Rewrites             []RewriteRule       `json:"rewrites"`
	RedirectAllowedHosts []string            `json:"redirect_allowed_hosts"`
	Redirects            []RedirectRule      `json:"redirects"`
	CORS                 *CORSPolicy         `json:"cors"`
	RefererCheck         *RefererCheckPolicy `json:"referer_check"`
	Enabled              bool                `json:"enabled"`
	Deleted              bool                `json:"deleted"`
	Revision             int64               `json:"revision"`
	PublicationRevision  uint64              `json:"publication_revision"`
	CreatedAt            time.Time           `json:"created_at"`
	UpdatedAt            time.Time           `json:"updated_at"`
}

type storedPolicy struct {
	Policy
	TenantID uuid.UUID
}

type WriteMetadata struct {
	IdempotencyKey string
	RequestID      string
	TraceID        string
}

type CreateRequest struct {
	TargetScopeID uuid.UUID
	SiteID        uuid.UUID
	Enabled       bool
	Config        Config
	WriteMetadata
}

type UpdateRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	Config           Config
	WriteMetadata
}

type StateRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	Enabled          bool
	WriteMetadata
}

type DeleteRequest struct {
	TargetScopeID    uuid.UUID
	ID               uuid.UUID
	ExpectedRevision int64
	WriteMetadata
}

type ListFilter struct {
	TargetScopeID uuid.UUID
	Limit         int
	Cursor        string
	SiteID        uuid.UUID
	Enabled       *bool
}

type ListResult struct {
	Items      []Policy `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

type WriteResult struct {
	Policy   Policy
	Replayed bool
}

type EdgeSitePolicy struct {
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

type EdgeSnapshot struct {
	SchemaVersion string           `json:"schema_version"`
	PolicyVersion uint64           `json:"policy_version"`
	Sites         []EdgeSitePolicy `json:"sites"`
}

type PublicationPreview struct {
	State    string       `json:"state"`
	SHA256   string       `json:"sha256"`
	Snapshot EdgeSnapshot `json:"snapshot"`
}

type entitlementCheck struct {
	AuditScopeID uuid.UUID
	ActorUserID  uuid.UUID
	ResourceID   uuid.UUID
	RequestID    string
	Operation    string
}

type entitlementGate interface {
	Check(context.Context, pgx.Tx, entitlementCheck) error
}

// TxAuthorizer owns the IAM lock protocol for every protected operation and returns the locked target tenant.
// Implementations must recheck the server-authenticated principal and permission. Pure reads
// must use the same transaction for authorization and business data.
type TxAuthorizer interface {
	AuthorizeWrite(context.Context, pgx.Tx, Actor, uuid.UUID, string) (uuid.UUID, error)
}

type revisionDocument struct {
	SchemaVersion        string              `json:"schema_version"`
	PolicyID             uuid.UUID           `json:"policy_id"`
	TenantScopeID        uuid.UUID           `json:"tenant_scope_id"`
	SiteID               uuid.UUID           `json:"site_id"`
	SiteOwnerUserID      uuid.UUID           `json:"site_owner_user_id"`
	Revision             int64               `json:"revision"`
	MaxUploadBytes       int64               `json:"max_upload_bytes"`
	RequestHeaders       []HeaderAction      `json:"request_headers"`
	ResponseHeaders      []HeaderAction      `json:"response_headers"`
	Rewrites             []RewriteRule       `json:"rewrites"`
	RedirectAllowedHosts []string            `json:"redirect_allowed_hosts"`
	Redirects            []RedirectRule      `json:"redirects"`
	CORS                 *CORSPolicy         `json:"cors"`
	RefererCheck         *RefererCheckPolicy `json:"referer_check"`
	Enabled              bool                `json:"enabled"`
	Deleted              bool                `json:"deleted"`
}
