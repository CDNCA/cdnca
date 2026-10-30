package plugininstallation

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"
)

const (
	Schema = "cdnca.control.plugin-installation/v1"

	ActionConfirm   = "confirm"
	ActionUpgrade   = "upgrade"
	ActionDisable   = "disable"
	ActionUninstall = "uninstall"
	// ActionResume undoes this controller's own pause (disable). A platform pause cannot be resumed here.
	ActionResume = "resume"

	StatusPendingConfirmation = "pending_confirmation"
	StatusEnabled             = "enabled"
	StatusDisabled            = "disabled"
	StatusUninstalled         = "uninstalled"

	ReceiptInstalled                 = "installed"
	ReceiptUpgradeApplied            = "upgrade_applied"
	ReceiptUpgradeFailedLKGPreserved = "upgrade_failed_lkg_preserved"
	ReceiptDisabled                  = "disabled"
	ReceiptUninstalled               = "uninstalled"
	ReceiptResumed                   = "resumed"

	// Who paused a disabled authorization, from the signed license snapshot (license paused_by).
	PausedByInstallation = "installation"
	PausedByOperator     = "operator"
	PausedByService      = "service"

	// Resource scope signed by the license service (from the verified manifest entrypoint): instance-wide
	// resources (themes, rule data packs) are confirmed in the controller's platform scope, other plugins in
	// the tenant scope that installs them. It equals the kind of the local access scope holding the head.
	ResourceScopePlatform = "platform"
	ResourceScopeTenant   = "tenant"

	// Plugin type: the verified manifest entrypoint type, signed by the license service next to the resource
	// scope (themes and rule data packs are platform resources, the other types tenant plugins).
	EntrypointTheme         = "theme"
	EntrypointRulePack      = "rule_pack"
	EntrypointExternalHTTPS = "external_https"
	EntrypointUIPage        = "ui_page"
)

var (
	ErrInvalidInput        = errors.New("plugin installation invalid input")
	ErrNotFound            = errors.New("plugin installation not found")
	ErrRevisionConflict    = errors.New("plugin installation revision conflict")
	ErrIdempotencyConflict = errors.New("plugin installation idempotency conflict")
	ErrConsentRequired     = errors.New("plugin installation scope approval required")
	ErrFactRequired        = errors.New("plugin installation signed fact required")
	ErrFactDenied          = errors.New("plugin installation signed fact denied")
	ErrFactUnavailable     = errors.New("plugin installation signed fact unavailable")
	ErrTransitionInvalid   = errors.New("plugin installation transition invalid")
	ErrPlatformPaused      = errors.New("plugin installation paused by the platform")
)

var (
	pluginPattern      = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)
	versionPattern     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	digestPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	scopePattern       = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,7}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type Candidate struct {
	TenantID                  uuid.UUID `json:"tenant_scope_id"`
	InstallationID            uuid.UUID `json:"installation_id"`
	AuthorizationID           uuid.UUID `json:"authorization_id"`
	VerificationID            uuid.UUID `json:"verification_id"`
	PluginID                  string    `json:"plugin_id"`
	Version                   string    `json:"version"`
	ResourceScope             string    `json:"resource_scope"`
	EntrypointType            string    `json:"entrypoint_type"`
	ManifestSHA256            string    `json:"manifest_sha256"`
	ConfigurationSchemaSHA256 string    `json:"configuration_schema_sha256"`
	ManifestScopes            []string  `json:"manifest_scopes"`
	ApprovedScopes            []string  `json:"approved_scopes"`
	SensitiveScopes           []string  `json:"sensitive_scopes"`
}

type SignedRuntimeFact struct {
	Scope        string
	RequestID    string
	IdentityJSON []byte
	DecisionJSON []byte
}

type Command struct {
	TenantID                      uuid.UUID
	InstallationID                uuid.UUID
	AuthorizationID               uuid.UUID
	Action                        string
	ExpectedRevision              uint64
	IdempotencyKey                string
	RequestID                     string
	Candidate                     Candidate
	Facts                         []SignedRuntimeFact
	SensitivePermissionsConfirmed bool
	NewPermissionsConfirmed       bool
	Applied                       bool
	StableReasonCode              string
	Reason                        string
}

type Installation struct {
	Schema                    string    `json:"schema"`
	TenantID                  uuid.UUID `json:"tenant_scope_id"`
	AuthorizationID           uuid.UUID `json:"authorization_id"`
	InstallationID            uuid.UUID `json:"installation_id"`
	VerificationID            uuid.UUID `json:"verification_id"`
	PluginID                  string    `json:"plugin_id"`
	Version                   string    `json:"version"`
	ResourceScope             string    `json:"resource_scope"`
	EntrypointType            string    `json:"entrypoint_type"`
	ManifestSHA256            string    `json:"manifest_sha256"`
	ConfigurationSchemaSHA256 string    `json:"configuration_schema_sha256"`
	ManifestScopes            []string  `json:"manifest_scopes"`
	ApprovedScopes            []string  `json:"approved_scopes"`
	SensitiveScopes           []string  `json:"sensitive_scopes"`
	Status                    string    `json:"status"`
	Revision                  uint64    `json:"revision"`
	IdentityGeneration        uint64    `json:"identity_generation"`
	LKGVerificationID         uuid.UUID `json:"lkg_verification_id"`
	LKGVersion                string    `json:"lkg_version"`
	StableReasonCode          string    `json:"stable_reason_code"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type Receipt struct {
	ID                      uuid.UUID
	TenantID                uuid.UUID
	AuthorizationID         uuid.UUID
	Action                  string
	IdempotencyKey          string
	RequestID               string
	RequestDigest           [32]byte
	FromRevision            uint64
	ToRevision              uint64
	Result                  string
	Reason                  string
	StableReasonCode        string
	AttemptedVerificationID uuid.UUID
	AttemptedVersion        string
	Snapshot                Installation
	OccurredAt              time.Time
}

type MutationResult struct {
	Installation Installation `json:"installation"`
	Receipt      Receipt      `json:"-"`
}

func ErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "plugin_installation_not_found"
	case errors.Is(err, ErrRevisionConflict):
		return "plugin_installation_revision_conflict"
	case errors.Is(err, ErrIdempotencyConflict):
		return "plugin_installation_idempotency_conflict"
	case errors.Is(err, ErrConsentRequired), errors.Is(err, ErrFactRequired), errors.Is(err, ErrFactDenied):
		return "plugin_installation_scope_approval_required"
	case errors.Is(err, ErrPlatformPaused):
		return "plugin_installation_platform_paused"
	case errors.Is(err, ErrFactUnavailable):
		return "plugin_installation_license_unavailable"
	default:
		return "invalid_request"
	}
}

func validCandidate(candidate Candidate) bool {
	return candidate.TenantID != uuid.Nil && candidate.InstallationID != uuid.Nil && candidate.AuthorizationID != uuid.Nil &&
		candidate.VerificationID != uuid.Nil && validResourceScope(candidate.ResourceScope) &&
		validEntrypoint(candidate.ResourceScope, candidate.EntrypointType) &&
		len(candidate.PluginID) >= 3 && len(candidate.PluginID) <= 128 &&
		pluginPattern.MatchString(candidate.PluginID) && len(candidate.Version) >= 5 && len(candidate.Version) <= 128 &&
		versionPattern.MatchString(candidate.Version) && semver.IsValid("v"+candidate.Version) &&
		digestPattern.MatchString(candidate.ManifestSHA256) &&
		digestPattern.MatchString(candidate.ConfigurationSchemaSHA256) && validScopes(candidate.ManifestScopes) &&
		validScopes(candidate.ApprovedScopes) && validScopes(candidate.SensitiveScopes) &&
		subset(candidate.ApprovedScopes, candidate.ManifestScopes) && subset(candidate.SensitiveScopes, candidate.ManifestScopes)
}

func validResourceScope(value string) bool {
	return value == ResourceScopePlatform || value == ResourceScopeTenant
}

// validEntrypoint: a known plugin type that agrees with the signed resource scope.
func validEntrypoint(resourceScope, entrypointType string) bool {
	switch entrypointType {
	case EntrypointTheme, EntrypointRulePack:
		return resourceScope == ResourceScopePlatform
	case EntrypointExternalHTTPS, EntrypointUIPage:
		return resourceScope == ResourceScopeTenant
	default:
		return false
	}
}

func validScopes(values []string) bool {
	if len(values) > 64 {
		return false
	}
	for index, value := range values {
		if len(value) < 3 || len(value) > 128 || !scopePattern.MatchString(value) ||
			(index > 0 && values[index-1] >= value) {
			return false
		}
	}
	return true
}

func subset(values, allowed []string) bool {
	for _, value := range values {
		if _, ok := slices.BinarySearch(allowed, value); !ok {
			return false
		}
	}
	return true
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

func validReason(value string) bool {
	return value != "" && value == strings.TrimSpace(value) &&
		utf8.ValidString(value) && utf8.RuneCountInString(value) <= 500
}
