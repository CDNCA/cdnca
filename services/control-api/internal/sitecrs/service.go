// Package sitecrs is a site's own OWASP CRS settings (PA-12, 站点“防护”页
// “CRS 档位”): the CRS profile pack its managed WAF runs and the rules it
// excludes are inherited from the site's WAF rule library, or set for this
// site only (securitypolicy.CRSOverride, site_crs_overrides).
//
// The override is a site setting written under security_policies.manage: the
// write advances sites.revision (GET ETag / PUT If-Match) and publishes the
// site as every site setting does (edgeautopublish EnqueueSiteSettingTx).
// Releases compile the library's managed WAF with the override applied
// (edgepublish attachSiteCRS, securitypublication).
package sitecrs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid site CRS input")
	ErrNotFound            = errors.New("site not found")
	ErrRevisionConflict    = errors.New("site revision conflict")
	ErrIdempotencyConflict = errors.New("site CRS idempotency conflict")
	ErrLocked              = errors.New("site is locked")
	// ErrNoManagedWAF: the site's WAF rule library runs no managed WAF to
	// override (an override that inherits everything needs none).
	ErrNoManagedWAF = errors.New("site WAF rule library runs no managed WAF")
	// ErrProfileUnavailable: the profile is not a downloaded usable pack.
	ErrProfileUnavailable = errors.New("CRS profile pack is not available")
	// ErrExclusionNotExported: an excluded rule is not in the effective
	// profile's exports.
	ErrExclusionNotExported = errors.New("excluded rule is not exported by the CRS profile")
	// ErrAppUnavailable: a selected application type's exclusion pack is not
	// downloaded on this control plane.
	ErrAppUnavailable = errors.New("application exclusion pack is not available")
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Actor is the authenticated principal (security_policies.read / manage
// checked by the caller); a tenant actor only reaches its own scope's sites.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// Library is the site's WAF rule library managed WAF the override applies to.
type Library struct {
	PolicyID   uuid.UUID `json:"policy_id"`
	Version    int64     `json:"version"`
	Profile    string    `json:"profile"`
	Exclusions []int     `json:"exclusions"`
}

// State is a site's CRS settings: its override, its library's, what the
// site runs once published and the profiles it may choose.
type State struct {
	SiteID uuid.UUID `json:"site_id"`
	// Version is sites.revision (ETag / If-Match).
	Version  int64                      `json:"version"`
	Override securitypolicy.CRSOverride `json:"override"`
	// Library is nil when the site's WAF rule library runs no managed WAF.
	Library *Library `json:"library"`
	// Effective profile and exclusions; nil without a library.
	Effective *Library                           `json:"effective"`
	Profiles  []securitypolicy.CRSProfileSummary `json:"profiles"`
	// Apps are the selectable application types (downloaded packs).
	Apps []securitypolicy.CRSAppSummary `json:"apps"`
	UpdatedAt *time.Time                         `json:"updated_at"`
	// RulePackSuspensions are the site's ModSecurity rule pack mounts
	// suspended because the effective profile does not cover them
	// (rulepackcontrol suspend.go); they come back when it does again.
	RulePackSuspensions []rulepackcontrol.Suspension `json:"rule_pack_suspensions"`
	// RulePackChange (update responses only) is what this write suspended
	// and restored.
	RulePackChange *rulepackcontrol.ProfileChange `json:"rule_pack_change,omitempty"`
}

type UpdateRequest struct {
	SiteID           uuid.UUID
	ExpectedRevision int64
	Override         securitypolicy.CRSOverride
	IdempotencyKey   string
	RequestID        string
	// SourceIP is the caller's address for the audit event ("" unknown).
	SourceIP string
}

type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

func (s *Service) Get(ctx context.Context, actor Actor, siteID uuid.UUID) (State, error) {
	if !validActor(actor) || siteID == uuid.Nil {
		return State{}, ErrInvalidInput
	}
	return s.store.Get(ctx, actor, siteID)
}

// Update replaces the site's override (every item inherit: the row goes).
// The effective profile must be a downloaded usable pack exporting every
// effective exclusion.
func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (State, error) {
	if !validActor(actor) || request.SiteID == uuid.Nil || request.ExpectedRevision < 1 ||
		!idempotencyPattern.MatchString(request.IdempotencyKey) || strings.TrimSpace(request.RequestID) == "" {
		return State{}, ErrInvalidInput
	}
	if err := securitypolicy.NormalizeCRSOverride(&request.Override); err != nil {
		return State{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(struct {
		SiteID   uuid.UUID                  `json:"site_id"`
		Version  int64                      `json:"expected_version"`
		Override securitypolicy.CRSOverride `json:"override"`
	}{request.SiteID, request.ExpectedRevision, request.Override})
	if err != nil {
		return State{}, err
	}
	return s.store.Update(ctx, actor, request, sha256.Sum256(encoded))
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

// effective applies the override to the library (nil without one).
func effective(library *Library, override securitypolicy.CRSOverride) *Library {
	if library == nil {
		return nil
	}
	config := securitypolicy.EffectiveManagedWAF(securitypolicy.ManagedWAFConfig{Profile: library.Profile,
		Exclusions: library.Exclusions}, override)
	exclusions := config.Exclusions
	if exclusions == nil {
		exclusions = []int{}
	}
	return &Library{PolicyID: library.PolicyID, Version: library.Version, Profile: config.Profile, Exclusions: exclusions}
}

// profileList is the selectable profiles, by pack ID.
func profileList(profiles securitypolicy.CRSProfiles) []securitypolicy.CRSProfileSummary {
	return profiles.Summaries()
}

// checkApps: every selected application type is a downloaded pack.
func checkApps(selected []string, apps securitypolicy.CRSApps) error {
	if _, _, ok := apps.Refs(selected); !ok {
		return ErrAppUnavailable
	}
	return nil
}
