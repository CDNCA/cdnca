// Package sitequickblock is a site's own quick block (
// 站点“防护”页“快速屏蔽”): each item of the site's WAF rule library quick
// block (securitypolicy.QuickBlock) is inherited, or set for this site only
// (securitypolicy.QuickBlockOverride, site_quick_block_overrides). Sites
// without an override keep following the library.
//
// The override is a site setting written under security_policies.manage: the
// write advances sites.revision (GET ETag / PUT If-Match), which advances the
// scope's source revision as every site write does, so a manual scope shows
// it pending and an automatic scope publishes it (edgeautopublish
// EnqueueSiteSettingTx, as the scope's automatic policy actor). Releases
// compile the library version the site's binding publishes with the
// override applied (edgepublish bindSoldPackageRuntimeSecurity).
package sitequickblock

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid site quick block input")
	ErrNotFound            = errors.New("site not found")
	ErrRevisionConflict    = errors.New("site revision conflict")
	ErrIdempotencyConflict = errors.New("site quick block idempotency conflict")
	ErrLocked              = errors.New("site is locked")
	// ErrNoLibrary: the site has no WAF rule library binding to override
	// (an override that inherits everything needs none).
	ErrNoLibrary = errors.New("site has no WAF rule library")
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Actor is the authenticated principal (security_policies.read / manage
// checked by the caller); a tenant actor only reaches its own scope's sites.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// Library is the site's WAF rule library as the override applies to it.
type Library struct {
	PolicyID uuid.UUID `json:"policy_id"`
	// Version is the library's latest version; ActiveVersion the one the
	// site's binding publishes (0: none published yet).
	Version       int64 `json:"version"`
	ActiveVersion int64 `json:"active_version"`
	// Supported: the library can carry a quick block that blocks anything
	// (securitypolicy.QuickBlockSupported).
	Supported bool `json:"supported"`
	// QuickBlock is the latest version's quick block (all off when never
	// configured): what an inherited item follows.
	QuickBlock securitypolicy.QuickBlock `json:"quick_block"`
}

// State is a site's quick block: its override, its library and what the
// site runs once published.
type State struct {
	SiteID uuid.UUID `json:"site_id"`
	// Version is sites.revision (ETag / If-Match).
	Version  int64                             `json:"version"`
	Override securitypolicy.QuickBlockOverride `json:"override"`
	// Library is nil when the site has no WAF rule library binding.
	Library *Library `json:"library"`
	// Effective is the library's latest quick block with the override's
	// items in place; nil without a library.
	Effective *securitypolicy.QuickBlock `json:"effective"`
	UpdatedAt *time.Time                 `json:"updated_at"`
}

type UpdateRequest struct {
	SiteID           uuid.UUID
	ExpectedRevision int64
	Override         securitypolicy.QuickBlockOverride
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
// Turning an item on needs the control plane's verified IP intelligence
// library (securitypolicy.ErrQuickBlockIPIntelUnavailable); an override the
// site's library cannot carry is refused with the library's quick block
// errors.
func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (State, error) {
	if !validActor(actor) || request.SiteID == uuid.Nil || request.ExpectedRevision < 1 ||
		!idempotencyPattern.MatchString(request.IdempotencyKey) || strings.TrimSpace(request.RequestID) == "" {
		return State{}, ErrInvalidInput
	}
	if err := securitypolicy.NormalizeQuickBlockOverride(&request.Override); err != nil {
		return State{}, ErrInvalidInput
	}
	encoded, err := json.Marshal(struct {
		SiteID   uuid.UUID                         `json:"site_id"`
		Version  int64                             `json:"expected_version"`
		Override securitypolicy.QuickBlockOverride `json:"override"`
	}{request.SiteID, request.ExpectedRevision, request.Override})
	if err != nil {
		return State{}, err
	}
	return s.store.Update(ctx, actor, request, sha256.Sum256(encoded))
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

// libraryState is the Library of policy (latest version) with active the
// binding's published version (0: none).
func libraryState(latest securitypolicy.Policy, active int64) Library {
	block := securitypolicy.EffectiveQuickBlock(latest.QuickBlock, securitypolicy.QuickBlockOverride{})
	return Library{PolicyID: latest.ID, Version: latest.Revision, ActiveVersion: active,
		Supported: securitypolicy.QuickBlockSupported(latest), QuickBlock: block}
}
