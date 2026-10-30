// Package siteschedule302 is a site's HTTP 302 scheduling (
// "DNS + 302 双调度"; 网站“302 调度”卡片): off, or on with the redirect
// target (node address or node direct hostname), whether the path and the
// query are kept, the signature lifetime, whether HTTPS requests are also
// redirected (to plain HTTP) and the large-file filters (extensions, path
// prefixes, learned size threshold).
//
// The settings are a site setting written under sites.manage: the write
// advances sites.revision (GET ETag / PUT If-Match) and publishes the site as
// every site setting does (edgeautopublish EnqueueSiteSettingTx). Releases
// carry the settings (edgepublish bindSiteRuntimeV2Schedule302); the signing
// key generated when the site is first scheduled only reaches its nodes in
// their signed scheduling table (sched302table). Audit:
// site.schedule302.update (success, or denied with a reason code).
package siteschedule302

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput        = errors.New("invalid site schedule302 input")
	ErrNotFound            = errors.New("site not found")
	ErrRevisionConflict    = errors.New("site revision conflict")
	ErrIdempotencyConflict = errors.New("site schedule302 idempotency conflict")
	ErrLocked              = errors.New("site is locked")
	// ErrNoPlainListener: scheduled requests land on plain HTTP; a site with
	// only HTTPS ports cannot be scheduled.
	ErrNoPlainListener = errors.New("site has no plain HTTP port")
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Actor is the authenticated principal (sites.read / sites.manage checked
// by the caller); a tenant actor only reaches its own scope's sites.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// Settings is the editable state. Disabled settings keep nothing: turning
// scheduling off deletes them (and the signing key, so re-enabling invalidates
// every redirect issued before).
type Settings struct {
	Enabled             bool     `json:"enabled"`
	Target              string   `json:"target"`
	KeepPath            bool     `json:"keep_path"`
	KeepQuery           bool     `json:"keep_query"`
	SignatureTTLSeconds int64    `json:"signature_ttl_seconds"`
	HTTPSToHTTP         bool     `json:"https_to_http"`
	Extensions          []string `json:"extensions"`
	PathPrefixes        []string `json:"path_prefixes"`
	MinSizeBytes        int64    `json:"min_size_bytes"`
}

// DefaultSettings is what the page shows for a site that was never scheduled.
func DefaultSettings() Settings {
	return Settings{Target: sched302.TargetAddress, KeepPath: true, KeepQuery: true,
		SignatureTTLSeconds: sched302.DefaultSignatureTTLSeconds, Extensions: []string{}, PathPrefixes: []string{}}
}

// State is a site's scheduling settings with its version.
type State struct {
	SiteID uuid.UUID `json:"site_id"`
	// Version is sites.revision (ETag / If-Match).
	Version  int64    `json:"version"`
	Settings Settings `json:"settings"`
	// PlainHTTP: the site has a plain HTTP port (scheduling needs one).
	PlainHTTP bool       `json:"plain_http"`
	UpdatedAt *time.Time `json:"updated_at"`
}

type UpdateRequest struct {
	SiteID           uuid.UUID
	ExpectedRevision int64
	Settings         Settings
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

// Update replaces the site's settings (disabled: they are deleted).
func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (State, error) {
	if !validActor(actor) || request.SiteID == uuid.Nil || request.ExpectedRevision < 1 ||
		!idempotencyPattern.MatchString(request.IdempotencyKey) || strings.TrimSpace(request.RequestID) == "" {
		return State{}, ErrInvalidInput
	}
	settings, err := Normalize(request.Settings)
	if err != nil {
		return State{}, err
	}
	request.Settings = settings
	encoded, err := json.Marshal(struct {
		SiteID   uuid.UUID `json:"site_id"`
		Version  int64     `json:"expected_version"`
		Settings Settings  `json:"settings"`
	}{request.SiteID, request.ExpectedRevision, request.Settings})
	if err != nil {
		return State{}, err
	}
	return s.store.Update(ctx, actor, request, sha256.Sum256(encoded))
}

// Normalize validates and canonicalizes settings; disabled settings become
// the defaults (nothing is kept).
func Normalize(settings Settings) (Settings, error) {
	if !settings.Enabled {
		return DefaultSettings(), nil
	}
	site := siteOf(settings)
	if err := sched302.NormalizeSite(&site); err != nil {
		return Settings{}, ErrInvalidInput
	}
	normalized := settingsOf(site)
	normalized.Enabled = true
	return normalized, nil
}

func siteOf(settings Settings) sched302.Site {
	return sched302.Site{Target: settings.Target, KeepPath: settings.KeepPath, KeepQuery: settings.KeepQuery,
		SignatureTTLSeconds: settings.SignatureTTLSeconds, HTTPSToHTTP: settings.HTTPSToHTTP,
		Extensions: append([]string{}, settings.Extensions...), PathPrefixes: append([]string{}, settings.PathPrefixes...),
		MinSizeBytes: settings.MinSizeBytes}
}

func settingsOf(site sched302.Site) Settings {
	return Settings{Target: site.Target, KeepPath: site.KeepPath, KeepQuery: site.KeepQuery,
		SignatureTTLSeconds: site.SignatureTTLSeconds, HTTPSToHTTP: site.HTTPSToHTTP,
		Extensions: append([]string{}, site.Extensions...), PathPrefixes: append([]string{}, site.PathPrefixes...),
		MinSizeBytes: site.MinSizeBytes}
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}
