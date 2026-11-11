// Package sitecontentrewrite is a site's 内容改写 rules (C8;
// console page 网站 → 内容改写): the whole settings object is read and
// replaced at once (GET / PUT with If-Match = sites.revision), and the
// tester runs draft settings on a pasted body with the node's algorithm
// (libs/edgeconfig/contentrewrite) without writing anything.
//
// A write advances sites.revision and publishes the site as every site
// setting does (edgeautopublish EnqueueSiteSettingTx); releases carry the
// enabled rules (edgepublish loadSiteContentRewrite). No idempotency table:
// a replayed PUT carries a stale If-Match and gets version_conflict. Audit:
// site.content_rewrite.update (success, or denied with a reason code).
package sitecontentrewrite

import (
	"context"
	"errors"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig/contentrewrite"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput     = errors.New("invalid site content rewrite input")
	ErrNotFound         = errors.New("site not found")
	ErrRevisionConflict = errors.New("site revision conflict")
	ErrLocked           = errors.New("site is locked")
)

// Actor is the authenticated principal (sites.read / sites.manage checked
// by the caller); a tenant actor only reaches its own scope's sites.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
}

// State is a site's settings with its version.
type State struct {
	SiteID uuid.UUID `json:"site_id"`
	// Version is sites.revision (ETag / If-Match).
	Version  int64                   `json:"version"`
	Settings contentrewrite.Settings `json:"settings"`
	// Domains are the site's active names (https rules with
	// include_site_domains add them).
	Domains []string `json:"domains"`
}

type UpdateRequest struct {
	SiteID           uuid.UUID
	ExpectedRevision int64
	Settings         contentrewrite.Settings
	RequestID        string
	SourceIP         string
}

// TestRequest is the tester's input: draft settings and one response.
type TestRequest struct {
	Settings    contentrewrite.Settings `json:"settings"`
	Path        string                  `json:"path"`
	ContentType string                  `json:"content_type"`
	Body        string                  `json:"body"`
}

type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

func defaults() contentrewrite.Settings {
	return contentrewrite.Settings{MaxBytes: contentrewrite.DefaultMaxBytes, Rules: []contentrewrite.Rule{}}
}

func (s *Service) Get(ctx context.Context, actor Actor, siteID uuid.UUID) (State, error) {
	if !validActor(actor) || siteID == uuid.Nil {
		return State{}, ErrInvalidInput
	}
	return s.store.Get(ctx, actor, siteID)
}

// Update replaces the settings; a *contentrewrite.FieldError names the
// refused field.
func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (State, error) {
	if !validActor(actor) || request.SiteID == uuid.Nil || request.ExpectedRevision < 1 || strings.TrimSpace(request.RequestID) == "" {
		return State{}, ErrInvalidInput
	}
	settings, err := contentrewrite.Normalize(request.Settings)
	if err != nil {
		return State{}, err
	}
	request.Settings = settings
	return s.store.Update(ctx, actor, request)
}

// Test runs draft settings with the site's real domains.
func (s *Service) Test(ctx context.Context, actor Actor, siteID uuid.UUID, request TestRequest) (contentrewrite.TestResult, error) {
	if !validActor(actor) || siteID == uuid.Nil || len(request.Body) > contentrewrite.MaxTestBody ||
		request.Path == "" || request.Path[0] != '/' || len(request.Path) > 2048 {
		return contentrewrite.TestResult{}, ErrInvalidInput
	}
	settings, err := contentrewrite.Normalize(request.Settings)
	if err != nil {
		return contentrewrite.TestResult{}, err
	}
	state, err := s.store.Get(ctx, actor, siteID)
	if err != nil {
		return contentrewrite.TestResult{}, err
	}
	return contentrewrite.Test(settings, state.Domains, request.Path, request.ContentType, []byte(request.Body))
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}
