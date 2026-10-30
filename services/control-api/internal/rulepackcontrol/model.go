// Package rulepackcontrol is the control plane side of rule packs (ADR 0007
// §5.4, PA-10/PA-11): the local artifacts ("下载" = canonical bytes kept
// here, never sent to a node by themselves), the enablement overrides
// (platform -> tenant -> site, pack and rule level, three states) and the
// resolved security.mounts of each site (ADR 0009 §8.4), computed by
// libs/rulepack — the same compiler the edge agent runs in its precheck.
//
// Node delivery is not wired yet (artifact set PA-01, site objects g8c):
// a published site mounts row is what those producers will read.
package rulepackcontrol

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput     = errors.New("invalid rule pack input")
	ErrNotFound         = errors.New("rule pack not found")
	ErrPermissionDenied = errors.New("rule pack permission denied")
	// ErrLocked: a level above does not allow this level to adjust the pack.
	ErrLocked = errors.New("rule pack is locked by an upper level")
	// ErrInUse: the artifact or pack is enabled at some level or mounted by a
	// published site; disable it first (deleting is never automatic).
	ErrInUse  = errors.New("rule pack is in use")
	ErrExists = errors.New("rule pack version already exists")
)

// ConflictError is a refused publication: the site's effective mounts
// conflict. It carries the full resolution for the page.
type ConflictError struct{ Resolution rulepack.Resolution }

func (e *ConflictError) Error() string { return "rule pack mounts conflict" }

// Actor is the authenticated caller. SourceIP and RequestID go into the
// audit events it causes.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	SourceIP  string
	RequestID string
	// system: the control plane itself (RecomputeDefaultOnMountsTx): sees
	// every site, has no user.
	system bool
}

func (a Actor) platform() bool { return a.system || a.ScopeKind == "platform" }

// DefaultOn reports whether a pack is enabled at platform level when it
// first arrives: every official free system pack (migration 454 started
// with the virtual patches; migration 544: all of
// them). Tenants and sites can still switch it off, the administrator can
// disable it for everyone.
func DefaultOn(layer rulepack.Layer, requiresFeature string) bool {
	return layer == rulepack.LayerSystem && requiresFeature == ""
}

type Version struct {
	Version          string     `json:"version"`
	Engine           string     `json:"engine"`
	EngineMinVersion int        `json:"engine_min_version"`
	SHA256           string     `json:"sha256"`
	SizeBytes        int        `json:"size_bytes"`
	Source           string     `json:"source"`
	State            string     `json:"state"`
	DownloadedAt     *time.Time `json:"downloaded_at"`
	CreatedAt        time.Time  `json:"created_at"`
}

// Pack is a pack as listed for a level: its versions, the current version's
// metadata and the inherited state at the requested level.
type Pack struct {
	PackID         string                        `json:"pack_id"`
	Layer          string                        `json:"layer"`
	OwnerScopeID   *uuid.UUID                    `json:"owner_scope_id"`
	CurrentVersion string                        `json:"current_version"`
	UpdatePolicy   string                        `json:"update_policy"`
	Name           string                        `json:"name"`
	Description    string                        `json:"description"`
	Engine         string                        `json:"engine"`
	Exports        []ExportedRule                `json:"exports"`
	ParamsSchema   map[string]rulepack.ParamSpec `json:"params_schema"`
	Defaults       rulepack.Params               `json:"defaults"`
	Requires       []string                      `json:"requires"`
	Cost           rulepack.Cost                 `json:"cost"`
	Versions       []Version                     `json:"versions"`
	Effect         *Effect                       `json:"effect"`
	UpdatedAt      time.Time                     `json:"updated_at"`
}

type ExportedRule struct {
	RuleID string `json:"rule_id"`
	Name   string `json:"name"`
}

// Effect is rulepack.Effect for the page.
type Effect struct {
	Enabled    bool                         `json:"enabled"`
	EnabledAt  rulepack.LevelRef            `json:"enabled_at"`
	Adjustable []rulepack.LevelRef          `json:"adjustable"`
	Priority   int                          `json:"priority"`
	Params     rulepack.Params              `json:"params"`
	RuleStates map[string]bool              `json:"rule_states"`
	RuleSource map[string]rulepack.LevelRef `json:"rule_source"`
	Ignored    int                          `json:"ignored_overrides"`
	// Inherited: what the level's "inherit" follows (the levels above
	// it), shown next to that option.
	Inherited bool `json:"inherited"`
}

// Override is one enablement row.
type Override struct {
	Level         rulepack.Level  `json:"level"`
	LevelObjectID *uuid.UUID      `json:"level_object_id"`
	PackID        string          `json:"pack_id"`
	RuleID        string          `json:"rule_id"`
	State         rulepack.State  `json:"state"`
	AllowLower    bool            `json:"allow_lower"`
	Priority      *int            `json:"priority"`
	Params        rulepack.Params `json:"params"`
	// UpdatedBy is nil on the control plane's own row opening an official
	// pack to lower levels (migration 418).
	UpdatedBy *uuid.UUID `json:"updated_by_user_id"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// OverrideInput sets one row (state inherit with nothing else = delete).
type OverrideInput struct {
	Level         rulepack.Level  `json:"level"`
	LevelObjectID *uuid.UUID      `json:"level_object_id"`
	PackID        string          `json:"pack_id"`
	RuleID        string          `json:"rule_id"`
	State         rulepack.State  `json:"state"`
	AllowLower    bool            `json:"allow_lower"`
	Priority      *int            `json:"priority"`
	Params        json.RawMessage `json:"params"`
}

// LevelView is the page of one level: every visible pack with its inherited
// state there and the rows of that level.
type LevelView struct {
	Level     rulepack.LevelRef `json:"level"`
	Packs     []Pack            `json:"packs"`
	Overrides []Override        `json:"overrides"`
}

// SiteMounts is the published state of a site next to its live resolution.
type SiteMounts struct {
	SiteID     uuid.UUID           `json:"site_id"`
	Published  *PublishedMounts    `json:"published"`
	Resolution rulepack.Resolution `json:"resolution"`
	UpToDate   bool                `json:"up_to_date"`
	// Suspended are the site's mounts suspended because its CRS profile no
	// longer covers them (suspend.go); Resolution leaves them out.
	Suspended []Suspension `json:"suspended"`
}

type PublishedMounts struct {
	Revision    int64             `json:"revision"`
	Security    rulepack.Security `json:"security"`
	PublishedAt time.Time         `json:"published_at"`
	// PublishedBy is nil when the control plane recomputed the mounts itself
	// (default-on official pack, migration 454).
	PublishedBy *uuid.UUID `json:"published_by_user_id"`
}
