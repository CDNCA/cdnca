package theme

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/brandasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrPermissionDenied  = errors.New("theme permission denied")
	ErrNotFound          = errors.New("theme not found")
	ErrRevisionConflict  = errors.New("theme activation revision conflict")
	ErrEntitlementDenied = errors.New("theme entitlement denied")
	ErrInvalidRequest    = errors.New("invalid theme request")
	ErrActivePackage     = errors.New("the active theme package cannot be removed")
	ErrUnavailable       = errors.New("theme service unavailable")
	// ErrAdminSlotOfficialOnly: only an official theme may restyle the admin console.
	ErrAdminSlotOfficialOnly = errors.New("only an official theme may be active on the admin console")
	requestIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	permissionRead           = "system_configuration.read"
	permissionManage         = "system_configuration.manage"
	auditResourceType        = "theme_package"
	maxListedPackages        = 200
	uploadedThemeIDPrefix    = "custom."
)

// Audit actions (BATCH-PLUGIN §10, <category>.<object>.<action>). Until the
// unified-log event catalog lands, ip and changes ride in Payload.
const (
	ActionDownload = "plugin.theme.download"
	ActionUpload   = "plugin.theme.upload"
	ActionActivate = "plugin.theme.activate"
	ActionRemove   = "plugin.theme.remove"
)

// AuditEventCatalog registers the theme events and their plain-language
// templates (fields come from the event only) for the unified-log catalog.
var AuditEventCatalog = []struct {
	Action, Category, TemplateZH, TemplateEN string
}{
	{ActionDownload, "plugin", "管理员 {actor} 在 {time} 从 {ip} 下载了主题「{theme_id}」{version}", "Admin {actor} downloaded theme {theme_id} {version} from {ip} at {time}"},
	{ActionUpload, "plugin", "管理员 {actor} 在 {time} 从 {ip} 上传了主题「{theme_id}」{version}", "Admin {actor} uploaded theme {theme_id} {version} from {ip} at {time}"},
	{ActionActivate, "plugin", "管理员 {actor} 在 {time} 从 {ip} 把平台主题从「{changes.theme_id.from}」切换为「{changes.theme_id.to}」", "Admin {actor} switched the platform theme from {changes.theme_id.from} to {changes.theme_id.to} from {ip} at {time}"},
	{ActionRemove, "plugin", "管理员 {actor} 在 {time} 从 {ip} 删除了已下载的主题「{theme_id}」{version}", "Admin {actor} removed downloaded theme {theme_id} {version} from {ip} at {time}"},
	{edgepublish.ThemeRepublicationAudit, "site", "系统在 {time} 因启用主题「{theme_id}」为 {scope_count} 个租户重新发布错误页", "The system republished error pages of {scope_count} tenants at {time} after theme {theme_id} was activated"},
}

// FeatureGuard is entitlementguard.Guard's feature check.
type FeatureGuard interface {
	CheckFeature(context.Context, pgx.Tx, entitlementguard.FeatureCheck) (entitlementguard.FeatureDecision, error)
}

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

// Actor is a platform administrator; IP is the resolved client address
// ("" when unknown) recorded in audit events.
type Actor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ScopeKind string
	IP        string
	RequestID string
}

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	guard   FeatureGuard
	catalog []CatalogEntry
	now     func() time.Time
}

func NewService(pool *pgxpool.Pool, auditor AuditAppender, guard FeatureGuard, catalog []CatalogEntry, now func() time.Time) (*Service, error) {
	if pool == nil || auditor == nil || now == nil || len(catalog) == 0 {
		return nil, ErrUnavailable
	}
	for _, entry := range catalog {
		if entry.RequiresFeature != "" && (guard == nil || FeatureCode(entry.ID) == "" || entry.RequiresFeature != FeatureCode(entry.ID)) {
			return nil, ErrUnavailable
		}
	}
	return &Service{pool: pool, auditor: auditor, guard: guard, catalog: catalog, now: now}, nil
}

// PackageView is a downloaded package.
type PackageView struct {
	PackageSHA256   string    `json:"package_sha256"`
	ThemeID         string    `json:"theme_id"`
	Version         string    `json:"version"`
	Name            I18nText  `json:"name"`
	Description     I18nText  `json:"description,omitempty"`
	Source          string    `json:"source"`
	RequiresFeature string    `json:"requires_feature,omitempty"`
	DownloadedAt    time.Time `json:"downloaded_at"`
	Active          bool      `json:"active"`
	TokensURL       string    `json:"tokens_url"`
	StylesheetURL   string    `json:"stylesheet_url"`
	// DerivedFrom is the package a customized theme was edited from.
	DerivedFrom *themepack.DerivedFrom `json:"derived_from,omitempty"`
	// PreviewURL is the screenshot of the theme plugin that carries this
	// console theme (same image as the plugin's card); absent otherwise.
	PreviewURL string `json:"preview_url,omitempty"`
}

// PluginPreviewPath serves a theme plugin's preview by sha256 (the public,
// immutable website image route of controlsite).
const PluginPreviewPath = "/v1/control-site/assets/"

// AvailableView is a catalog theme with its download state.
type AvailableView struct {
	ThemeID         string   `json:"theme_id"`
	Version         string   `json:"version"`
	Name            I18nText `json:"name"`
	Description     I18nText `json:"description,omitempty"`
	PackageSHA256   string   `json:"package_sha256"`
	RequiresFeature string   `json:"requires_feature,omitempty"`
	Downloaded      bool     `json:"downloaded"`
}

type CatalogView struct {
	Schema             string `json:"schema"`
	ActivationRevision int64  `json:"activation_revision"`
	ActivePackage      string `json:"active_package_sha256"`
	// UserPackage is the package the user console shows (its latest user or
	// all activation; "" before any): the user tab tells a plain
	// cdnca.theme/v1 package chosen there apart from "follows official" (F2).
	UserPackage string          `json:"user_package_sha256"`
	Available   []AvailableView `json:"available"`
	Packages    []PackageView   `json:"packages"`
	// ErrorPageRepublication is the latest activation's automatic error page
	// republication to the tenants.
	ErrorPageRepublication edgepublish.ThemeRepublicationProgress `json:"error_page_republication"`
}

// ActivationResult reports the new activation. ErrorPagePublicationRevision is
// the error page revision that pins the theme (ADR 0007 §7.3); the system
// republishes it to ErrorPageRepublishScopes tenant scopes (every scope that
// has published error pages), so node default error pages follow the theme
// without a tenant publish. AlreadyActive: the package was already the active
// theme and nothing changed.
type ActivationResult struct {
	Revision                     int64  `json:"revision"`
	PackageSHA256                string `json:"package_sha256"`
	ThemeID                      string `json:"theme_id"`
	ErrorPagePublicationRevision int64  `json:"error_page_publication_revision"`
	ErrorPageRepublishScopes     int    `json:"error_page_republish_scopes"`
	AlreadyActive                bool   `json:"already_active,omitempty"`
	// Slot is the console the activation applies to: all, admin or user.
	Slot string `json:"slot,omitempty"`
}

// Current is the public pointer to the active theme's immutable files.
type Current struct {
	Schema        string `json:"schema"`
	Revision      int64  `json:"revision"`
	ThemeID       string `json:"theme_id"`
	Version       string `json:"version"`
	PackageSHA256 string `json:"package_sha256"`
	TokensURL     string `json:"tokens_url"`
	StylesheetURL string `json:"stylesheet_url"`
	// Scope is "platform" or "tenant" (a tenant's own theme, PA-26): brand
	// images the platform uploaded apply only to the platform theme.
	Scope string `json:"scope"`
	// BrandAssets maps each slot the platform uploaded to its revision; empty
	// for a tenant's own theme. The page requests /v1/brand-assets/<slot>?v=
	// <revision> only for these slots, so a missing upload costs no 404.
	BrandAssets map[string]int64 `json:"brand_assets"`
	// AuthStyleURL names the sign-in page style (GET, JSON {css, images}) of
	// the theme plugin active on the user console; absent without one.
	AuthStyleURL string `json:"auth_style_url,omitempty"`
}

// AuthStylePath is the public route of the sign-in page style.
const AuthStylePath = "/v1/theme/auth-style"

// AuthStyle is the sign-in page look of the theme plugin whose console theme
// the user console shows (site theme C): CSS that the console puts in a
// <style> of its own on /auth/* and the plugin's images. The forms stay the
// platform's; the page CSP allows images, fonts and requests from 'self' only.
type AuthStyle struct {
	CSS    string            `json:"css"`
	Images map[string]string `json:"images"`
}

// UserAuthStyle returns the active user console plugin's sign-in style (an
// empty style when none applies).
func (s *Service) UserAuthStyle(ctx context.Context) (AuthStyle, error) {
	style := AuthStyle{Images: map[string]string{}}
	user, err := slotPackage(ctx, s.pool, SlotUser)
	if err != nil || user == "" {
		return style, err
	}
	digest, _ := hex.DecodeString(user)
	var themeID string
	var css *string
	err = s.pool.QueryRow(ctx, `SELECT theme_id,auth_css FROM site_theme_packages WHERE console_package_sha256=$1 AND
		installed_at IS NOT NULL AND auth_css IS NOT NULL ORDER BY theme_id LIMIT 1`, digest).Scan(&themeID, &css)
	if errors.Is(err, pgx.ErrNoRows) {
		return style, nil
	}
	if err != nil {
		return AuthStyle{}, fmt.Errorf("read sign-in style: %w", ErrUnavailable)
	}
	style.CSS = *css
	// Slot "preview" is the theme card's screenshot, not a sign-in image.
	rows, err := s.pool.Query(ctx, `SELECT slot,encode(image_sha256,'hex') FROM site_theme_images WHERE theme_id=$1 AND slot<>'preview'
		ORDER BY slot`, themeID)
	if err != nil {
		return AuthStyle{}, fmt.Errorf("read sign-in style images: %w", ErrUnavailable)
	}
	defer rows.Close()
	for rows.Next() {
		var slot, sha string
		if err := rows.Scan(&slot, &sha); err != nil {
			return AuthStyle{}, err
		}
		style.Images[slot] = AuthStylePath + "/assets/" + sha
	}
	return style, rows.Err()
}

// AuthStyleAsset returns one image of an installed plugin's sign-in style.
func (s *Service) AuthStyleAsset(ctx context.Context, sha string) (string, []byte, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != sha {
		return "", nil, ErrNotFound
	}
	var mime string
	var body []byte
	err = s.pool.QueryRow(ctx, `SELECT image.mime_type,image.body FROM site_theme_images image
		JOIN site_theme_packages plugin ON plugin.theme_id=image.theme_id AND plugin.auth_css IS NOT NULL
		WHERE image.image_sha256=$1 AND image.slot<>'preview' LIMIT 1`, digest).Scan(&mime, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("read sign-in style image: %w", ErrUnavailable)
	}
	return mime, body, nil
}

const CurrentSchema = "cdnca.theme.current/v1"

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.ScopeKind == "platform" &&
		requestIDPattern.MatchString(actor.RequestID)
}

func (s *Service) Catalog(ctx context.Context, actor Actor) (CatalogView, error) {
	if !validActor(actor) {
		return CatalogView{}, ErrPermissionDenied
	}
	view := CatalogView{Schema: "cdnca.theme.catalog/v1", Available: []AvailableView{}, Packages: []PackageView{}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		revision, active, err := activeActivation(ctx, tx)
		if err != nil {
			return err
		}
		view.ActivationRevision = revision
		view.ActivePackage = active
		if view.UserPackage, err = slotPackage(ctx, tx, SlotUser); err != nil {
			return err
		}
		if active == "" {
			view.ActivePackage = DefaultRendered().PackageSHA256
		}
		if view.ErrorPageRepublication, err = edgepublish.ThemeRepublicationProgressTx(ctx, tx); err != nil {
			return err
		}
		// A console theme a theme plugin carries shows the plugin's preview.
		rows, err := tx.Query(ctx, `SELECT pkg.package_sha256,pkg.theme_id,pkg.version,pkg.source,pkg.requires_feature,
			pkg.package_body,pkg.css_sha256,pkg.json_sha256,pkg.downloaded_at,
			(SELECT encode(image.image_sha256,'hex') FROM site_theme_packages plugin JOIN site_theme_images image
				ON image.theme_id=plugin.theme_id AND image.slot='preview'
				WHERE plugin.console_package_sha256=pkg.package_sha256 ORDER BY plugin.theme_id LIMIT 1)
			FROM theme_packages pkg WHERE pkg.removed_at IS NULL ORDER BY pkg.downloaded_at DESC, pkg.package_sha256 LIMIT $1`,
			maxListedPackages)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var digest, body, css, tokens []byte
			var preview *string
			var item PackageView
			if err := rows.Scan(&digest, &item.ThemeID, &item.Version, &item.Source, &item.RequiresFeature, &body, &css, &tokens, &item.DownloadedAt,
				&preview); err != nil {
				return err
			}
			if preview != nil {
				item.PreviewURL = PluginPreviewPath + *preview
			}
			pkg, err := Parse(body)
			if err != nil {
				return ErrUnavailable
			}
			item.PackageSHA256 = hex.EncodeToString(digest)
			item.Name, item.Description, item.DerivedFrom = pkg.Name, pkg.Description, pkg.DerivedFrom
			item.Active = item.PackageSHA256 == view.ActivePackage
			item.DownloadedAt = item.DownloadedAt.UTC()
			item.StylesheetURL, item.TokensURL = StylesheetPath(hex.EncodeToString(css)), TokensPath(hex.EncodeToString(tokens))
			view.Packages = append(view.Packages, item)
		}
		return rows.Err()
	})
	if err != nil {
		return CatalogView{}, fmt.Errorf("list themes: %w", err)
	}
	for _, entry := range s.catalog {
		pkg, err := Parse(entry.Raw)
		if err != nil {
			return CatalogView{}, ErrUnavailable
		}
		digest := sha256.Sum256(entry.Raw)
		item := AvailableView{ThemeID: entry.ID, Version: pkg.Version, Name: pkg.Name, Description: pkg.Description,
			PackageSHA256: hex.EncodeToString(digest[:]), RequiresFeature: entry.RequiresFeature}
		for _, downloaded := range view.Packages {
			item.Downloaded = item.Downloaded || downloaded.PackageSHA256 == item.PackageSHA256
		}
		view.Available = append(view.Available, item)
	}
	return view, nil
}

func (s *Service) catalogEntry(id string) (CatalogEntry, bool) {
	for _, entry := range s.catalog {
		if entry.ID == id {
			return entry, true
		}
	}
	return CatalogEntry{}, false
}

// Download stores a catalog theme ("downloaded", not active).
func (s *Service) Download(ctx context.Context, actor Actor, themeID string) (PackageView, error) {
	entry, ok := s.catalogEntry(themeID)
	if !ok {
		return PackageView{}, ErrNotFound
	}
	return s.store(ctx, actor, entry.Raw, "builtin", entry.RequiresFeature, ActionDownload)
}

// Upload stores an operator's own theme package (id custom.*). Failures are
// *ValidationError (ErrInvalidPackage) and are audited.
func (s *Service) Upload(ctx context.Context, actor Actor, raw []byte) (PackageView, error) {
	return s.store(ctx, actor, raw, "upload", "", ActionUpload)
}

func (s *Service) store(ctx context.Context, actor Actor, raw []byte, source, feature, action string) (PackageView, error) {
	if !validActor(actor) {
		return PackageView{}, ErrPermissionDenied
	}
	rendered, err := Render(raw)
	if err == nil && (source == "upload") != strings.HasPrefix(rendered.Package.ID, uploadedThemeIDPrefix) {
		err = invalid("id", "id")
	}
	if err != nil {
		s.auditFailure(ctx, actor, action, "", map[string]any{"reason": failureReason(err)})
		return PackageView{}, err
	}
	var view PackageView
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		digest, _ := hex.DecodeString(rendered.PackageSHA256)
		tag, err := tx.Exec(ctx, `UPDATE theme_packages SET removed_at=NULL,removed_by_user_id=NULL
			WHERE package_sha256=$1 AND removed_at IS NOT NULL`, digest)
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT true FROM theme_packages WHERE package_sha256=$1`, digest).Scan(&exists); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if from := rendered.Package.DerivedFrom; from != nil {
			if _, _, err := s.derivedSource(ctx, tx, from); err != nil {
				return err
			}
		}
		if !exists {
			if err := insertRendered(ctx, tx, rendered, source, feature, actor.UserID, now); err != nil {
				return err
			}
		}
		var downloadedAt time.Time
		if err := tx.QueryRow(ctx, `SELECT downloaded_at FROM theme_packages WHERE package_sha256=$1`, digest).Scan(&downloadedAt); err != nil {
			return err
		}
		_, active, err := activeActivation(ctx, tx)
		if err != nil {
			return err
		}
		view = PackageView{PackageSHA256: rendered.PackageSHA256, ThemeID: rendered.Package.ID, Version: rendered.Package.Version,
			Name: rendered.Package.Name, Description: rendered.Package.Description, Source: source, RequiresFeature: feature,
			DownloadedAt: downloadedAt.UTC(), Active: active == rendered.PackageSHA256,
			StylesheetURL: StylesheetPath(rendered.CSSSHA256), TokensURL: TokensPath(rendered.JSONSHA256),
			DerivedFrom: rendered.Package.DerivedFrom}
		return s.auditor.Append(ctx, tx, s.event(actor, action, rendered.PackageSHA256, "success", map[string]any{
			"theme_id": rendered.Package.ID, "version": rendered.Package.Version, "source": source,
			"already_downloaded": exists && tag.RowsAffected() == 0,
		}))
	})
	if err != nil {
		s.auditFailure(ctx, actor, action, rendered.PackageSHA256, map[string]any{"theme_id": rendered.Package.ID, "reason": failureReason(err)})
		return PackageView{}, fmt.Errorf("store theme package: %w", err)
	}
	return view, nil
}

func insertRendered(ctx context.Context, tx pgx.Tx, rendered Rendered, source, feature string, userID uuid.UUID, now time.Time) error {
	digest, _ := hex.DecodeString(rendered.PackageSHA256)
	body := rendered.Raw
	if _, err := tx.Exec(ctx, `INSERT INTO theme_packages(package_sha256,theme_id,version,source,requires_feature,package_body,
		css_sha256,css_body,json_sha256,json_body,downloaded_by_user_id,downloaded_at)
		VALUES($1,$2,$3,$4,$5,$6,sha256($7::bytea),$7,sha256($8::bytea),$8,$9,$10)`,
		digest, rendered.Package.ID, rendered.Package.Version, source, feature, body, rendered.CSS, rendered.JSON, userID, now); err != nil {
		return err
	}
	for _, asset := range rendered.Assets {
		assetDigest, _ := hex.DecodeString(asset.SHA256)
		if _, err := tx.Exec(ctx, `INSERT INTO theme_assets(asset_sha256,mime_type,body) VALUES($1,$2,$3) ON CONFLICT (asset_sha256) DO NOTHING`,
			assetDigest, asset.MIMEType, asset.Body); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO theme_package_assets(package_sha256,slot,asset_sha256) VALUES($1,$2,$3)`,
			digest, asset.Slot, assetDigest); err != nil {
			return err
		}
	}
	for _, page := range rendered.ErrorPages {
		if _, err := tx.Exec(ctx, `INSERT INTO theme_error_pages(package_sha256,category,status_code,body_sha256,body)
			VALUES($1,$2,$3,sha256($4::bytea),$4)`, digest, page.Category, page.Status, page.Body); err != nil {
			return err
		}
	}
	return nil
}

// StoreMarketPackageTx keeps a theme bought on the plugin market (PA-18,
// theme id market.<plugin id>) as a downloaded package, source market, in
// the caller's transaction. It never activates anything. A package an
// administrator removed stays removed. It reports whether a row was added.
func StoreMarketPackageTx(ctx context.Context, tx pgx.Tx, raw []byte, pluginID string, userID uuid.UUID, now time.Time) (Rendered, bool, error) {
	rendered, err := Render(raw)
	if err != nil {
		return Rendered{}, false, err
	}
	if rendered.Package.ID != themepack.MarketThemeID(pluginID) {
		return Rendered{}, false, invalid("id", "id")
	}
	digest, _ := hex.DecodeString(rendered.PackageSHA256)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM theme_packages WHERE package_sha256=$1)`, digest).Scan(&exists); err != nil {
		return Rendered{}, false, err
	}
	if exists {
		return rendered, false, nil
	}
	if err := insertRendered(ctx, tx, rendered, sourceMarket, "", userID, now.UTC().Truncate(time.Microsecond)); err != nil {
		return Rendered{}, false, err
	}
	return rendered, true, nil
}

const sourceMarket = "market"

// marketWithdrawn reports a market theme whose plugin authorization this
// installation no longer has (ADR 0007 §9): it stays downloaded but cannot
// be activated.
func marketWithdrawn(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, themeID string) (bool, error) {
	if !strings.HasPrefix(themeID, themepack.MarketThemePrefix) {
		return false, nil
	}
	var withdrawn bool
	err := q.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM market_data_pack_sources
		WHERE kind='market_theme' AND local_name=$1 AND status='active')`, themeID).Scan(&withdrawn)
	return withdrawn, err
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// derivedSource resolves the package a customized theme names: a package
// this installation downloaded (removed or not) or a catalog theme, with the
// same id and version. It returns the source's theme id and license feature,
// which a customized copy inherits: editing a paid or market theme never
// frees it. An unknown source is a validation error.
func (s *Service) derivedSource(ctx context.Context, q rowQuerier, from *themepack.DerivedFrom) (string, string, error) {
	digest, err := hex.DecodeString(from.PackageSHA256)
	if err != nil || len(digest) != sha256.Size {
		return "", "", invalid("derived_from", "derived_from.package_sha256")
	}
	var themeID, version, feature string
	err = q.QueryRow(ctx, `SELECT theme_id,version,requires_feature FROM theme_packages WHERE package_sha256=$1`, digest).Scan(&themeID, &version, &feature)
	if errors.Is(err, pgx.ErrNoRows) {
		found := false
		for _, entry := range s.catalog {
			if sum := sha256.Sum256(entry.Raw); hex.EncodeToString(sum[:]) == from.PackageSHA256 {
				pkg, parseErr := Parse(entry.Raw)
				if parseErr != nil {
					return "", "", ErrUnavailable
				}
				themeID, version, feature, found = pkg.ID, pkg.Version, entry.RequiresFeature, true
			}
		}
		if !found {
			return "", "", invalid("derived_from", "derived_from.package_sha256")
		}
	} else if err != nil {
		return "", "", err
	}
	if themeID != from.ID || version != from.Version {
		return "", "", invalid("derived_from", "derived_from")
	}
	return themeID, feature, nil
}

// licenseOf returns the theme id and license feature activation checks for
// a package: its own, or its source's for a customized copy.
func (s *Service) licenseOf(ctx context.Context, q rowQuerier, themeID, feature string, body []byte) (string, string, error) {
	pkg, err := Parse(body)
	if err != nil {
		return "", "", ErrUnavailable
	}
	if pkg.DerivedFrom == nil {
		return themeID, feature, nil
	}
	return s.derivedSource(ctx, q, pkg.DerivedFrom)
}

// Activate makes a downloaded package the active theme of both consoles.
// expected is the activation revision the caller saw (0 = none yet).
func (s *Service) Activate(ctx context.Context, actor Actor, packageSHA256 string, expected int64) (ActivationResult, error) {
	return s.ActivateSlot(ctx, actor, packageSHA256, expected, SlotAll)
}

// ActivateSlot activates a package on one console (admin or user) or both
// (all). Only an official theme may be active on the admin console (all
// includes it): a built-in or uploaded package, or a market theme of the
// official namespace; a third party's market theme is refused there
// (ErrAdminSlotOfficialOnly) and is a user console theme only. The node
// error pages follow the admin console theme, so a user-only activation
// republishes nothing.
func (s *Service) ActivateSlot(ctx context.Context, actor Actor, packageSHA256 string, expected int64, slot string) (ActivationResult, error) {
	if !validActor(actor) {
		return ActivationResult{}, ErrPermissionDenied
	}
	digest, err := hex.DecodeString(packageSHA256)
	if err != nil || len(digest) != sha256.Size || expected < 0 || (slot != SlotAll && slot != SlotAdmin && slot != SlotUser) {
		return ActivationResult{}, ErrInvalidRequest
	}
	var themeID, feature string
	var body []byte
	if err := s.pool.QueryRow(ctx, `SELECT theme_id,requires_feature,package_body FROM theme_packages WHERE package_sha256=$1 AND removed_at IS NULL`, digest).
		Scan(&themeID, &feature, &body); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.auditFailure(ctx, actor, ActionActivate, packageSHA256, map[string]any{"reason": "not_downloaded"})
			return ActivationResult{}, ErrNotFound
		}
		return ActivationResult{}, fmt.Errorf("read theme package: %w", err)
	}
	licenseID, feature, err := s.licenseOf(ctx, s.pool, themeID, feature, body)
	if err != nil {
		s.auditFailure(ctx, actor, ActionActivate, packageSHA256, map[string]any{"theme_id": themeID, "reason": failureReason(err)})
		return ActivationResult{}, fmt.Errorf("read theme source: %w", err)
	}
	if withdrawn, err := marketWithdrawn(ctx, s.pool, licenseID); err != nil {
		return ActivationResult{}, fmt.Errorf("read market theme authorization: %w", err)
	} else if withdrawn {
		s.auditFailure(ctx, actor, ActionActivate, packageSHA256, map[string]any{"theme_id": themeID, "reason": "market_authorization_withdrawn"})
		return ActivationResult{}, ErrEntitlementDenied
	}
	if slot != SlotUser && !OfficialConsoleTheme(licenseID) {
		s.auditFailure(ctx, actor, ActionActivate, packageSHA256, map[string]any{"theme_id": themeID, "slot": slot,
			"reason": "admin_slot_official_only"})
		return ActivationResult{}, ErrAdminSlotOfficialOnly
	}
	if feature != "" {
		// The guard records its own denial audit; commit it on denial.
		denied := false
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := authorize(ctx, tx, actor, permissionManage); err != nil {
				return err
			}
			resource := uuid.NewSHA1(uuid.NameSpaceURL, digest)
			_, checkErr := s.guard.CheckFeature(ctx, tx, entitlementguard.FeatureCheck{
				TargetScopeID: actor.ScopeID, ActorScopeID: actor.ScopeID, ActorUserID: actor.UserID,
				ResourceType: auditResourceType, ResourceID: resource, RequestID: actor.RequestID,
				Operation: ActionActivate, Feature: feature,
			})
			if checkErr != nil && entitlementguard.IsDenial(checkErr) {
				denied = true
				return nil
			}
			return checkErr
		})
		if err != nil {
			return ActivationResult{}, fmt.Errorf("check theme entitlement: %w", err)
		}
		if denied {
			s.auditFailure(ctx, actor, ActionActivate, packageSHA256, map[string]any{"theme_id": themeID, "reason": "entitlement_feature_denied", "feature": feature})
			return ActivationResult{}, ErrEntitlementDenied
		}
	}
	var result ActivationResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('theme-activation',0))`); err != nil {
			return err
		}
		revision, previous, err := activeActivation(ctx, tx)
		if err != nil {
			return err
		}
		adminChanges := slot != SlotUser
		if !adminChanges {
			if previous, err = slotPackage(ctx, tx, SlotUser); err != nil {
				return err
			}
		}
		already := previous == packageSHA256
		if slot == SlotAll && already {
			// all is in effect only when the user console shows it too.
			user, err := slotPackage(ctx, tx, SlotUser)
			if err != nil {
				return err
			}
			already = user == packageSHA256
		}
		if already {
			// Activating the active theme again changes nothing: no new
			// activation, no second republication.
			var publicationRevision int64
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0) FROM error_page_publications`).Scan(&publicationRevision); err != nil {
				return err
			}
			result = ActivationResult{Revision: revision, PackageSHA256: packageSHA256, ThemeID: themeID,
				ErrorPagePublicationRevision: publicationRevision, AlreadyActive: true}
			return nil
		}
		if revision != expected {
			return ErrRevisionConflict
		}
		previousID := DefaultThemeID
		if previous != "" {
			previousDigest, _ := hex.DecodeString(previous)
			if err := tx.QueryRow(ctx, `SELECT theme_id FROM theme_packages WHERE package_sha256=$1`, previousDigest).Scan(&previousID); err != nil {
				return err
			}
		} else {
			previous = DefaultRendered().PackageSHA256
		}
		var removed bool
		if err := tx.QueryRow(ctx, `SELECT removed_at IS NOT NULL FROM theme_packages WHERE package_sha256=$1 FOR SHARE`, digest).Scan(&removed); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if removed {
			return ErrNotFound
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if _, err := tx.Exec(ctx, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at,slot)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, revision+1, actor.ScopeID, digest, actor.UserID, actor.RequestID, now, slot); err != nil {
			return err
		}
		if !adminChanges {
			result = ActivationResult{Revision: revision + 1, PackageSHA256: packageSHA256, ThemeID: themeID, Slot: slot}
			return s.auditor.Append(ctx, tx, s.event(actor, ActionActivate, packageSHA256, "success", map[string]any{
				"theme_id": themeID, "activation_revision": result.Revision, "slot": slot,
				"changes": map[string]any{
					"theme_id":       map[string]any{"from": previousID, "to": themeID},
					"package_sha256": map[string]any{"from": previous, "to": packageSHA256},
				},
			}))
		}
		// Queued before the error page publication lock: the worker locks a
		// scope's head before it (edgepublish.QueueThemeErrorPageRepublicationTx).
		scopes, err := edgepublish.QueueThemeErrorPageRepublicationTx(ctx, tx, s.auditor, edgepublish.ThemeErrorPageRepublication{
			ActivationRevision: revision + 1, ThemeID: themeID, PackageSHA256: packageSHA256,
			PlatformScopeID: actor.ScopeID, RequestID: actor.RequestID, ActorIP: actor.IP,
		})
		if err != nil {
			return fmt.Errorf("queue theme error page republication: %w", err)
		}
		publication, err := errorpagecontrol.AppendThemePublication(ctx, tx, actor.UserID, actor.ScopeID, actor.RequestID, actor.RequestID, now)
		if err != nil {
			return fmt.Errorf("record theme error page publication: %w", err)
		}
		result = ActivationResult{Revision: revision + 1, PackageSHA256: packageSHA256, ThemeID: themeID,
			ErrorPagePublicationRevision: publication.Policy.Revision, ErrorPageRepublishScopes: scopes, Slot: slot}
		return s.auditor.Append(ctx, tx, s.event(actor, ActionActivate, packageSHA256, "success", map[string]any{
			"theme_id": themeID, "activation_revision": result.Revision, "slot": slot,
			"error_page_publication_revision": result.ErrorPagePublicationRevision,
			"error_page_republish_scopes":     scopes,
			"changes": map[string]any{
				"theme_id":       map[string]any{"from": previousID, "to": themeID},
				"package_sha256": map[string]any{"from": previous, "to": packageSHA256},
			},
		}))
	})
	if err != nil {
		s.auditFailure(ctx, actor, ActionActivate, packageSHA256, map[string]any{"theme_id": themeID, "reason": failureReason(err)})
		return ActivationResult{}, fmt.Errorf("activate theme: %w", err)
	}
	return result, nil
}

// PackageBody returns the exact cdnca.theme/v1 JSON of a package this
// installation stored (removed or not) or a catalog theme, so the theme management page can edit a copy of it
// (customize). Requires system_configuration.read.
func (s *Service) PackageBody(ctx context.Context, actor Actor, packageSHA256 string) ([]byte, error) {
	if !validActor(actor) {
		return nil, ErrPermissionDenied
	}
	digest, err := hex.DecodeString(packageSHA256)
	if err != nil || len(digest) != sha256.Size {
		return nil, ErrInvalidRequest
	}
	var body []byte
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		// Removed rows too: a customized theme's older source stays readable
		// for the three-way merge after the source is upgraded.
		err := tx.QueryRow(ctx, `SELECT package_body FROM theme_packages WHERE package_sha256=$1`, digest).Scan(&body)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if errors.Is(err, ErrNotFound) {
		for _, entry := range s.catalog {
			if sum := sha256.Sum256(entry.Raw); hex.EncodeToString(sum[:]) == packageSHA256 {
				return bytes.Clone(entry.Raw), nil
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read theme package: %w", err)
	}
	return body, nil
}

// Remove marks a downloaded, inactive package removed. Rows stay (error page
// publications pin packages by digest); a removed package can be downloaded
// again.
func (s *Service) Remove(ctx context.Context, actor Actor, packageSHA256 string) error {
	if !validActor(actor) {
		return ErrPermissionDenied
	}
	digest, err := hex.DecodeString(packageSHA256)
	if err != nil || len(digest) != sha256.Size {
		return ErrInvalidRequest
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('theme-activation',0))`); err != nil {
			return err
		}
		var themeID, version string
		if err := tx.QueryRow(ctx, `SELECT theme_id,version FROM theme_packages WHERE package_sha256=$1 AND removed_at IS NULL FOR UPDATE`, digest).
			Scan(&themeID, &version); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		_, active, err := activeActivation(ctx, tx)
		if err != nil {
			return err
		}
		if active == packageSHA256 {
			return ErrActivePackage
		}
		if _, err := tx.Exec(ctx, `UPDATE theme_packages SET removed_at=$2,removed_by_user_id=$3 WHERE package_sha256=$1`,
			digest, s.now().UTC().Truncate(time.Microsecond), actor.UserID); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, s.event(actor, ActionRemove, packageSHA256, "success", map[string]any{
			"theme_id": themeID, "version": version,
		}))
	})
	if err != nil {
		s.auditFailure(ctx, actor, ActionRemove, packageSHA256, map[string]any{"reason": failureReason(err)})
		return fmt.Errorf("remove theme package: %w", err)
	}
	return nil
}

// CurrentRequest says whose theme to resolve: a signed-in platform
// administrator (admin console theme), else the user console theme. The
// community edition has no tenant themes (white label removed).
type CurrentRequest struct {
	// Platform: a signed-in platform administrator (admin console theme).
	Platform bool
}

// Current returns the theme pointer for request: the admin or user console
// theme (the default before any activation).
func (s *Service) Current(ctx context.Context, request CurrentRequest) (Current, error) {
	var resolved effective
	var err error
	if request.Platform {
		resolved, err = platformTheme(ctx, s.pool)
	} else {
		// Tenant users and signed-out pages (sign-in, sign-up, recovery): the user console theme.
		resolved, err = slotTheme(ctx, s.pool, SlotUser)
	}
	if err != nil {
		return Current{}, fmt.Errorf("read current theme: %w", ErrUnavailable)
	}
	current := Current{Schema: CurrentSchema, Revision: resolved.Revision, ThemeID: resolved.ThemeID, Version: resolved.Version,
		PackageSHA256: resolved.PackageSHA256, TokensURL: TokensPath(resolved.JSONSHA256),
		StylesheetURL: StylesheetPath(resolved.CSSSHA256), Scope: "platform", BrandAssets: map[string]int64{}}
	uploaded, err := brandasset.PublicRevisions(ctx, s.pool)
	if err != nil {
		return Current{}, fmt.Errorf("read uploaded brand assets: %w", ErrUnavailable)
	}
	for slot, revision := range uploaded {
		current.BrandAssets[string(slot)] = revision
	}
	// The sign-in pages are the user console's: name its plugin style for
	// every caller except a signed-in platform administrator.
	if !request.Platform {
		if style, err := s.UserAuthStyle(ctx); err == nil && style.CSS != "" {
			current.AuthStyleURL = AuthStylePath
		}
	}
	return current, nil
}

// File kinds served by digest.
const (
	FileStylesheet = "css"
	FileTokens     = "json"
)

// File returns an immutable rendered file by content digest. The default
// theme's files are served even before it is downloaded.
func (s *Service) File(ctx context.Context, kind, sha string) ([]byte, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != sha {
		return nil, ErrNotFound
	}
	rendered := DefaultRendered()
	if kind == FileStylesheet && sha == rendered.CSSSHA256 {
		return rendered.CSS, nil
	}
	if kind == FileTokens && sha == rendered.JSONSHA256 {
		return rendered.JSON, nil
	}
	query := `SELECT css_body FROM theme_packages WHERE css_sha256=$1 LIMIT 1`
	if kind == FileTokens {
		query = `SELECT json_body FROM theme_packages WHERE json_sha256=$1 LIMIT 1`
	} else if kind != FileStylesheet {
		return nil, ErrNotFound
	}
	var body []byte
	if err := s.pool.QueryRow(ctx, query, digest).Scan(&body); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("read theme file: %w", ErrUnavailable)
	}
	return body, nil
}

// Asset returns a theme brand image by digest.
func (s *Service) Asset(ctx context.Context, sha string) (string, []byte, error) {
	digest, err := hex.DecodeString(sha)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != sha {
		return "", nil, ErrNotFound
	}
	var mime string
	var body []byte
	if err := s.pool.QueryRow(ctx, `SELECT mime_type,body FROM theme_assets WHERE asset_sha256=$1`, digest).Scan(&mime, &body); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, ErrNotFound
		}
		return "", nil, fmt.Errorf("read theme asset: %w", ErrUnavailable)
	}
	return mime, body, nil
}

// activeActivation returns the latest activation revision (any slot) and
// the admin console's package: the latest admin or all activation. Error
// pages, mail and tenant fallbacks follow the admin (platform) theme, as
// they did when one theme served both consoles.
func activeActivation(ctx context.Context, tx pgx.Tx) (int64, string, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0) FROM theme_activations`).Scan(&revision); err != nil {
		return 0, "", err
	}
	digest, err := slotPackage(ctx, tx, SlotAdmin)
	return revision, digest, err
}

// ActivateUserTx activates a downloaded console theme on the user console
// only, in the caller's transaction (the website theme plugin page enables a
// plugin's console theme there). packageSHA256 "" activates the admin
// console's theme (or the default) for the user console again. Any theme
// may be the user console's, a third party's too; nothing is republished
// (node error pages follow the admin console).
func ActivateUserTx(ctx context.Context, tx pgx.Tx, auditor AuditAppender, scopeID, userID uuid.UUID, packageSHA256, requestID string,
	now time.Time) error {
	if !requestIDPattern.MatchString(requestID) {
		return ErrInvalidRequest
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('theme-activation',0))`); err != nil {
		return err
	}
	revision, admin, err := activeActivation(ctx, tx)
	if err != nil {
		return err
	}
	if packageSHA256 == "" {
		packageSHA256 = admin
		if packageSHA256 == "" {
			// Before any activation the consoles show the default theme;
			// store it (downloaded) so the activation can reference it.
			rendered := DefaultRendered()
			defaultDigest, _ := hex.DecodeString(rendered.PackageSHA256)
			var stored bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM theme_packages WHERE package_sha256=$1)`, defaultDigest).Scan(&stored); err != nil {
				return err
			}
			if !stored {
				if err := insertRendered(ctx, tx, rendered, "builtin", "", userID, now); err != nil {
					return err
				}
			}
			packageSHA256 = rendered.PackageSHA256
		}
	}
	digest, err := hex.DecodeString(packageSHA256)
	if err != nil || len(digest) != sha256.Size {
		return ErrInvalidRequest
	}
	var themeID string
	if err := tx.QueryRow(ctx, `SELECT theme_id FROM theme_packages WHERE package_sha256=$1 AND removed_at IS NULL FOR SHARE`, digest).
		Scan(&themeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if withdrawn, err := marketWithdrawn(ctx, tx, themeID); err != nil {
		return err
	} else if withdrawn {
		return ErrEntitlementDenied
	}
	previous, err := slotPackage(ctx, tx, SlotUser)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at,slot)
		VALUES($1,$2,$3,$4,$5,$6,'user')`, revision+1, scopeID, digest, userID, requestID, now); err != nil {
		return err
	}
	return auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &userID, Action: ActionActivate,
		ResourceType: auditResourceType, ResourceID: packageSHA256, RequestID: requestID, Result: "success",
		Payload: map[string]any{"theme_id": themeID, "activation_revision": revision + 1, "slot": SlotUser, "scope": "platform",
			"changes": map[string]any{"package_sha256": map[string]any{"from": previous, "to": packageSHA256}}}})
}

// OfficialConsoleTheme reports a console theme that may restyle the admin
// console: built in, an administrator's own upload or customized copy, or a
// market theme of the official publisher namespace io.cdnca. themeID is the
// license source (licenseOf), so a customized copy of a third party's market
// theme stays third party.
func OfficialConsoleTheme(themeID string) bool {
	plugin, market := themepack.MarketThemePlugin(themeID)
	return !market || plugin == "io.cdnca" || strings.HasPrefix(plugin, "io.cdnca.")
}

// Console theme slots (migration 466): admin, user, or all (both).
const (
	SlotAdmin = "admin"
	SlotUser  = "user"
	SlotAll   = "all"
)

// slotPackage is the package active on one console ("" before any).
func slotPackage(ctx context.Context, q rowQuerier, slot string) (string, error) {
	var digest []byte
	err := q.QueryRow(ctx, `SELECT package_sha256 FROM theme_activations WHERE slot IN ($1,'all') ORDER BY revision DESC LIMIT 1`, slot).Scan(&digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

func (s *Service) event(actor Actor, action, resourceID, result string, payload map[string]any) audit.Event {
	payload["ip"] = actor.IP
	payload["scope"] = "platform"
	userID := actor.UserID
	if resourceID == "" {
		resourceID = "-"
	}
	return audit.Event{ScopeID: actor.ScopeID, ActorUserID: &userID, Action: action, ResourceType: auditResourceType,
		ResourceID: resourceID, RequestID: actor.RequestID, Result: result, Payload: payload}
}

// auditFailure records a failed operation in its own transaction (the
// operation's own transaction rolled back). Best effort: a failed audit write
// does not mask the original error.
func (s *Service) auditFailure(ctx context.Context, actor Actor, action, resourceID string, payload map[string]any) {
	if !validActor(actor) {
		return
	}
	_ = pgx.BeginFunc(context.WithoutCancel(ctx), s.pool, func(tx pgx.Tx) error {
		return s.auditor.Append(ctx, tx, s.event(actor, action, resourceID, "failure", payload))
	})
}

func failureReason(err error) string {
	var validation *ValidationError
	switch {
	case errors.As(err, &validation):
		return "invalid_package." + validation.Code
	case errors.Is(err, ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, ErrRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrActivePackage):
		return "active_package"
	case errors.Is(err, ErrEntitlementDenied):
		return "entitlement_feature_denied"
	case errors.Is(err, ErrAdminSlotOfficialOnly):
		return "admin_slot_official_only"
	case errors.Is(err, ErrInvalidRequest):
		return "invalid_request"
	default:
		return "unavailable"
	}
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil ||
		kind != "platform" || tenantID != nil {
		return ErrPermissionDenied
	}
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users account
		JOIN memberships membership ON membership.user_id=account.id AND membership.scope_id=$1 AND membership.status='active'
		JOIN role_assignments assignment ON assignment.user_id=account.id AND assignment.scope_id=$1
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions grant_row ON grant_row.role_id=role.id AND grant_row.permission_name IN ($3,'platform.admin')
		WHERE account.id=$2 AND account.status='active')`, actor.ScopeID, actor.UserID, permission).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// UserFollowsAdminTx reports whether the user console shows the admin
// console's theme (both unset counts). controlsite's "恢复官方主题" accepts
// any other user console theme, a plain cdnca.theme/v1 package too (F2).
func UserFollowsAdminTx(ctx context.Context, q rowQuerier) (bool, error) {
	user, err := slotPackage(ctx, q, SlotUser)
	if err != nil {
		return false, err
	}
	admin, err := slotPackage(ctx, q, SlotAdmin)
	if err != nil {
		return false, err
	}
	if admin == "" {
		// Before any admin activation the admin console shows the default
		// theme, which ActivateUserTx stores for a cleared user console.
		admin = DefaultRendered().PackageSHA256
	}
	return user == admin, nil
}

// querier is a pool or a transaction.
type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type effective struct {
	PackageSHA256 string
	ThemeID       string
	CSSSHA256     string
	JSONSHA256    string
	Version       string
	Revision      int64
}

// platformTheme is the active platform theme of the admin console (the
// default before any).
func platformTheme(ctx context.Context, q querier) (effective, error) {
	return slotTheme(ctx, q, SlotAdmin)
}

// slotTheme is the theme active on one console: the latest activation of
// the slot or of all (migration 466), else the default.
func slotTheme(ctx context.Context, q querier, slot string) (effective, error) {
	var result effective
	var digest, css, tokens []byte
	err := q.QueryRow(ctx, `SELECT activation.revision,package.theme_id,package.version,package.package_sha256,package.css_sha256,package.json_sha256
		FROM theme_activations activation JOIN theme_packages package ON package.package_sha256=activation.package_sha256
		WHERE activation.slot IN ($1,'all') ORDER BY activation.revision DESC LIMIT 1`, slot).Scan(&result.Revision, &result.ThemeID, &result.Version, &digest, &css, &tokens)
	if errors.Is(err, pgx.ErrNoRows) {
		rendered := DefaultRendered()
		return effective{PackageSHA256: rendered.PackageSHA256, ThemeID: rendered.Package.ID, Version: rendered.Package.Version,
			CSSSHA256: rendered.CSSSHA256, JSONSHA256: rendered.JSONSHA256}, nil
	}
	if err != nil {
		return effective{}, err
	}
	result.PackageSHA256, result.CSSSHA256, result.JSONSHA256 = hex.EncodeToString(digest), hex.EncodeToString(css), hex.EncodeToString(tokens)
	return result, nil
}
