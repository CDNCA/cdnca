package pluginuihttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/cdnca/cdnca/libs/entitlement/pluginui"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Stable reason codes of an unavailable plugin page. The platform session gets the specific state
// it can act on; a tenant only learns "the administrator has not enabled it for you" or "your account lacks the
// page permission", never whether the platform bought it.
const (
	ReasonNotLicensed      = "not_licensed"
	ReasonNotInstalled     = "not_installed"
	ReasonDisabled         = "disabled"
	ReasonUninstalled      = "uninstalled"
	ReasonPermissionDenied = "permission_denied"
	ReasonNotEnabled       = "not_enabled"
)

// Unavailable is a page this principal's role declares but cannot open now, and why.
type Unavailable struct {
	PluginID   string         `json:"plugin_id"`
	PageID     string         `json:"page_id"`
	Mount      string         `json:"mount"`
	MenuParent string         `json:"menu_parent,omitempty"`
	Title      pluginui.Title `json:"title"`
	Reason     string         `json:"reason"`
}

// KnownPlugin is a ui_page plugin this control plane holds a declaration for but does not serve: a withdrawn
// plugin_ui_pages row (or an active one whose local head is no longer enabled), or a plugin_ui catalog entry the
// license service lists that was never materialized here.
type KnownPlugin struct {
	Declaration pluginui.Declaration
	// Authorizations are the tenant-resource ui_page installation heads of the plugin, newest first.
	Authorizations []uuid.UUID
	// InstallStatus is the newest head's status (enabled, disabled, uninstalled), "" without a head.
	InstallStatus string
	// Licensed: the license service still serves the plugin_ui catalog entry.
	Licensed bool
}

// UnavailableSource is a Store that also lists the known plugins it does not serve. Without it the page list
// carries no reasons (every missing page is a plain not-found).
type UnavailableSource interface {
	KnownPlugins(context.Context) ([]KnownPlugin, error)
}

// UnavailableFor lists the pages of role that the principal cannot open, with a reason it may learn.
// active are the served plugins this principal is covered by (a tenant: installed for it); known the unserved
// ones; covers reports whether a known plugin's installation covers this principal (always true for the platform).
// Pages of another role, site tabs and plugins the principal may not confirm are left out: they stay not-found.
func UnavailableFor(active []ActivePlugin, known []KnownPlugin, role string, permissions, modules []string,
	covers func(KnownPlugin) bool) []Unavailable {
	out := []Unavailable{}
	add := func(declaration pluginui.Declaration, page pluginui.Page, reason string) {
		item := Unavailable{PluginID: declaration.PluginID, PageID: page.ID, Mount: page.Mount, Title: page.Title,
			Reason: reason}
		if page.Mount == pluginui.MountMenu {
			item.MenuParent = page.MenuParent
		}
		out = append(out, item)
	}
	openable := func(page pluginui.Page) bool {
		return page.Role == role && page.Mount != pluginui.MountSiteTab
	}
	served := map[string]bool{}
	for _, plugin := range active {
		served[plugin.Declaration.PluginID] = true
		for _, page := range plugin.Declaration.Pages {
			if !openable(page) {
				continue
			}
			moduleMissing := page.RequiredModule != "" && !slices.Contains(modules, page.RequiredModule)
			permissionMissing := page.RequiredPermission != "" && !slices.Contains(permissions, page.RequiredPermission)
			switch {
			case moduleMissing && role == pluginui.RoleAdmin:
				add(plugin.Declaration, page, ReasonNotLicensed)
			case moduleMissing:
				add(plugin.Declaration, page, ReasonNotEnabled)
			case permissionMissing:
				add(plugin.Declaration, page, ReasonPermissionDenied)
			}
		}
	}
	for _, plugin := range known {
		if served[plugin.Declaration.PluginID] || role != pluginui.RoleAdmin && !covers(plugin) {
			continue
		}
		reason := ReasonNotEnabled
		if role == pluginui.RoleAdmin {
			switch {
			case plugin.InstallStatus == "uninstalled":
				reason = ReasonUninstalled
			case plugin.InstallStatus == "disabled":
				reason = ReasonDisabled
			case !plugin.Licensed:
				reason = ReasonNotLicensed
			default:
				reason = ReasonNotInstalled
			}
		}
		for _, page := range plugin.Declaration.Pages {
			if openable(page) {
				add(plugin.Declaration, page, reason)
			}
		}
	}
	return out
}

// unavailable answers the reasons for the page list. They are hints: a failed read leaves them out (the pages
// then fall back to not-found) instead of failing the list the menu is built from.
func (h *Handler) unavailable(r *http.Request, current session, active []ActivePlugin) []Unavailable {
	var known []KnownPlugin
	if source, ok := h.config.Store.(UnavailableSource); ok {
		var err error
		if known, err = source.KnownPlugins(r.Context()); err != nil {
			known = nil
		}
	}
	coverage, scoped := h.config.Store.(TenantCoverage)
	covers := func(plugin KnownPlugin) bool {
		if current.principal.ScopeKind == "platform" || !scoped {
			return true
		}
		for _, authorization := range plugin.Authorizations {
			if covered, err := coverage.CoversTenant(r.Context(), authorization, current.principal.ScopeID); err == nil && covered {
				return true
			}
		}
		return false
	}
	return UnavailableFor(active, known, current.role, current.principal.Permissions, current.modules, covers)
}

func (store PostgresStore) KnownPlugins(ctx context.Context) ([]KnownPlugin, error) {
	if store.Pool == nil {
		return nil, errors.New("plugin ui store is not configured")
	}
	rows, err := store.Pool.Query(ctx, `SELECT known.declaration,known.content,heads.authorizations,heads.status,
		COALESCE(entry.status='active',false)
		FROM (SELECT page.plugin_id,page.declaration::text AS declaration,NULL::bytea AS content
		      FROM plugin_ui_pages page WHERE page.status='withdrawn' OR NOT EXISTS (SELECT 1 FROM plugin_installation_heads head
		            WHERE head.tenant_scope_id=page.tenant_scope_id AND head.authorization_id=page.authorization_id AND
		            head.status='enabled')
		      UNION ALL
		      SELECT substr(entry.artifact_id,11),NULL,object.content FROM artifact_catalog_entries entry
		      JOIN local_artifacts local ON local.artifact_id=entry.artifact_id AND local.current_revision IS NOT NULL
		      JOIN artifact_objects object ON object.sha256=local.current_sha256
		      WHERE entry.kind='plugin_ui' AND NOT EXISTS (SELECT 1 FROM plugin_ui_pages page
		            WHERE page.plugin_id=substr(entry.artifact_id,11))) known
		LEFT JOIN artifact_catalog_entries entry ON entry.artifact_id='plugin_ui/'||known.plugin_id
		LEFT JOIN LATERAL (SELECT array_agg(head.authorization_id ORDER BY head.updated_at DESC,head.authorization_id) AS authorizations,
		       (array_agg(head.status ORDER BY head.updated_at DESC,head.authorization_id))[1] AS status
		       FROM plugin_installation_heads head WHERE head.plugin_id=known.plugin_id AND head.resource_scope='tenant' AND
		       head.entrypoint_type='ui_page') heads ON true
		ORDER BY known.plugin_id`)
	if err != nil {
		return nil, err
	}
	type row struct {
		declaration *string
		content     []byte
		plugin      KnownPlugin
	}
	scanned, err := pgx.CollectRows(rows, func(collectable pgx.CollectableRow) (row, error) {
		var item row
		var status *string
		err := collectable.Scan(&item.declaration, &item.content, &item.plugin.Authorizations, &status, &item.plugin.Licensed)
		if status != nil {
			item.plugin.InstallStatus = *status
		}
		return item, err
	})
	if err != nil {
		return nil, err
	}
	out := make([]KnownPlugin, 0, len(scanned))
	for _, item := range scanned {
		// A declaration that no longer validates names no pages: skip it (its pages stay not-found).
		var declaration pluginui.Declaration
		if item.declaration != nil {
			var stored pluginui.Declaration
			if json.Unmarshal([]byte(*item.declaration), &stored) != nil {
				continue
			}
			declaration, _, err = pluginui.Build(stored.PluginID, stored.Version, stored.Permissions, pluginui.Entrypoint{
				Type: pluginui.EntrypointType, Origin: stored.Origin, APIBaseURL: stored.APIBaseURL, Pages: stored.Pages})
		} else {
			declaration, err = pluginui.Parse(item.content)
		}
		if err != nil {
			continue
		}
		item.plugin.Declaration = declaration
		out = append(out, item.plugin)
	}
	return out, nil
}
