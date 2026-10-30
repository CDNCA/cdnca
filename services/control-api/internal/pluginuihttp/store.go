// Package pluginuihttp serves ui_page plugin pages to the web app (PA-19,
// ADR 0007 §8.3): the page list for menus and mounts, the CSP frame-src
// origins nginx reads before index.html, and the restricted proxy a page
// uses (through the host's postMessage bridge) to call its own backend.
//
// No plugin code runs here: pages are served from the plugin's own https
// origin into a sandboxed iframe. The proxy never forwards the user's
// session or token; it sends a context the control plane signs with the
// installation key under its own domain.
package pluginuihttp

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/pluginui"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Page is one mounted page as the web app sees it.
type Page struct {
	PluginID           string         `json:"plugin_id"`
	PluginVersion      string         `json:"plugin_version"`
	PageID             string         `json:"page_id"`
	Origin             string         `json:"origin"`
	URL                string         `json:"url"`
	Mount              string         `json:"mount"`
	MenuParent         string         `json:"menu_parent,omitempty"`
	Role               string         `json:"role"`
	Title              pluginui.Title `json:"title"`
	RequiredPermission string         `json:"required_permission,omitempty"`
	RequiredModule     string         `json:"required_module,omitempty"`
	HasAPI             bool           `json:"has_api"`
}

// ActivePlugin is an enabled ui_page plugin.
type ActivePlugin struct {
	Declaration     pluginui.Declaration
	TenantScopeID   uuid.UUID
	AuthorizationID uuid.UUID
}

// Store reads plugin_ui_pages (migration 386).
type Store interface {
	ActivePlugins(context.Context) ([]ActivePlugin, error)
}

// PostgresStore is the production Store.
type PostgresStore struct{ Pool *pgxpool.Pool }

func (store PostgresStore) ActivePlugins(ctx context.Context) ([]ActivePlugin, error) {
	if store.Pool == nil {
		return nil, errors.New("plugin ui store is not configured")
	}
	rows, err := store.Pool.Query(ctx, `SELECT declaration::text,tenant_scope_id,authorization_id FROM plugin_ui_pages
		WHERE status='active' ORDER BY plugin_id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ActivePlugin, error) {
		var raw string
		var plugin ActivePlugin
		if err := row.Scan(&raw, &plugin.TenantScopeID, &plugin.AuthorizationID); err != nil {
			return ActivePlugin{}, err
		}
		// jsonb normalizes key order and spacing: decode, then rebuild the
		// canonical form to re-validate what is served.
		var stored pluginui.Declaration
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return ActivePlugin{}, err
		}
		declaration, _, err := pluginui.Build(stored.PluginID, stored.Version, stored.Permissions, pluginui.Entrypoint{
			Type: pluginui.EntrypointType, Origin: stored.Origin, APIBaseURL: stored.APIBaseURL, Pages: stored.Pages})
		if err != nil {
			return ActivePlugin{}, err
		}
		plugin.Declaration = declaration
		return plugin, nil
	})
}

// CSPOrigins is the frame-src list: the origin of every enabled ui_page
// plugin, sorted and space-separated (nothing else ever enters).
func CSPOrigins(plugins []ActivePlugin) string {
	origins := make([]string, 0, len(plugins))
	seen := map[string]bool{}
	for _, plugin := range plugins {
		origin, ok := pluginui.CanonicalOrigin(plugin.Declaration.Origin)
		if ok && !seen[origin] {
			origins = append(origins, origin)
			seen[origin] = true
		}
	}
	sort.Strings(origins)
	return strings.Join(origins, " ")
}

// PagesFor lists the pages a principal may see: the page role matches the
// principal's (platform scope = admin), and its permission / module gates
// hold (platform.admin does not bypass a plugin page's permission: the
// plugin asked for that permission explicitly).
func PagesFor(plugins []ActivePlugin, role string, permissions, modules []string) []Page {
	has := func(values []string, value string) bool {
		for _, candidate := range values {
			if candidate == value {
				return true
			}
		}
		return false
	}
	out := []Page{}
	for _, plugin := range plugins {
		declaration := plugin.Declaration
		for _, page := range declaration.Pages {
			if page.Role != role || page.RequiredPermission != "" && !has(permissions, page.RequiredPermission) ||
				page.RequiredModule != "" && !has(modules, page.RequiredModule) {
				continue
			}
			out = append(out, Page{PluginID: declaration.PluginID, PluginVersion: declaration.Version, PageID: page.ID,
				Origin: declaration.Origin, URL: declaration.Origin + page.Path, Mount: page.Mount, MenuParent: page.MenuParent,
				Role: page.Role, Title: page.Title, RequiredPermission: page.RequiredPermission,
				RequiredModule: page.RequiredModule, HasAPI: declaration.APIBaseURL != ""})
		}
	}
	return out
}
