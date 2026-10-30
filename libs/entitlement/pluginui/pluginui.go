// Package pluginui is the ui_page plugin declaration (PA-19, ADR 0007 §8.3):
// a C3 plugin that brings its own pages. The pages run on the developer's
// own https origin inside a sandboxed iframe of the control plane web app;
// no third-party code is served by, or runs in, the control plane.
//
// The same code checks the declaration at market upload and review, at
// license service manifest verification and when the control plane
// materializes it from the artifact catalog (plugin_ui/<plugin id>).
package pluginui

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// EntrypointType is spec.entrypoint.type of a plugin that brings pages.
	EntrypointType = "ui_page"
	// Schema is the declaration document served as artifact
	// plugin_ui/<plugin id>.
	Schema = "cdnca.plugin-ui/v1"
	// Permission is the consent permission every ui_page plugin declares
	// (what the installing administrator approves); a plugin may add the
	// permissions its backend needs through the control plane proxy.
	Permission = "platform.ui_pages.provide"

	MountMenu    = "menu"     // a menu item under MenuParent
	MountSiteTab = "site_tab" // a tab on the site detail page

	RoleAdmin = "admin"
	RoleUser  = "user"

	MaxPages = 16
	// MaxDocumentBytes bounds the canonical declaration.
	MaxDocumentBytes = 64 << 10
)

// MenuParents are the menu groups a page may be mounted under, per role
// (apps/web/src/routes/navigation.ts top-level keys).
var MenuParents = map[string]map[string]bool{
	RoleAdmin: {"monitor": true, "node": true, "site": true, "stream": true, "config": true, "package": true,
		"finance": true, "system": true},
	RoleUser: {"monitor": true, "site": true, "stream": true, "user-package": true, "account": true},
}

var (
	ErrInvalid = errors.New("invalid ui_page declaration")

	pageIDPattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	pagePathPattern   = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$`)
	permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){1,7}$`)
	modulePattern     = regexp.MustCompile(`^(module|pack|theme)\.[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$`)
	hostLabelPattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	pluginIDPattern   = regexp.MustCompile(`^[a-z0-9]+([.-][a-z0-9]+)+$`)
)

// Title is a localized page title (zh-CN required).
type Title struct {
	ZhCN string `json:"zh-CN"`
	EnUS string `json:"en-US,omitempty"`
}

// Page is one mounted page.
//   - Path is appended to the origin as the iframe src (no query/fragment).
//   - Mount menu: a menu item under MenuParent for Role; site_tab: an
//     "扩展" tab on the site detail page (Role admin or user).
//   - RequiredPermission / RequiredModule gate the menu item and the route
//     the same way as built-in pages (RBAC code / lease module code).
type Page struct {
	ID                 string `json:"id"`
	Path               string `json:"path"`
	Mount              string `json:"mount"`
	MenuParent         string `json:"menu_parent,omitempty"`
	Role               string `json:"role"`
	Title              Title  `json:"title"`
	RequiredPermission string `json:"required_permission,omitempty"`
	RequiredModule     string `json:"required_module,omitempty"`
}

// Entrypoint is spec.entrypoint of a ui_page manifest.
//   - Origin is the page origin (https://host, default port only). It goes
//     into the control plane CSP frame-src only while the plugin is enabled
//     on that installation.
//   - APIBaseURL (optional) is the plugin backend the control plane proxies
//     the page's restricted API calls to (https; same registrable trust as
//     the origin is not required, but it must be a verified publisher
//     origin too).
type Entrypoint struct {
	Type       string `json:"type"`
	Origin     string `json:"origin"`
	APIBaseURL string `json:"api_base_url,omitempty"`
	Pages      []Page `json:"pages"`
}

// Declaration is the artifact plugin_ui/<plugin id> the license service
// serves to authorized installations.
type Declaration struct {
	Schema      string   `json:"schema"`
	PluginID    string   `json:"plugin_id"`
	Version     string   `json:"version"`
	Origin      string   `json:"origin"`
	APIBaseURL  string   `json:"api_base_url"`
	Permissions []string `json:"permissions"`
	Pages       []Page   `json:"pages"`
}

// Finding is one structured validation failure.
type Finding struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Validate checks the entrypoint and returns every problem (nil = valid).
func Validate(entrypoint Entrypoint) []Finding {
	var out []Finding
	add := func(field, reason string) { out = append(out, Finding{Field: field, Reason: reason}) }
	if entrypoint.Type != EntrypointType {
		add("spec.entrypoint.type", "type_invalid")
	}
	if _, ok := CanonicalOrigin(entrypoint.Origin); !ok {
		add("spec.entrypoint.origin", "origin_invalid")
	}
	if entrypoint.APIBaseURL != "" {
		if _, ok := APIBase(entrypoint.APIBaseURL); !ok {
			add("spec.entrypoint.api_base_url", "api_base_url_invalid")
		}
	}
	if len(entrypoint.Pages) == 0 || len(entrypoint.Pages) > MaxPages {
		add("spec.entrypoint.pages", "pages_count")
	}
	seen := map[string]bool{}
	for index, page := range entrypoint.Pages {
		field := "spec.entrypoint.pages[" + itoa(index) + "]"
		if !pageIDPattern.MatchString(page.ID) || seen[page.ID] {
			add(field+".id", "page_id_invalid")
		}
		seen[page.ID] = true
		if !validPagePath(page.Path) {
			add(field+".path", "page_path_invalid")
		}
		if page.Role != RoleAdmin && page.Role != RoleUser {
			add(field+".role", "role_invalid")
		}
		switch page.Mount {
		case MountMenu:
			if !MenuParents[page.Role][page.MenuParent] {
				add(field+".menu_parent", "menu_parent_invalid")
			}
		case MountSiteTab:
			if page.MenuParent != "" {
				add(field+".menu_parent", "menu_parent_invalid")
			}
		default:
			add(field+".mount", "mount_invalid")
		}
		if !validTitle(page.Title) {
			add(field+".title", "title_invalid")
		}
		if page.RequiredPermission != "" && (len(page.RequiredPermission) > 128 ||
			!permissionPattern.MatchString(page.RequiredPermission) || page.RequiredPermission == "platform.admin") {
			add(field+".required_permission", "required_permission_invalid")
		}
		if page.RequiredModule != "" && (len(page.RequiredModule) > 128 || !modulePattern.MatchString(page.RequiredModule)) {
			add(field+".required_module", "required_module_invalid")
		}
	}
	return out
}

// CanonicalOrigin returns "https://host" for an https origin with a DNS
// host name (lowercase, no IP literal, no userinfo, port, path, query or
// fragment; a trailing "/" alone is tolerated and dropped).
func CanonicalOrigin(value string) (string, bool) {
	if value == "" || len(value) > 270 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Port() != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return "", false
	}
	host := parsed.Hostname()
	if !validHost(host) || parsed.Host != host {
		return "", false
	}
	return "https://" + host, true
}

// APIBase returns the canonical backend base URL: https, DNS host, default
// port, optional path without query/fragment, no trailing "/".
func APIBase(value string) (string, bool) {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Port() != "" {
		return "", false
	}
	host := parsed.Hostname()
	if !validHost(host) || parsed.Host != host {
		return "", false
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path != "" && !validPagePath(path) {
		return "", false
	}
	return "https://" + host + path, true
}

// Origin is the origin of a canonical API base URL.
func Origin(apiBase string) string {
	parsed, err := url.Parse(apiBase)
	if err != nil {
		return ""
	}
	return "https://" + parsed.Hostname()
}

// Build makes the canonical declaration of a valid entrypoint; permissions
// are the manifest's (canonical order).
func Build(pluginID, version string, permissions []string, entrypoint Entrypoint) (Declaration, []byte, error) {
	if findings := Validate(entrypoint); len(findings) > 0 || !pluginIDPattern.MatchString(pluginID) || version == "" {
		return Declaration{}, nil, ErrInvalid
	}
	origin, _ := CanonicalOrigin(entrypoint.Origin)
	apiBase := ""
	if entrypoint.APIBaseURL != "" {
		apiBase, _ = APIBase(entrypoint.APIBaseURL)
	}
	sorted := append([]string{}, permissions...)
	sort.Strings(sorted)
	pages := append([]Page{}, entrypoint.Pages...)
	sort.Slice(pages, func(i, j int) bool { return pages[i].ID < pages[j].ID })
	declaration := Declaration{Schema: Schema, PluginID: pluginID, Version: version, Origin: origin, APIBaseURL: apiBase,
		Permissions: sorted, Pages: pages}
	if declaration.Permissions == nil {
		declaration.Permissions = []string{}
	}
	encoded, err := json.Marshal(declaration)
	if err != nil || len(encoded) > MaxDocumentBytes {
		return Declaration{}, nil, ErrInvalid
	}
	return declaration, encoded, nil
}

// Parse decodes a declaration (strict, canonical) and re-validates it; the
// bytes must be exactly what Build produces.
func Parse(content []byte) (Declaration, error) {
	if len(content) == 0 || len(content) > MaxDocumentBytes {
		return Declaration{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var declaration Declaration
	if err := decoder.Decode(&declaration); err != nil {
		return Declaration{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Declaration{}, ErrInvalid
	}
	if declaration.Schema != Schema {
		return Declaration{}, ErrInvalid
	}
	rebuilt, encoded, err := Build(declaration.PluginID, declaration.Version, declaration.Permissions, Entrypoint{
		Type: EntrypointType, Origin: declaration.Origin, APIBaseURL: declaration.APIBaseURL, Pages: declaration.Pages})
	if err != nil || !bytes.Equal(encoded, content) {
		return Declaration{}, ErrInvalid
	}
	return rebuilt, nil
}

func validPagePath(value string) bool {
	if !pagePathPattern.MatchString(value) || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validTitle(title Title) bool {
	check := func(value string, required bool) bool {
		if value == "" {
			return !required
		}
		return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 32 && strings.TrimSpace(value) == value &&
			!strings.ContainsAny(value, "<>\r\n\t")
	}
	return check(title.ZhCN, true) && check(title.EnUS, false)
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || net.ParseIP(host) != nil || host == "localhost" ||
		strings.HasSuffix(host, ".localhost") || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
