package sitetheme

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
)

// v2Package is the wire form of cdnca.site-theme/v2.
type v2Package struct {
	Schema        string          `json:"schema"`
	ID            string          `json:"id"`
	Version       string          `json:"version"`
	Name          I18nText        `json:"name"`
	Description   I18nText        `json:"description,omitempty"`
	AppliesTo     []Scope         `json:"applies_to"`
	ConsoleTheme  json.RawMessage `json:"console_theme,omitempty"`
	SiteBundle    *v2Bundle       `json:"site_bundle,omitempty"`
	AuthStyle     *v2AuthStyle    `json:"auth_style,omitempty"`
	ContentSchema []Field         `json:"content_schema,omitempty"`
	// Preview is the theme card's screenshot, base64 (png/jpeg/webp).
	Preview *string `json:"preview,omitempty"`
}

type v2Bundle struct {
	Entry string   `json:"entry,omitempty"`
	Files []v2File `json:"files"`
}

type v2File struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"data_base64"`
}

type v2AuthStyle struct {
	CSS    string            `json:"css"`
	Images map[string]string `json:"images,omitempty"`
}

// scopeOrder is the normalized order of AppliesTo.
var scopeOrder = []Scope{ScopeAdmin, ScopeUser, ScopeSite}

// thirdPartyScopes / officialScopes are the accepted applies_to sets, keyed
// by their normalized "+"-joined form.
var (
	thirdPartyScopes = map[string]bool{"user+site": true, "user": true, "site": true}
	officialScopes   = map[string]bool{"user+site": true, "user": true, "site": true,
		"admin": true, "admin+user": true, "admin+user+site": true}
)

func parseV2(raw []byte, opt ParseOptions) (*Theme, error) {
	var pkg v2Package
	if err := decodeStrict(raw, &pkg); err != nil {
		return nil, err
	}
	switch {
	case !ValidV1ID(pkg.ID):
		return nil, invalid("id", "id")
	case !versionPattern.MatchString(pkg.Version):
		return nil, invalid("version", "version")
	}
	if err := checkPublisherID(pkg.ID, opt.Publisher); err != nil {
		return nil, err
	}
	if err := validI18n(pkg.Name, 64, true, "name"); err != nil {
		return nil, err
	}
	if err := validI18n(pkg.Description, 512, false, "description"); err != nil {
		return nil, err
	}
	scopes, err := normalizeScopes(pkg.AppliesTo, opt.Publisher)
	if err != nil {
		return nil, err
	}
	theme := &Theme{Schema: SchemaV2, ID: pkg.ID, Version: pkg.Version, Name: pkg.Name, Description: pkg.Description,
		AppliesTo: scopes}
	if bytes.Equal(bytes.TrimSpace(pkg.ConsoleTheme), []byte("null")) {
		pkg.ConsoleTheme = nil
	}
	console := theme.Allows(ScopeAdmin) || theme.Allows(ScopeUser)
	switch {
	case console && len(pkg.ConsoleTheme) == 0:
		return nil, invalid("console_theme_required", "console_theme")
	case !console && len(pkg.ConsoleTheme) != 0:
		return nil, invalid("console_theme_unexpected", "console_theme")
	case theme.Allows(ScopeSite) && pkg.SiteBundle == nil:
		return nil, invalid("site_bundle_required", "site_bundle")
	case !theme.Allows(ScopeSite) && pkg.SiteBundle != nil:
		return nil, invalid("site_bundle_unexpected", "site_bundle")
	case !theme.Allows(ScopeSite) && pkg.ContentSchema != nil:
		return nil, invalid("content_schema_unexpected", "content_schema")
	}
	if console {
		if err := checkConsole(pkg.ConsoleTheme, opt.Publisher, theme.Allows(ScopeAdmin)); err != nil {
			return nil, err
		}
		theme.Console = append([]byte(nil), pkg.ConsoleTheme...)
	}
	if pkg.SiteBundle != nil {
		if theme.Bundle, err = parseBundle(*pkg.SiteBundle); err != nil {
			return nil, err
		}
	}
	if pkg.AuthStyle != nil {
		if theme.AuthStyle, err = parseAuthStyle(*pkg.AuthStyle); err != nil {
			return nil, err
		}
	}
	if pkg.ContentSchema != nil {
		if err := validateFields(pkg.ContentSchema, "content_schema", true); err != nil {
			return nil, err
		}
		theme.ContentSchema = pkg.ContentSchema
	}
	if pkg.Preview != nil {
		if theme.Preview, err = parsePreview(*pkg.Preview); err != nil {
			return nil, err
		}
	}
	return theme, nil
}

// normalizeScopes checks applies_to: known, unique, and one of the sets the
// publisher may declare. A third party may never declare admin.
func normalizeScopes(values []Scope, publisher Publisher) ([]Scope, error) {
	seen := map[Scope]bool{}
	for index, value := range values {
		field := "applies_to[" + strconv.Itoa(index) + "]"
		if value != ScopeAdmin && value != ScopeUser && value != ScopeSite {
			return nil, invalid("applies_to", field)
		}
		if seen[value] {
			return nil, invalid("applies_to", field)
		}
		seen[value] = true
	}
	scopes := make([]Scope, 0, len(seen))
	key := ""
	for _, scope := range scopeOrder {
		if seen[scope] {
			scopes = append(scopes, scope)
			if key != "" {
				key += "+"
			}
			key += string(scope)
		}
	}
	if publisher != PublisherOfficial {
		if seen[ScopeAdmin] {
			return nil, invalid("admin_forbidden", "applies_to")
		}
		if !thirdPartyScopes[key] {
			return nil, invalid("applies_to", "applies_to")
		}
		return scopes, nil
	}
	if !officialScopes[key] {
		return nil, invalid("applies_to", "applies_to")
	}
	return scopes, nil
}

// consoleScopeKeys are the keys under which a console theme could name the
// consoles it targets; any "admin" value under them is an admin scope.
var consoleScopeKeys = map[string]bool{"scope": true, "scopes": true, "role": true, "roles": true, "applies_to": true}

// checkConsole verifies console_theme is a JSON object of schema
// cdnca.theme/v1 and, unless the theme is an official one that applies to
// the admin console, carries no admin tokens (tokens_by_role.admin), admin
// scope, or admin role selector. Everything else is the caller's
// (libs/themepack).
func checkConsole(raw json.RawMessage, publisher Publisher, adminDeclared bool) error {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return invalid("console_theme", "console_theme")
	}
	var schema string
	if json.Unmarshal(value["schema"], &schema) != nil || schema != ConsoleSchema {
		return invalid("console_theme_schema", "console_theme.schema")
	}
	if publisher == PublisherOfficial && adminDeclared {
		return nil
	}
	code := "console_admin"
	if publisher != PublisherOfficial {
		code = "admin_forbidden"
	}
	if roles, ok := value["tokens_by_role"]; ok {
		var byRole map[string]json.RawMessage
		if json.Unmarshal(roles, &byRole) != nil {
			return invalid("console_theme", "console_theme.tokens_by_role")
		}
		if _, ok := byRole[string(ScopeAdmin)]; ok {
			return invalid(code, "console_theme.tokens_by_role.admin")
		}
	}
	if field := findAdmin(raw, "console_theme"); field != "" {
		return invalid(code, field)
	}
	return nil
}

// findAdmin walks a JSON value and returns the path of the first admin
// scope: an "admin" value (or element) under a scope-like key, or a string
// that selects the admin console (data-cdnca-role ... admin).
func findAdmin(raw json.RawMessage, field string) string {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return field
	}
	return walkAdmin(value, field, false)
}

func walkAdmin(value any, field string, scopeKey bool) string {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if found := walkAdmin(v[key], field+"."+key, consoleScopeKeys[key]); found != "" {
				return found
			}
		}
	case []any:
		for index, item := range v {
			if found := walkAdmin(item, field+"["+strconv.Itoa(index)+"]", scopeKey); found != "" {
				return found
			}
		}
	case string:
		if scopeKey && containsAdminWord(v) {
			return field
		}
		if adminRoleSelector.MatchString(v) {
			return field
		}
	}
	return ""
}

var adminWord = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])admin(?:$|[^a-z0-9_])`)

// containsAdminWord matches "admin", "admin+user", "user,admin", ... but not
// "administrator" or "sysadmin".
func containsAdminWord(value string) bool { return adminWord.MatchString(value) }
