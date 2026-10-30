// Package theme implements the declarative theme package cdnca.theme/v1
// (ADR 0007 §7): whitelisted tokens, brand slots, layout slots and logic-less
// templates for error pages and notification email. The control plane renders
// a package into static theme.<sha>.css and theme.<sha>.json served same-origin;
// a theme never carries or runs script and never changes any CSP.
package themepack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	PackageSchema  = "cdnca.theme/v1"
	RenderedSchema = "cdnca.theme.rendered/v1"
	MaxPackageSize = 8 << 20
	MaxAssetSize   = 2 << 20
	DefaultThemeID = "default"
)

var (
	ErrInvalidPackage  = errors.New("invalid theme package")
	themeIDPattern     = regexp.MustCompile(`^(default|official\.[a-z][a-z0-9-]{0,31}|custom\.[a-z][a-z0-9-]{0,31}|market\.[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+)$`)
	marketThemePattern = regexp.MustCompile(`^market\.([a-z][a-z0-9]*(?:[.-][a-z0-9]+)+)$`)
	versionPattern     = regexp.MustCompile(`^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$`)
	localePattern      = map[string]struct{}{"zh-CN": {}, "zh-TW": {}, "en-US": {}}
	forbiddenFragments = []string{"url(", "@import", "expression(", "javascript:", "<script", "<link", "<iframe", "<object", "<embed", "src=", "href=", "srcset="}
)

// MarketThemePrefix starts the id of a theme sold on the plugin market:
// market.<plugin id> (PA-18).
const MarketThemePrefix = "market."

// MarketThemeID is the theme id a market plugin's theme package must carry.
func MarketThemeID(pluginID string) string { return MarketThemePrefix + pluginID }

// MarketThemePlugin returns the plugin id of a market theme id.
func MarketThemePlugin(themeID string) (string, bool) {
	match := marketThemePattern.FindStringSubmatch(themeID)
	if match == nil || len(themeID) > 128 {
		return "", false
	}
	return match[1], true
}

// ValidationError names what made a package invalid; Field is a JSON path.
type ValidationError struct {
	Code  string `json:"code"`
	Field string `json:"field,omitempty"`
}

func (err *ValidationError) Error() string {
	if err.Field == "" {
		return "theme package invalid: " + err.Code
	}
	return fmt.Sprintf("theme package invalid: %s at %s", err.Code, err.Field)
}

func (err *ValidationError) Unwrap() error { return ErrInvalidPackage }

func invalid(code, field string) error { return &ValidationError{Code: code, Field: field} }

// I18nText maps locale to text; zh-CN is required.
type I18nText map[string]string

type Package struct {
	Schema      string                     `json:"schema"`
	ID          string                     `json:"id"`
	Version     string                     `json:"version"`
	Name        I18nText                   `json:"name"`
	Description I18nText                   `json:"description,omitempty"`
	Tokens      map[string]json.RawMessage `json:"tokens,omitempty"`
	// TokensByRole overrides tokens for one console only ("admin" or
	// "user"); the CSS lands on :root[data-cdnca-theme][data-cdnca-role=…].
	TokensByRole map[string]map[string]json.RawMessage `json:"tokens_by_role,omitempty"`
	BrandSlots   map[string]BrandSlot                  `json:"brand_slots,omitempty"`
	Layout       Layout                                `json:"layout_slots"`
	Templates    *Templates                            `json:"templates,omitempty"`
	// DerivedFrom names the package a custom theme was edited from (theme
	// management "customize"). Only custom.* packages carry it.
	DerivedFrom *DerivedFrom `json:"derived_from,omitempty"`
}

// DerivedFrom is the source package of a customized theme: its id, version
// and package digest. The source keeps its own row; the control plane applies
// the source's license and market checks to the copy.
type DerivedFrom struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	PackageSHA256 string `json:"package_sha256"`
}

var packageDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type BrandSlot struct {
	MIMEType   string `json:"mime_type"`
	BodyBase64 string `json:"body_base64"`
}

type Layout struct {
	LoginLayout string       `json:"login_layout"`
	Sidebar     string       `json:"sidebar"`
	HeaderLinks []HeaderLink `json:"header_links,omitempty"`
	FooterText  I18nText     `json:"footer_text,omitempty"`
	// BrandName is the product name the consoles and sign-in page show (PA-26
	// white label); the SPA falls back to "cdnca" when it is absent.
	BrandName I18nText `json:"brand_name,omitempty"`
	UserHome  []string `json:"user_home_blocks,omitempty"`
	// Look picks the SPA's structural style set ("classic" by default,
	// "tech" for the console-like look); Motion its animation level.
	Look   string `json:"look,omitempty"`
	Motion string `json:"motion,omitempty"`
}

type HeaderLink struct {
	Label I18nText `json:"label"`
	URL   string   `json:"url"`
}

type Templates struct {
	Styles    []StyleRule `json:"styles"`
	ErrorPage string      `json:"error_page"`
	Email     string      `json:"email"`
}

// StyleRule is one rule of the theme stylesheet. A value "token:<name>" takes
// the token's CSS text; any other value is literal. Both must fit the
// errorpagestyle grammar for the property.
type StyleRule struct {
	Selector     string            `json:"selector"`
	Declarations map[string]string `json:"declarations"`
}

var (
	loginLayouts   = []string{"split", "centered", "background"}
	sidebarModes   = []string{"light", "dark"}
	looks          = []string{"classic", "tech"}
	motions        = []string{"off", "subtle", "rich"}
	UserHomeBlocks = []string{"profile", "network", "monitoring", "top", "notices", "package_traffic", "usage"}
)

// Parse decodes and validates a package. It rejects unknown fields, duplicate
// keys, trailing data and any string carrying an external reference.
func Parse(raw []byte) (Package, error) {
	if len(raw) == 0 || len(raw) > MaxPackageSize || !utf8.Valid(raw) {
		return Package{}, invalid("package_size", "")
	}
	if err := edgeconfig.RejectDuplicateJSONKeys(raw); err != nil {
		return Package{}, invalid("package_json", "")
	}
	if err := scanStrings(raw); err != nil {
		return Package{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var pkg Package
	if err := decoder.Decode(&pkg); err != nil {
		return Package{}, invalid("package_json", "")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Package{}, invalid("package_json", "")
	}
	if err := pkg.validate(); err != nil {
		return Package{}, err
	}
	return pkg, nil
}

func (pkg Package) validate() error {
	if pkg.Schema != PackageSchema {
		return invalid("schema", "schema")
	}
	if !themeIDPattern.MatchString(pkg.ID) {
		return invalid("id", "id")
	}
	if !versionPattern.MatchString(pkg.Version) {
		return invalid("version", "version")
	}
	if err := validateI18n(pkg.Name, 64, true, "name"); err != nil {
		return err
	}
	if err := validateI18n(pkg.Description, 512, false, "description"); err != nil {
		return err
	}
	if source := pkg.DerivedFrom; source != nil {
		switch {
		case !strings.HasPrefix(pkg.ID, "custom."):
			return invalid("derived_from", "derived_from")
		case !themeIDPattern.MatchString(source.ID) || len(source.ID) > 128:
			return invalid("derived_from", "derived_from.id")
		case !versionPattern.MatchString(source.Version):
			return invalid("derived_from", "derived_from.version")
		case !packageDigestPattern.MatchString(source.PackageSHA256):
			return invalid("derived_from", "derived_from.package_sha256")
		}
	}
	if !oneOf(pkg.Layout.LoginLayout, loginLayouts) {
		return invalid("layout_value", "layout_slots.login_layout")
	}
	if !oneOf(pkg.Layout.Sidebar, sidebarModes) {
		return invalid("layout_value", "layout_slots.sidebar")
	}
	if pkg.Layout.Look != "" && !oneOf(pkg.Layout.Look, looks) {
		return invalid("layout_value", "layout_slots.look")
	}
	if pkg.Layout.Motion != "" && !oneOf(pkg.Layout.Motion, motions) {
		return invalid("layout_value", "layout_slots.motion")
	}
	if len(pkg.Layout.HeaderLinks) > 8 {
		return invalid("layout_value", "layout_slots.header_links")
	}
	for index, link := range pkg.Layout.HeaderLinks {
		field := fmt.Sprintf("layout_slots.header_links[%d]", index)
		if err := validateI18n(link.Label, 32, true, field+".label"); err != nil {
			return err
		}
		if !validHeaderURL(link.URL) {
			return invalid("header_link_url", field+".url")
		}
	}
	if err := validateI18n(pkg.Layout.FooterText, 256, false, "layout_slots.footer_text"); err != nil {
		return err
	}
	if err := validateI18n(pkg.Layout.BrandName, 64, false, "layout_slots.brand_name"); err != nil {
		return err
	}
	seenBlocks := make(map[string]struct{})
	for index, block := range pkg.Layout.UserHome {
		if _, duplicate := seenBlocks[block]; duplicate || !oneOf(block, UserHomeBlocks) {
			return invalid("layout_value", fmt.Sprintf("layout_slots.user_home_blocks[%d]", index))
		}
		seenBlocks[block] = struct{}{}
	}
	return nil
}

func validateI18n(text I18nText, maxRunes int, required bool, field string) error {
	if len(text) == 0 {
		if required {
			return invalid("i18n_required", field)
		}
		return nil
	}
	if _, ok := text["zh-CN"]; !ok {
		return invalid("i18n_required", field+".zh-CN")
	}
	for locale, value := range text {
		if _, ok := localePattern[locale]; !ok {
			return invalid("i18n_locale", field+"."+locale)
		}
		if value == "" || utf8.RuneCountInString(value) > maxRunes || strings.TrimSpace(value) != value {
			return invalid("i18n_value", field+"."+locale)
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return invalid("i18n_value", field+"."+locale)
			}
		}
	}
	return nil
}

func validHeaderURL(value string) bool {
	if len(value) > 512 || !strings.HasPrefix(value, "https://") {
		return false
	}
	host := strings.TrimPrefix(value, "https://")
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if host == "" || strings.ContainsAny(host, "@:") {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r == '"' || r == '\'' || r == '<' || r == '>' || r == '\\' || r == '`' || r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func oneOf(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// scanStrings decodes every JSON string (so \u escapes cannot hide anything)
// and rejects external references anywhere except header link URLs, which
// validHeaderURL checks, and base64 image bodies. A theme loads nothing from
// outside the control plane.
func scanStrings(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return invalid("package_json", "")
	}
	return scanValue(document, "")
}

func scanValue(value any, field string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			next := key
			if field != "" {
				next = field + "." + key
			}
			if err := scanValue(child, next); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := scanValue(child, field+"[]"); err != nil {
				return err
			}
		}
	case string:
		if strings.HasSuffix(field, ".body_base64") || field == "layout_slots.header_links[].url" {
			return nil
		}
		lower := strings.ToLower(typed)
		for _, fragment := range forbiddenFragments {
			if strings.Contains(lower, fragment) {
				return invalid("external_reference", field)
			}
		}
		if strings.Contains(lower, "://") {
			return invalid("external_reference", field)
		}
	}
	return nil
}
