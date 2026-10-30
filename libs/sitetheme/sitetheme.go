// Package sitetheme parses and validates website theme plugins (官网主题插件)
// for the market, the license service and the control plane alike:
//
//	cdnca.site-theme/v1  declarative: a built-in layout + tokens + images + seed
//	cdnca.site-theme/v2  open: applies_to, console_theme (cdnca.theme/v1),
//	                     site_bundle (page bundle), auth_style, content_schema
//
// Parse never renders anything. console_theme is only checked to be a JSON
// object of schema cdnca.theme/v1 without admin tokens or scope; the caller
// validates and renders it with libs/themepack.
package sitetheme

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	SchemaV1 = "cdnca.site-theme/v1"
	SchemaV2 = "cdnca.site-theme/v2"
	// ConsoleSchema is the schema console_theme must carry (libs/themepack).
	ConsoleSchema = "cdnca.theme/v1"
	// MaxContentBytes caps a whole package, the same 8 MiB the market
	// (version.go), license (plugin_manifest_verifier.go) and controlsite
	// already use.
	MaxContentBytes = 8 << 20
	// ErrorPrefix starts every Error.Code.
	ErrorPrefix = "site_theme."
)

// ErrInvalid is what every *Error unwraps to.
var ErrInvalid = errors.New("invalid website theme package")

// Error names why a package was refused. Code starts with "site_theme.";
// Field is the JSON path of the offending key ("" for the whole package).
type Error struct {
	Code  string `json:"code"`
	Field string `json:"field,omitempty"`
}

func (err *Error) Error() string {
	if err.Field == "" {
		return "website theme package invalid: " + err.Code
	}
	return fmt.Sprintf("website theme package invalid: %s at %s", err.Code, err.Field)
}

func (err *Error) Unwrap() error { return ErrInvalid }

func invalid(code, field string) error { return &Error{Code: ErrorPrefix + code, Field: field} }

// Publisher is who signed the package. The zero value is PublisherThirdParty
// so that a caller that forgets to set it gets the stricter rules.
type Publisher int

const (
	PublisherThirdParty Publisher = iota
	// PublisherOfficial is the official publisher io.cdnca only.
	PublisherOfficial
)

// Scope is one console or site a theme applies to.
type Scope string

const (
	ScopeAdmin Scope = "admin"
	ScopeUser  Scope = "user"
	ScopeSite  Scope = "site"
)

type ParseOptions struct{ Publisher Publisher }

// Theme is a validated package of either schema.
type Theme struct {
	Schema      string // SchemaV1 | SchemaV2
	ID, Version string
	Name        I18nText
	Description I18nText
	// AppliesTo is normalized to the order admin, user, site; v1 is [site].
	AppliesTo []Scope
	// Console is the cdnca.theme/v1 JSON (validate/render with themepack).
	Console       []byte
	Bundle        *Bundle
	AuthStyle     *AuthStyle
	ContentSchema []Field
	// Preview is the theme card's screenshot (v1 images.preview, v2
	// preview); nil when the package has none.
	Preview *Image
	// V1 is the v1 declarative package (layout/tokens/images/seed).
	V1 *V1Theme
}

// Bundle is the website page bundle; Files are sorted by Path.
type Bundle struct {
	Entry string // default "index.html"
	Files []File
}

// File is one bundle file; SHA256 is lowercase hex of Data, Size len(Data).
type File struct {
	Path   string
	SHA256 string
	Size   int64
	Data   []byte
}

// AuthStyle is the look of the platform sign-in / sign-up pages: CSS and
// images by slot (the form itself is the platform's).
type AuthStyle struct {
	CSS    string
	Images []Image // sorted by Slot; MIMEType is sniffed
}

// Allows reports whether the theme applies to s.
func (t *Theme) Allows(s Scope) bool {
	if t == nil {
		return false
	}
	for _, scope := range t.AppliesTo {
		if scope == s {
			return true
		}
	}
	return false
}

// Parse decodes and validates a package of either schema. Errors are *Error.
func Parse(raw []byte, opt ParseOptions) (*Theme, error) {
	if err := checkEnvelope(raw); err != nil {
		return nil, err
	}
	var head struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return nil, invalid("package_json", "")
	}
	switch head.Schema {
	case SchemaV1:
		pkg, images, err := ParseV1(raw)
		if err != nil {
			return nil, err
		}
		if err := checkPublisherID(pkg.ID, opt.Publisher); err != nil {
			return nil, err
		}
		return &Theme{Schema: SchemaV1, ID: pkg.ID, Version: pkg.Version, Name: pkg.Name, Description: pkg.Description,
			AppliesTo: []Scope{ScopeSite}, Preview: V1Preview(images), V1: &pkg}, nil
	case SchemaV2:
		return parseV2(raw, opt)
	}
	return nil, invalid("schema", "schema")
}

// checkPublisherID keeps the official.* ids to the official publisher.
func checkPublisherID(id string, publisher Publisher) error {
	if publisher != PublisherOfficial && strings.HasPrefix(id, "official.") {
		return invalid("id", "id")
	}
	return nil
}
