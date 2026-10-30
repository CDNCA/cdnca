package theme

import (
	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/libs/themepack"
)

// The cdnca.theme/v1 format, renderer and validation live in
// libs/themepack so the market review worker checks a theme with exactly the
// code the control plane renders it with (PA-18).
type (
	CatalogEntry    = themepack.CatalogEntry
	Rendered        = themepack.Rendered
	ValidationError = themepack.ValidationError
	I18nText        = themepack.I18nText
	Package         = themepack.Package
)

const (
	DefaultThemeID = themepack.DefaultThemeID
	MaxPackageSize = themepack.MaxPackageSize
)

var (
	ErrInvalidPackage = themepack.ErrInvalidPackage
	Render            = themepack.Render
	Parse             = themepack.Parse
	BuiltinCatalog    = themepack.BuiltinCatalog
	DefaultRendered   = themepack.DefaultRendered
	StylesheetPath    = themepack.StylesheetPath
	TokensPath        = themepack.TokensPath
	AssetPath         = themepack.AssetPath
	// DefaultErrorPages are the node default pages a theme renders.
	DefaultErrorPages = themepack.DefaultErrorPages
)

func invalid(code, field string) error { return &ValidationError{Code: code, Field: field} }

// FeatureCode is the license feature code of an official theme (ADR 0007
// §3.1, libs/entitlement module codes): theme.<id>; "" if id is not a valid
// module id.
func FeatureCode(id string) string {
	code, err := entitlement.ModuleFeatureCode(entitlement.ModuleKindTheme, id)
	if err != nil {
		return ""
	}
	return code
}
