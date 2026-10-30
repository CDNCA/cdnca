package themepack

import (
	"embed"
	"encoding/json"
	"sync"
)

//go:embed builtin/*.json
var builtinFiles embed.FS

// CatalogEntry is a theme the control plane can download without an upload:
// the default theme (the community edition ships no official themes).
// RequiresFeature is the license feature activation needs ("" = free); the
// built-in themes are free, a paid official theme names "theme.<id>".
type CatalogEntry struct {
	ID              string
	Raw             []byte
	RequiresFeature string
}

func mustBuiltin(name string) []byte {
	raw, err := builtinFiles.ReadFile("builtin/" + name)
	if err != nil {
		panic(err)
	}
	return raw
}

// BuiltinCatalog returns the shipped themes: only the default theme (free).
func BuiltinCatalog() []CatalogEntry {
	return []CatalogEntry{
		{ID: DefaultThemeID, Raw: mustBuiltin("default.json")},
	}
}

var (
	defaultTemplatesOnce sync.Once
	defaultTemplatesData Templates
)

// defaultTemplates are the default theme's templates, used by packages that
// carry none.
func defaultTemplates() *Templates {
	defaultTemplatesOnce.Do(func() {
		var pkg struct {
			Templates Templates `json:"templates"`
		}
		if err := json.Unmarshal(mustBuiltin("default.json"), &pkg); err != nil {
			panic(err)
		}
		defaultTemplatesData = pkg.Templates
	})
	copy := defaultTemplatesData
	return &copy
}

var (
	defaultRenderedOnce sync.Once
	defaultRendered     Rendered
)

// DefaultRendered is the default theme, served while nothing is activated.
func DefaultRendered() Rendered {
	defaultRenderedOnce.Do(func() {
		rendered, err := Render(mustBuiltin("default.json"))
		if err != nil {
			panic(err)
		}
		defaultRendered = rendered
	})
	return defaultRendered
}
