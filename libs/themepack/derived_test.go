package themepack

import (
	"strings"
	"testing"
)

// A customized theme records the package it was edited from; only custom.*
// packages may, and every part of the reference is validated.
func TestDerivedFrom(t *testing.T) {
	source := map[string]any{"id": "official.tech", "version": "1.0.0", "package_sha256": strings.Repeat("a", 64)}
	rendered, err := Render(customPackage(t, func(d map[string]any) { d["derived_from"] = source }))
	if err != nil {
		t.Fatalf("derived package rejected: %v", err)
	}
	if from := rendered.Package.DerivedFrom; from == nil || from.ID != "official.tech" || from.Version != "1.0.0" {
		t.Fatalf("derived_from = %+v", from)
	}
	market := map[string]any{"id": "market.io.cdnca.examples.slate-dark", "version": "2.1.0", "package_sha256": strings.Repeat("b", 64)}
	if _, err := Render(customPackage(t, func(d map[string]any) { d["derived_from"] = market })); err != nil {
		t.Fatalf("market source rejected: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"not custom":     func(d map[string]any) { d["id"] = "official.copy"; d["derived_from"] = source },
		"bad id":         func(d map[string]any) { d["derived_from"] = with(source, "id", "evil") },
		"bad version":    func(d map[string]any) { d["derived_from"] = with(source, "version", "1.0") },
		"bad digest":     func(d map[string]any) { d["derived_from"] = with(source, "package_sha256", "ABC") },
		"unknown field":  func(d map[string]any) { d["derived_from"] = with(source, "extra", "x") },
		"missing fields": func(d map[string]any) { d["derived_from"] = map[string]any{"id": "default"} },
	} {
		_, err := Render(customPackage(t, mutate))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if code := validationCode(t, err); code != "derived_from" && code != "package_json" {
			t.Errorf("%s: code %q", name, code)
		}
	}
}

func with(source map[string]any, key string, value any) map[string]any {
	copy := map[string]any{}
	for k, v := range source {
		copy[k] = v
	}
	copy[key] = value
	return copy
}
