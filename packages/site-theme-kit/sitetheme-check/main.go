// Command sitetheme-check validates packed website theme contents with the
// platform's own libraries: libs/sitetheme (the parser the market, the
// licence service and the control plane share) and libs/themepack (the
// console theme renderer, for console_theme). It is what the kit's tests
// use to prove its scaffold and examples pass the real checks.
//
//	GOWORK=off go -C packages/site-theme-kit/sitetheme-check run . <content.json>...
//
// It prints one JSON line per file: {"file","ok","code","field","applies_to","files"}.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cdnca/cdnca/libs/sitetheme"
	"github.com/cdnca/cdnca/libs/themepack"
)

type result struct {
	File      string   `json:"file"`
	OK        bool     `json:"ok"`
	Code      string   `json:"code,omitempty"`
	Field     string   `json:"field,omitempty"`
	AppliesTo []string `json:"applies_to,omitempty"`
	Files     int      `json:"files,omitempty"`
}

func check(path string) result {
	out := result{File: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		out.Code = "read: " + err.Error()
		return out
	}
	theme, err := sitetheme.Parse(raw, sitetheme.ParseOptions{Publisher: sitetheme.PublisherThirdParty})
	if err != nil {
		var invalid *sitetheme.Error
		if errors.As(err, &invalid) {
			out.Code, out.Field = invalid.Code, invalid.Field
		} else {
			out.Code = err.Error()
		}
		return out
	}
	if theme.Console != nil {
		rendered, err := themepack.Render(theme.Console)
		if err != nil {
			var invalid *themepack.ValidationError
			if errors.As(err, &invalid) {
				out.Code, out.Field = "themepack."+invalid.Code, "console_theme."+invalid.Field
			} else {
				out.Code = "themepack: " + err.Error()
			}
			return out
		}
		if rendered.Package.ID != theme.ID || rendered.Package.Version != theme.Version {
			out.Code = "console_theme id/version differ from the theme"
			return out
		}
	}
	for _, scope := range theme.AppliesTo {
		out.AppliesTo = append(out.AppliesTo, string(scope))
	}
	if theme.Bundle != nil {
		out.Files = len(theme.Bundle.Files)
	}
	out.OK = true
	return out
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sitetheme-check <content.json>...")
		os.Exit(2)
	}
	failed := false
	encoder := json.NewEncoder(os.Stdout)
	for _, path := range os.Args[1:] {
		r := check(path)
		failed = failed || !r.OK
		_ = encoder.Encode(r)
	}
	if failed {
		os.Exit(1)
	}
}
